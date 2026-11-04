// raptor.UncheckedCursorWrite: a write position advanced by data-dependent
// steps with no end check (CWE-787). Two shapes:
//
// 1. Unbounded writer: a buffer is passed to an unbounded writer and the
//    caller never compares that buffer pointer to a bound.
// 2. Run loop (see RunLoops below): an inner loop whose count comes from the
//    data moves the position of an outer loop that checks the end only
//    between runs. CVE-2026-118752 (FreeImage IFF PBM ByteRun1),
//    CVE-2026-40494 (SAIL TGA raw packets).
//
// An unbounded writer, for one of its pointer parameters P, is a function
// defined in this translation unit that
//   - moves a cursor (P itself, or a local initialised from P) forward by a
//     non-constant step (`c += step`, `c = c + step`) inside a loop,
//   - writes through the cursor or P (`c[i] = ...`, `*c = ...`, `c->f = ...`,
//     or passes it to a call that is not declared to take a const pointer),
//   - never compares the cursor, P, or a variable of the step in a relational
//     comparison (<, <=, >, >=),
//   - is not told how far to go: no loop around the cursor step has a
//     condition that mentions a parameter or a local initialised from one
//     (so `for (y = 0; y < rows; ++y)` and `int lines = h; while (lines--)`
//     copy loops are not writers in this sense), and
//   - does not count down the room it has (`bufsize -= sz`, `*left -= n`,
//     on a parameter or a copy of one).
// A function that passes its own parameter to an unbounded writer, without
// comparing it, is an unbounded writer too.
//
// A call to an unbounded writer is reported when its argument is not a null
// pointer and the calling function never uses that argument (same variable or
// member path) in a relational comparison.
//
// This is CVE-2023-4863 (libwebp <= 1.3.1, src/utils/huffman_utils.c):
// BuildHuffmanTable() advances `table += table_size` with sizes derived from
// the image's code lengths and has no notion of the buffer's size;
// VP8LBuildHuffmanTable() handed it the caller's fixed-size buffer. The fix
// computes the size first and checks
//   curr_table + total_size >= start + size
// before writing.
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <set>

using namespace clang;
using namespace ento;

namespace {
using VarSet = llvm::SmallPtrSet<const VarDecl *, 8>;

void varsIn(const Stmt *S, VarSet &Out) {
  if (!S)
    return;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(S))
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      Out.insert(VD);
  for (const Stmt *C : S->children())
    varsIn(C, Out);
}

// Does S mention a variable in Vars?
bool mentions(const Stmt *S, const VarSet &Vars) {
  if (!S)
    return false;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(S))
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      if (Vars.count(VD))
        return true;
  for (const Stmt *C : S->children())
    if (mentions(C, Vars))
      return true;
  return false;
}

const VarDecl *refVar(const Expr *E) {
  const auto *DRE = dyn_cast_or_null<DeclRefExpr>(raptor::strip(E));
  return DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
}

// The variable at the root of an lvalue such as c[i], *c, c->f, c[i].f.
const VarDecl *writtenBase(const Expr *E) {
  E = raptor::strip(E);
  while (E) {
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E))
      E = raptor::strip(ASE->getBase());
    else if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      if (!ME->isArrow())
        E = raptor::strip(ME->getBase());
      else
        return refVar(ME->getBase());
    } else if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() != UO_Deref)
        return nullptr;
      return refVar(UO->getSubExpr());
    } else
      return nullptr;
  }
  return nullptr;
}

// The pointer an argument designates: p, &p[i], p + n, (T *)p...
const Expr *pointerBase(const Expr *E) {
  E = raptor::strip(E);
  while (E) {
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() != UO_AddrOf)
        return E;
      E = raptor::strip(UO->getSubExpr());
      if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E))
        E = raptor::strip(ASE->getBase());
      else
        return E;
    } else if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() != BO_Add && BO->getOpcode() != BO_Sub)
        return E;
      E = raptor::strip(BO->getLHS()->getType()->isPointerType() ? BO->getLHS() : BO->getRHS());
    } else
      return E;
  }
  return E;
}

bool constPointee(const FunctionDecl *FD, unsigned I) {
  if (I >= FD->getNumParams())
    return false; // variadic: unknown, may write
  QualType T = FD->getParamDecl(I)->getType();
  return T->isPointerType() && T->getPointeeType().isConstQualified();
}

class Analysis {
  ASTContext &Ctx;
  enum class State { InProgress, Yes, No };
  llvm::DenseMap<std::pair<const FunctionDecl *, unsigned>, State> Cache;

public:
  explicit Analysis(ASTContext &C) : Ctx(C) {}

  bool unbounded(const FunctionDecl *FD, unsigned K) {
    const FunctionDecl *Def = nullptr;
    if (!FD || !FD->hasBody(Def) || !Def || K >= Def->getNumParams())
      return false;
    const ParmVarDecl *P = Def->getParamDecl(K);
    if (!P->getType()->isPointerType() || P->getType()->getPointeeType().isConstQualified())
      return false;
    auto Key = std::make_pair(Def, K);
    auto [It, New] = Cache.try_emplace(Key, State::InProgress);
    if (!New)
      return It->second == State::Yes;
    bool R = compute(Def, P);
    Cache[Key] = R ? State::Yes : State::No;
    return R;
  }

private:
  bool compute(const FunctionDecl *FD, const ParmVarDecl *P) {
    const Stmt *Body = FD->getBody();
    ParentMap PM(const_cast<Stmt *>(Body));

    // Cursors: P and locals initialised or assigned from a cursor.
    VarSet Cursors;
    Cursors.insert(P);
    for (int Pass = 0; Pass < 3; ++Pass)
      walk(Body, [&](const Stmt *S) {
        if (const auto *DS = dyn_cast<DeclStmt>(S)) {
          for (const Decl *D : DS->decls())
            if (const auto *VD = dyn_cast<VarDecl>(D))
              if (VD->getType()->isPointerType() && VD->getInit())
                if (const VarDecl *Src = refVar(VD->getInit()))
                  if (Cursors.count(Src))
                    Cursors.insert(VD);
        } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
          if (BO->getOpcode() == BO_Assign)
            if (const VarDecl *L = refVar(BO->getLHS()))
              if (const VarDecl *Src = refVar(BO->getRHS()))
                if (Cursors.count(Src) && L->getType()->isPointerType())
                  Cursors.insert(L);
        }
      });

    // Caller-controlled values: the parameters and locals initialised from
    // them (`int lines = mb_h;`).
    VarSet Controlled;
    for (const ParmVarDecl *PV : FD->parameters())
      Controlled.insert(PV);
    for (int Pass = 0; Pass < 3; ++Pass)
      walk(Body, [&](const Stmt *S) {
        if (const auto *DS = dyn_cast<DeclStmt>(S)) {
          for (const Decl *D : DS->decls())
            if (const auto *VD = dyn_cast<VarDecl>(D))
              if (VD->getInit() && mentions(VD->getInit(), Controlled))
                Controlled.insert(VD);
        }
      });
    // Room counters: Controlled values and plain copies of them (`n = cc;`).
    VarSet Room = Controlled;
    walk(Body, [&](const Stmt *S) {
      if (const auto *BO = dyn_cast<BinaryOperator>(S))
        if (BO->getOpcode() == BO_Assign)
          if (const VarDecl *L = refVar(BO->getLHS()))
            if (const VarDecl *R = refVar(BO->getRHS()))
              if (Controlled.count(R))
                Room.insert(L);
    });

    VarSet Compared, StepVars;
    bool Advances = false, LoopBoundByCaller = false, Writes = false, Forwards = false,
         CountsRoom = false;
    walk(Body, [&](const Stmt *S) {
      if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isRelationalOp()) {
          varsIn(BO->getLHS(), Compared);
          varsIn(BO->getRHS(), Compared);
        }
        const Expr *Step = nullptr;
        const VarDecl *L = refVar(BO->getLHS());
        if (L && Cursors.count(L)) {
          if (BO->getOpcode() == BO_AddAssign || BO->getOpcode() == BO_SubAssign)
            Step = BO->getRHS();
          else if (BO->getOpcode() == BO_Assign)
            if (const auto *Sum = dyn_cast<BinaryOperator>(raptor::strip(BO->getRHS())))
              if (Sum->isAdditiveOp() && refVar(Sum->getLHS()) == L)
                Step = Sum->getRHS();
        }
        if (Step && !Step->isValueDependent() && !Step->isIntegerConstantExpr(Ctx)) {
          bool InLoop = false;
          for (const Stmt *Up = PM.getParent(S); Up; Up = PM.getParent(Up)) {
            const Stmt *Cond = nullptr;
            if (const auto *F = dyn_cast<ForStmt>(Up))
              Cond = F->getCond();
            else if (const auto *W = dyn_cast<WhileStmt>(Up))
              Cond = W->getCond();
            else if (const auto *D = dyn_cast<DoStmt>(Up))
              Cond = D->getCond();
            else
              continue;
            InLoop = true;
            if (Cond && mentions(Cond, Controlled))
              LoopBoundByCaller = true;
          }
          // A single offset is not a cursor walk.
          if (InLoop) {
            Advances = true;
            varsIn(Step, StepVars);
          }
        }
        // The room left is counted down (`bufsize -= sz`, `*left = *left - n`).
        if (BO->getOpcode() == BO_SubAssign ||
            (BO->getOpcode() == BO_Assign && isa<BinaryOperator>(raptor::strip(BO->getRHS())) &&
             cast<BinaryOperator>(raptor::strip(BO->getRHS()))->getOpcode() == BO_Sub &&
             raptor_mem::keyOf(cast<BinaryOperator>(raptor::strip(BO->getRHS()))->getLHS()) ==
                 raptor_mem::keyOf(BO->getLHS()))) {
          const Expr *Lhs = raptor::strip(BO->getLHS());
          if (const auto *UO = dyn_cast<UnaryOperator>(Lhs))
            if (UO->getOpcode() == UO_Deref)
              Lhs = UO->getSubExpr();
          if (const VarDecl *R = refVar(Lhs))
            if (!Cursors.count(R) && Room.count(R))
              CountsRoom = true;
        }
        if (BO->isAssignmentOp())
          if (const VarDecl *W = writtenBase(BO->getLHS()))
            if (Cursors.count(W))
              Writes = true;
      }
      if (const auto *CE = dyn_cast<CallExpr>(S)) {
        const FunctionDecl *Callee = CE->getDirectCallee();
        for (unsigned I = 0; I < CE->getNumArgs(); ++I) {
          const VarDecl *V = refVar(pointerBase(CE->getArg(I)));
          if (!V || !Cursors.count(V))
            continue;
          if (!Callee || !constPointee(Callee, I))
            Writes = true;
          if (Callee && unbounded(Callee, I))
            Forwards = true;
        }
      }
    });

    for (const VarDecl *C : Cursors)
      if (Compared.count(C))
        return false;
    if (CountsRoom)
      return false;
    if (Forwards)
      return true;
    if (!Advances || !Writes || LoopBoundByCaller)
      return false;
    for (const VarDecl *V : StepVars)
      if (Compared.count(V))
        return false;
    return true;
  }

  template <class F> static void walk(const Stmt *S, F &&Fn) {
    if (!S)
      return;
    Fn(S);
    for (const Stmt *C : S->children())
      walk(C, Fn);
  }
};

bool comparedIn(const Stmt *S, const std::string &Key) {
  if (!S)
    return false;
  if (const auto *BO = dyn_cast<BinaryOperator>(S))
    if (BO->isRelationalOp() && raptor_mem::findKey(BO, {Key}))
      return true;
  for (const Stmt *C : S->children())
    if (comparedIn(C, Key))
      return true;
  return false;
}

void calls(const Stmt *S, llvm::SmallVectorImpl<const CallExpr *> &Out) {
  if (!S)
    return;
  if (const auto *CE = dyn_cast<CallExpr>(S))
    Out.push_back(CE);
  for (const Stmt *C : S->children())
    calls(C, Out);
}

// ---- Run loops ------------------------------------------------------------
//
//   while (written < line) {                     // outer: index vs. end
//     n = read_count();
//     for (k = 0; k < n + 1; k++)                // run: count from the data
//       bits[written++] = read_byte();           // moves and writes the index
//   }
//
// The outer condition stops the index at the end only between runs; inside a
// run nothing does. Reported unless the run is clamped first (a comparison of
// the index, the end, or a value computed from them, on the path to the run
// or inside it).
using Keys = std::set<std::string>;

void keysIn(const Stmt *S, Keys &Out) {
  if (!S)
    return;
  if (isa<DeclRefExpr>(S) || isa<MemberExpr>(S)) {
    std::string K = raptor_mem::keyOf(cast<Expr>(S));
    if (!K.empty())
      Out.insert(K);
    if (isa<DeclRefExpr>(S))
      return;
  }
  for (const Stmt *C : S->children())
    keysIn(C, Out);
}

// Keys of the variables S modifies (++, --, assignments).
void modifiedIn(const Stmt *S, Keys &Out) {
  if (!S)
    return;
  const Expr *Target = nullptr;
  if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->isIncrementDecrementOp())
      Target = UO->getSubExpr();
  } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      Target = BO->getLHS();
  }
  if (Target && isa<DeclRefExpr>(raptor::strip(Target)))
    Out.insert(raptor_mem::keyOf(Target));
  for (const Stmt *C : S->children())
    modifiedIn(C, Out);
}

// Variables added up in E (`pos + cur` -> pos, cur), not those that only
// select a value (`f[i].n`).
void termsOf(const Expr *E, Keys &Out) {
  E = raptor::strip(E);
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(E)) {
    if (BO->isAdditiveOp()) {
      termsOf(BO->getLHS(), Out);
      termsOf(BO->getRHS(), Out);
    }
  } else if (const auto *DRE = dyn_cast_or_null<DeclRefExpr>(E)) {
    Out.insert(DRE->getDecl()->getNameAsString());
  }
}

bool hasRelational(const Stmt *S, const Keys &K) {
  if (!S)
    return false;
  if (const auto *BO = dyn_cast<BinaryOperator>(S))
    if (BO->isRelationalOp() && raptor_mem::findKey(BO, K))
      return true;
  for (const Stmt *C : S->children())
    if (hasRelational(C, K))
      return true;
  return false;
}

const Stmt *loopCond(const Stmt *S) {
  if (const auto *F = dyn_cast<ForStmt>(S))
    return F->getCond();
  if (const auto *W = dyn_cast<WhileStmt>(S))
    return W->getCond();
  if (const auto *D = dyn_cast<DoStmt>(S))
    return D->getCond();
  return nullptr;
}

const Stmt *loopBody(const Stmt *S) {
  if (const auto *F = dyn_cast<ForStmt>(S))
    return F->getBody();
  if (const auto *W = dyn_cast<WhileStmt>(S))
    return W->getBody();
  if (const auto *D = dyn_cast<DoStmt>(S))
    return D->getBody();
  return nullptr;
}

bool isLoop(const Stmt *S) { return isa<ForStmt>(S) || isa<WhileStmt>(S) || isa<DoStmt>(S); }

template <class F> void walkStmts(const Stmt *S, F &&Fn) {
  if (!S)
    return;
  Fn(S);
  for (const Stmt *C : S->children())
    walkStmts(C, Fn);
}

// Is a value set from the guard keys (`count = min(count, w - x)`)?
bool assignsFrom(const Stmt *S, const Keys &Targets, const Keys &From) {
  bool Hit = false;
  walkStmts(S, [&](const Stmt *X) {
    if (const auto *BO = dyn_cast<BinaryOperator>(X)) {
      if (BO->getOpcode() == BO_Assign && Targets.count(raptor_mem::keyOf(BO->getLHS())) &&
          raptor_mem::findKey(BO->getRHS(), From))
        Hit = true;
    } else if (const auto *DS = dyn_cast<DeclStmt>(X)) {
      for (const Decl *D : DS->decls())
        if (const auto *VD = dyn_cast<VarDecl>(D))
          if (VD->getInit() && Targets.count(VD->getNameAsString()) &&
              raptor_mem::findKey(VD->getInit(), From))
            Hit = true;
    }
  });
  return Hit;
}

class RunLoops {
  ParentMap PM;

public:
  explicit RunLoops(const Stmt *Body) : PM(const_cast<Stmt *>(Body)) {}

  // The first write of each inner loop of Body that overruns its outer
  // loop's bound.
  void find(const Stmt *Body, llvm::SmallVectorImpl<const Stmt *> &Out) {
    llvm::SmallPtrSet<const Stmt *, 8> Done;
    walkStmts(Body, [&](const Stmt *L) {
      if (!isLoop(L))
        return;
      const Stmt *Cond = loopCond(L);
      if (!Cond)
        return;
      // Index: compared in the outer condition and moved by the loop.
      Keys Moved, Index, End;
      modifiedIn(L, Moved);
      walkStmts(Cond, [&](const Stmt *X) {
        const auto *BO = dyn_cast<BinaryOperator>(X);
        if (!BO || !BO->isRelationalOp())
          return;
        Keys Lk, Rk;
        keysIn(BO->getLHS(), Lk);
        keysIn(BO->getRHS(), Rk);
        for (auto [A, B] : {std::pair{&Lk, &Rk}, std::pair{&Rk, &Lk}})
          for (const std::string &K : *A)
            if (Moved.count(K)) {
              Index.insert(K);
              End.insert(B->begin(), B->end());
            }
      });
      for (const std::string &K : Index)
        End.erase(K);
      // A constant end (`len <= 15`) is a count, not a buffer's end.
      if (Index.empty() || End.empty())
        return;
      // Guard keys: index, end, and locals computed from them (`remaining`).
      Keys Guard = Index;
      Guard.insert(End.begin(), End.end());
      for (int Pass = 0; Pass < 2; ++Pass)
        walkStmts(loopBody(L), [&](const Stmt *X) {
          if (const auto *DS = dyn_cast<DeclStmt>(X))
            for (const Decl *D : DS->decls())
              if (const auto *VD = dyn_cast<VarDecl>(D))
                if (VD->getInit() && raptor_mem::findKey(VD->getInit(), Guard))
                  Guard.insert(VD->getNameAsString());
        });
      walkStmts(loopBody(L), [&](const Stmt *R) {
        if (!isLoop(R) || Done.count(R))
          return;
        if (const Stmt *W = overruns(L, R, Index, End, Guard)) {
          Done.insert(R);
          Out.push_back(W);
        }
      });
    });
  }

private:
  const Stmt *overruns(const Stmt *L, const Stmt *R, const Keys &Index, const Keys &End,
                       const Keys &Guard) {
    const Stmt *RCond = loopCond(R);
    if (!RCond || raptor_mem::findKey(RCond, End))
      return nullptr;
    // A counted run: `k < n`, `n--`. Two comparisons mean the run also tests
    // a position (`j < c && x < width`).
    unsigned Rel = 0;
    bool Counts = false;
    walkStmts(RCond, [&](const Stmt *X) {
      if (const auto *BO = dyn_cast<BinaryOperator>(X))
        Rel += BO->isRelationalOp();
      if (const auto *UO = dyn_cast<UnaryOperator>(X))
        Counts |= UO->isIncrementDecrementOp();
    });
    if (Rel > 1 || (Rel == 0 && !Counts))
      return nullptr;
    // Run variables: the inner loop's own counter (set in its init).
    Keys Own;
    if (const auto *F = dyn_cast<ForStmt>(R)) {
      modifiedIn(F->getInit(), Own);
      if (const auto *DS = dyn_cast_or_null<DeclStmt>(F->getInit()))
        for (const Decl *D : DS->decls())
          if (const auto *VD = dyn_cast<VarDecl>(D))
            Own.insert(VD->getNameAsString());
    }
    // The count: what else the inner condition depends on.
    Keys Count;
    keysIn(RCond, Count);
    for (const std::string &K : Index)
      Count.erase(K);
    for (const std::string &K : Own)
      Count.erase(K);
    if (Count.empty())
      return nullptr;
    // The run moves the index: inside it, by its condition, or by the count.
    Keys InR;
    modifiedIn(R, InR);
    bool Moves = false;
    walkStmts(RCond, [&](const Stmt *X) {
      if (const auto *BO = dyn_cast<BinaryOperator>(X))
        if (BO->isRelationalOp()) {
          Keys T;
          termsOf(BO->getLHS(), T);
          termsOf(BO->getRHS(), T);
          for (const std::string &K : Index)
            Moves |= T.count(K) > 0;
        }
    });
    for (const std::string &K : Index)
      Moves |= InR.count(K) > 0;
    if (!Moves)
      walkStmts(loopBody(L), [&](const Stmt *X) {
        if (const auto *BO = dyn_cast<BinaryOperator>(X))
          if ((BO->getOpcode() == BO_AddAssign || BO->getOpcode() == BO_SubAssign) &&
              Index.count(raptor_mem::keyOf(BO->getLHS())) &&
              raptor_mem::findKey(BO->getRHS(), Count))
            Moves = true;
      });
    if (!Moves)
      return nullptr;
    // Write positions: the index, the run counter when it starts at the
    // index, and pointers moved by the run.
    Keys At = Index;
    if (const auto *F = dyn_cast<ForStmt>(R))
      if (raptor_mem::findKey(F->getInit(), Index))
        At.insert(Own.begin(), Own.end());
    Keys Ptrs;
    walkStmts(R, [&](const Stmt *X) {
      if (const auto *BO = dyn_cast<BinaryOperator>(X))
        if ((BO->getOpcode() == BO_AddAssign || BO->getOpcode() == BO_SubAssign) &&
            BO->getLHS()->getType()->isPointerType())
          Ptrs.insert(raptor_mem::keyOf(BO->getLHS()));
      if (const auto *UO = dyn_cast<UnaryOperator>(X))
        if (UO->isIncrementDecrementOp() && UO->getSubExpr()->getType()->isPointerType())
          Ptrs.insert(raptor_mem::keyOf(UO->getSubExpr()));
    });
    Ptrs.erase("");
    At.insert(Ptrs.begin(), Ptrs.end());
    const Stmt *W = firstWrite(R, At, Ptrs);
    if (!W)
      return nullptr;
    // Clamped inside the run...
    if (hasRelational(loopBody(R), Guard))
      return nullptr;
    if (const auto *F = dyn_cast<ForStmt>(R))
      if (hasRelational(F->getInc(), Guard))
        return nullptr;
    // ...or on the way to it.
    const Stmt *Child = R;
    for (const Stmt *Up = PM.getParent(R); Up && Child != loopBody(L);
         Child = Up, Up = PM.getParent(Up)) {
      if (const auto *CS = dyn_cast<CompoundStmt>(Up)) {
        for (const Stmt *Sib : CS->body()) {
          if (Sib == Child)
            break;
          if (hasRelational(Sib, Guard) || assignsFrom(Sib, Count, Guard))
            return nullptr;
        }
      } else if (const auto *If = dyn_cast<IfStmt>(Up)) {
        if (Child != If->getCond() && hasRelational(If->getCond(), Guard))
          return nullptr;
      }
      if (Up == L)
        break;
    }
    return W;
  }

  // The first store of R through a position in At, or call handed a moved
  // pointer that it may write through.
  const Stmt *firstWrite(const Stmt *R, const Keys &At, const Keys &Ptrs) {
    const Stmt *W = nullptr;
    walkStmts(R, [&](const Stmt *X) {
      if (W)
        return;
      if (const auto *BO = dyn_cast<BinaryOperator>(X)) {
        if (!BO->isAssignmentOp())
          return;
        const Expr *L = raptor::strip(BO->getLHS());
        if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(L))
          W = raptor_mem::findKey(ASE->getBase(), At) || raptor_mem::findKey(ASE->getIdx(), At)
                  ? X
                  : nullptr;
        else if (const auto *UO = dyn_cast<UnaryOperator>(L))
          W = UO->getOpcode() == UO_Deref && raptor_mem::findKey(UO->getSubExpr(), At) ? X
                                                                                       : nullptr;
      } else if (const auto *CE = dyn_cast<CallExpr>(X)) {
        const FunctionDecl *FD = CE->getDirectCallee();
        for (unsigned I = 0; I < CE->getNumArgs(); ++I) {
          const Expr *A = raptor::strip(CE->getArg(I));
          if (!A->getType()->isPointerType() || !Ptrs.count(raptor_mem::keyOf(pointerBase(A))))
            continue;
          if (!FD || !constPointee(FD, I)) {
            W = X;
            return;
          }
        }
      }
    });
    return W;
  }
};

class UncheckedCursorWriteChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    Analysis A(Ctx);
    llvm::SmallVector<const Stmt *, 8> Runs;
    RunLoops(Body).find(Body, Runs);
    for (const Stmt *R : Runs)
      raptor::reportAt(BR, this, "Unchecked cursor write",
                       "Write in a run whose count comes from the data: the run moves the "
                       "enclosing loop's position, which is checked against the end only "
                       "between runs, and nothing clamps the run to the room left (CWE-787)",
                       R, Mgr.getAnalysisDeclContext(D));
    llvm::SmallVector<const CallExpr *, 32> Calls;
    calls(Body, Calls);
    for (const CallExpr *CE : Calls) {
      const FunctionDecl *FD = CE->getDirectCallee();
      if (!FD)
        continue;
      for (unsigned I = 0; I < CE->getNumArgs() && I < FD->getNumParams(); ++I) {
        const Expr *Arg = CE->getArg(I);
        if (Arg->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNotNull))
          continue;
        std::string Key = raptor_mem::keyOf(pointerBase(Arg));
        if (Key.empty() || comparedIn(Body, Key) || !A.unbounded(FD, I))
          continue;
        raptor::reportAt(
            BR, this, "Unchecked cursor write",
            ("'" + FD->getNameAsString() + "' writes through '" + Key +
             "' with a cursor advanced by data-dependent steps and never "
             "compared to a bound; nothing here checks the buffer's capacity "
             "either (CWE-787)"),
            CE, Mgr.getAnalysisDeclContext(D));
        break;
      }
    }
  }
};
} // namespace

RAPTOR_CHECKER(UncheckedCursorWriteChecker, "UncheckedCursorWrite",
               "Buffer passed to an unbounded cursor writer without a capacity check")
