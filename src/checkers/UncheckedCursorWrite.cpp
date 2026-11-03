// raptor.UncheckedCursorWrite: a buffer is passed to an unbounded writer and
// the caller never compares that buffer pointer to a bound (CWE-787).
//
// An unbounded writer, for one of its pointer parameters P, is a function
// defined in this translation unit that
//   - moves a cursor (P itself, or a local initialised from P) forward by a
//     non-constant step (`c += step`, `c = c + step`),
//   - writes through the cursor or P (`c[i] = ...`, `*c = ...`, `c->f = ...`,
//     or passes it to a call that is not declared to take a const pointer),
//   - never compares the cursor, P, or a variable of the step in a relational
//     comparison (<, <=, >, >=), and
//   - is not told how far to go: no loop around the cursor step has a
//     condition that mentions a parameter or a local initialised from one
//     (so `for (y = 0; y < rows; ++y)` and `int lines = h; while (lines--)`
//     copy loops are not writers in this sense).
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
        if (const auto *DS = dyn_cast<DeclStmt>(S))
          for (const Decl *D : DS->decls())
            if (const auto *VD = dyn_cast<VarDecl>(D))
              if (VD->getInit() && mentions(VD->getInit(), Controlled))
                Controlled.insert(VD);
      });

    VarSet Compared, StepVars;
    bool Advances = false, LoopBoundByCaller = false, Writes = false, Forwards = false;
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
          Advances = true;
          varsIn(Step, StepVars);
          for (const Stmt *Up = PM.getParent(S); Up; Up = PM.getParent(Up)) {
            const Stmt *Cond = nullptr;
            if (const auto *F = dyn_cast<ForStmt>(Up))
              Cond = F->getCond();
            else if (const auto *W = dyn_cast<WhileStmt>(Up))
              Cond = W->getCond();
            else if (const auto *D = dyn_cast<DoStmt>(Up))
              Cond = D->getCond();
            if (Cond && mentions(Cond, Controlled))
              LoopBoundByCaller = true;
          }
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

class UncheckedCursorWriteChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    Analysis A(Ctx);
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
