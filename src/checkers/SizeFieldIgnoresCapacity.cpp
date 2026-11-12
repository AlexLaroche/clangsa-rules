// raptor.SizeFieldIgnoresCapacity: a (pointer, size) pair is set up to
// describe another object's buffer, but the size neither comes from that
// buffer's capacity field nor is compared with it (CWE-787, CWE-125).
//
//   entry->size = entry2.width * entry2.height * 4;
//   entry->data = persistent->bmpData;          // holds persistent->bmpSize
//
// Pair: in one block, `x->p = <buffer>` and `x->s = <size>` on the same
// object, where s is a size field of p (size, len, p_len...), and no other
// assignment of x->p in that block is nearer to the size.
// Buffer: a pointer or array field `y->b` (directly, plus an offset, or
// through a local pointer set from it) whose struct has a capacity field for
// b (bmpData -> bmpSize, block -> block_size).
// Size: not a constant. Its slice is the variables and fields it uses,
// followed back through the definitions of locals.
// Not reported: a buffer whose owner (the object holding it and its
// capacity) is passed to a call, which bounds what it returns (regex
// captures); a buffer built in this function (a field set here, or a
// part of a local struct set here: `name.data = v.data + 7`, `e = *value`);
// a size whose slice contains the size field itself (`x->len = x->len - k`
// keeps the pair's invariant) or a capacity field; a function that compares
// a capacity field with anything, directly or through a local set from it
// (`for (j = 7; j < value->len; j++) len++;`, `if (n > c->bmpSize)`); a
// capacity field set from the slice; a size taken from another field of
// the object holding the buffer (`r->base = b->base; r->length =
// b->current;`): that object keeps its own bookkeeping within its capacity; a
// size written by a call handed the buffer's bound (`get_tag(&p, end, &len)`
// with `end = p + buf->len`); a buffer (or its owner) allocated by a call
// given the size (`ref = av_buffer_alloc(n + 3); x->data = ref->data;
// x->size = n + 3;`, `av_fast_padded_malloc(&o->buf, &o->buf_size, size)`,
// FFmpeg); a size that indexes the function's writes through the pointer
// (`dst[di++] = ...; x->data = dst; x->size = di;`).
//
// CVE-2026-111381 (FreeRDP persistent cache v2 parser).
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
using Keys = std::set<std::string>;
using DefMap = std::map<std::string, std::vector<const Expr *>>;

template <class F> void walk(const Stmt *S, F &&Fn) {
  if (!S)
    return;
  Fn(S);
  for (const Stmt *C : S->children())
    walk(C, Fn);
}

const VarDecl *localVar(const Expr *E) {
  const auto *DRE = dyn_cast_or_null<DeclRefExpr>(raptor::strip(E));
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  return VD && VD->hasLocalStorage() && !isa<ParmVarDecl>(VD) ? VD : nullptr;
}

class SizeFieldIgnoresCapacityChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    ParentMap &PM = Mgr.getAnalysisDeclContext(D)->getParentMap();

    DefMap Defs; // local name -> values it is set to
    std::vector<const BinaryOperator *> FieldAssigns, Compares;
    std::vector<const CallExpr *> Calls;
    walk(Body, [&](const Stmt *S) {
      if (const auto *CE = dyn_cast<CallExpr>(S))
        Calls.push_back(CE);
      if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *Dc : DS->decls())
          if (const auto *VD = dyn_cast<VarDecl>(Dc))
            if (VD->getInit())
              Defs[VD->getNameAsString()].push_back(VD->getInit());
      } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isComparisonOp())
          Compares.push_back(BO);
        else if (BO->isAssignmentOp()) {
          if (const VarDecl *V = localVar(BO->getLHS()))
            Defs[V->getNameAsString()].push_back(BO->getRHS());
          else if (BO->getOpcode() == BO_Assign && isa<MemberExpr>(raptor::strip(BO->getLHS())))
            FieldAssigns.push_back(BO);
        }
      }
    });

    // Fields set in this function, and local structs set here.
    std::set<std::string> Owned;
    for (const BinaryOperator *A : FieldAssigns)
      Owned.insert(raptor_mem::keyOf(A->getLHS()));
    walk(Body, [&](const Stmt *S) {
      const VarDecl *V = nullptr;
      if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *Dc : DS->decls())
          if (const auto *VD = dyn_cast<VarDecl>(Dc))
            if (VD->getInit() && VD->getType()->isRecordType())
              Owned.insert(VD->getNameAsString());
      } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isAssignmentOp())
          V = localVar(BO->getLHS());
      }
      if (V && V->getType()->isRecordType())
        Owned.insert(V->getNameAsString());
    });
    const SourceManager &SM = Ctx.getSourceManager();
    // Objects passed to calls, as `x` or `&x`.
    std::set<std::string> Passed;
    walk(Body, [&](const Stmt *S) {
      if (const auto *CE = dyn_cast<CallExpr>(S))
        for (const Expr *A : CE->arguments()) {
          const Expr *X = raptor::strip(A);
          if (const auto *UO = dyn_cast<UnaryOperator>(X))
            if (UO->getOpcode() == UO_AddrOf)
              X = raptor::strip(UO->getSubExpr());
          std::string K = raptor_mem::keyOf(X);
          if (!K.empty())
            Passed.insert(K);
        }
    });

    for (const BinaryOperator *PtrA : FieldAssigns) {
      const auto *PtrME = cast<MemberExpr>(raptor::strip(PtrA->getLHS()));
      const auto *PtrFD = dyn_cast<FieldDecl>(PtrME->getMemberDecl());
      if (!PtrFD || !PtrFD->getType()->isPointerType())
        continue;
      std::set<std::string> SeenLocals;
      const MemberExpr *Buf = bufferField(PtrA->getRHS(), Defs, SeenLocals, 0);
      if (!Buf)
        continue;
      Keys Caps = capacityKeys(Buf);
      if (Caps.empty())
        continue;
      // A buffer built here (a slice of a local struct, or a field set in
      // this function) is not another object's buffer.
      if (builtHere(raptor_mem::keyOf(Buf), Owned))
        continue;
      // The object holding the buffer and its capacity is handed to a call,
      // which bounds what it returns (`ngx_regex_exec(re, s, captures)`).
      if (Passed.count(raptor_mem::keyOf(Buf->getBase())))
        continue;
      std::string Obj = raptor_mem::keyOf(PtrME->getBase());
      for (const BinaryOperator *SizeA : FieldAssigns) {
        const auto *SizeME = cast<MemberExpr>(raptor::strip(SizeA->getLHS()));
        const auto *SizeFD = dyn_cast<FieldDecl>(SizeME->getMemberDecl());
        if (!SizeFD || SizeFD->getParent() != PtrFD->getParent() ||
            !SizeFD->getType()->isIntegerType() || raptor_mem::keyOf(SizeME->getBase()) != Obj ||
            !raptor_mem::isSizeField(SizeFD, PtrFD))
          continue;
        // One pair: both set in the same block, and no assignment of the
        // pointer is nearer to the size than this one.
        if (PM.getParent(SizeA) != PM.getParent(PtrA) || nearestPtr(SizeA, PtrME, FieldAssigns, PM, SM) != PtrA)
          continue;
        const Expr *Size = raptor::strip(SizeA->getRHS());
        if (Size->isValueDependent() || Size->isIntegerConstantExpr(Ctx))
          continue;
        // Updated from its own old value: the pair's invariant is kept.
        if (slice(Size, Defs).count(raptor_mem::keyOf(SizeME)))
          continue;
        if (sanitized(Size, Caps, Defs, Compares, FieldAssigns))
          continue;
        // Taken from the owner's own bookkeeping (`r->length = b->current`
        // for b->base): the owner keeps it within its capacity.
        if (fromOwner(Size, Buf, Defs))
          continue;
        // Written by a parser handed the buffer's bound (`get_tag(&p, end,
        // &len)` with `end = p + buf->len`).
        if (fromBoundedParser(Size, Caps, Defs, Calls))
          continue;
        if (allocatedFor(Size, Buf, Body, Calls, Ctx))
          continue;
        if (writtenCount(Size, PtrA->getRHS(), Body))
          continue;
        raptor::reportAt(BR, this, "Size field ignores capacity",
                         "'" + raptor_mem::keyOf(SizeME) + "' describes '" +
                             raptor_mem::keyOf(Buf) + "', whose capacity is '" + *Caps.begin() +
                             "', but the size neither comes from that capacity nor is compared "
                             "with it: out-of-bounds access through the pair (CWE-787)",
                         SizeA, Mgr.getAnalysisDeclContext(D));
      }
    }
  }

private:
  static std::string squeezed(const Expr *E, ASTContext &Ctx) {
    const SourceManager &SM = Ctx.getSourceManager();
    CharSourceRange R = SM.getExpansionRange(E->getSourceRange());
    std::string T;
    for (char Ch : Lexer::getSourceText(R, SM, Ctx.getLangOpts()))
      if (!isspace(static_cast<unsigned char>(Ch)))
        T += Ch;
    return T;
  }

  // A call given Size as an argument that allocates the buffer: it is handed
  // &Buf, or its result is assigned to Buf or to the object holding it.
  static bool allocatedFor(const Expr *Size, const MemberExpr *Buf,
                           const Stmt *Body,
                           const std::vector<const CallExpr *> &Calls,
                           ASTContext &Ctx) {
    std::string ST = squeezed(Size, Ctx);
    std::string BK = raptor_mem::keyOf(Buf),
                OK = raptor_mem::keyOf(Buf->getBase());
    for (const CallExpr *C : Calls) {
      bool HasSize = false, HandsBuf = false;
      for (const Expr *A : C->arguments()) {
        HasSize |= !ST.empty() && squeezed(A, Ctx) == ST;
        if (const auto *U = dyn_cast<UnaryOperator>(raptor::strip(A));
            U && U->getOpcode() == UO_AddrOf)
          HandsBuf |= raptor_mem::keyOf(U->getSubExpr()) == BK;
      }
      if (!HasSize)
        continue;
      if (HandsBuf)
        return true;
      bool Assigned = false;
      walk(Body, [&](const Stmt *S) {
        std::string LK;
        const Expr *RHS = nullptr;
        if (const auto *BO = dyn_cast<BinaryOperator>(S);
            BO && BO->getOpcode() == BO_Assign) {
          LK = raptor_mem::keyOf(BO->getLHS());
          RHS = BO->getRHS();
        } else if (const auto *DS = dyn_cast<DeclStmt>(S)) {
          for (const Decl *Dc : DS->decls())
            if (const auto *VD = dyn_cast<VarDecl>(Dc); VD && VD->getInit() &&
                                                         raptor::strip(VD->getInit()) == C)
              Assigned |= VD->getName() == OK || VD->getName() == BK;
        }
        if (RHS && raptor::strip(RHS) == C && (LK == BK || LK == OK))
          Assigned = true;
      });
      if (Assigned)
        return true;
    }
    return false;
  }

  // Size is a local used as the index of writes `P[size++] = ...` through
  // the pointer stored in the field (a local P).
  static bool writtenCount(const Expr *Size, const Expr *PtrRHS,
                           const Stmt *Body) {
    const VarDecl *N = localVar(Size), *P = localVar(PtrRHS);
    if (!N || !P)
      return false;
    bool Writes = false;
    walk(Body, [&](const Stmt *S) {
      const auto *BO = dyn_cast<BinaryOperator>(S);
      if (!BO || !BO->isAssignmentOp())
        return;
      const auto *AS =
          dyn_cast<ArraySubscriptExpr>(BO->getLHS()->IgnoreParenImpCasts());
      if (!AS || localVar(AS->getBase()) != P)
        return;
      walk(AS->getIdx(), [&](const Stmt *X) {
        if (const auto *E = dyn_cast<Expr>(X); E && localVar(E) == N)
          Writes = true;
      });
    });
    return Writes;
  }

  // Is Key, or an object it is a part of (`e` for `e.data`, `name` for
  // `name->data`... only when that object is in Owned), set in this function?
  static bool builtHere(const std::string &Key, const std::set<std::string> &Owned) {
    if (Owned.count(Key))
      return true;
    for (size_t I = 0; I < Key.size(); ++I)
      if ((Key[I] == '.' || (Key[I] == '-' && I + 1 < Key.size() && Key[I + 1] == '>')) &&
          Owned.count(Key.substr(0, I)))
        return true;
    return false;
  }

  // The assignment of the pointer field (same key as PtrME) in SizeA's block
  // nearest to SizeA.
  static const BinaryOperator *nearestPtr(const BinaryOperator *SizeA, const MemberExpr *PtrME,
                                          const std::vector<const BinaryOperator *> &FieldAssigns,
                                          ParentMap &PM, const SourceManager &SM) {
    std::string Key = raptor_mem::keyOf(PtrME);
    unsigned At = SM.getFileOffset(SM.getExpansionLoc(SizeA->getBeginLoc()));
    const BinaryOperator *Best = nullptr;
    unsigned BestDist = ~0u;
    for (const BinaryOperator *A : FieldAssigns) {
      if (PM.getParent(A) != PM.getParent(SizeA) || raptor_mem::keyOf(A->getLHS()) != Key)
        continue;
      unsigned Off = SM.getFileOffset(SM.getExpansionLoc(A->getBeginLoc()));
      unsigned Dist = Off > At ? Off - At : At - Off;
      if (Dist < BestDist) {
        BestDist = Dist;
        Best = A;
      }
    }
    return Best;
  }

  // Does the slice of Size use a local that a call writes through `&local`
  // while being handed a value built from a capacity field?
  static bool fromBoundedParser(const Expr *Size, const Keys &Caps, const DefMap &Defs,
                                const std::vector<const CallExpr *> &Calls) {
    Keys Sl = slice(Size, Defs);
    for (const CallExpr *CE : Calls) {
      bool Out = false, Bound = false;
      for (const Expr *A : CE->arguments()) {
        const Expr *X = raptor::strip(A);
        if (const auto *UO = dyn_cast<UnaryOperator>(X); UO && UO->getOpcode() == UO_AddrOf) {
          if (Sl.count(raptor_mem::keyOf(UO->getSubExpr())))
            Out = true;
          continue;
        }
        for (const std::string &K : slice(X, Defs))
          Bound |= Caps.count(K) > 0;
      }
      if (Out && Bound)
        return true;
    }
    return false;
  }

  // Does the slice of Size use another part of the object holding Buf?
  static bool fromOwner(const Expr *Size, const MemberExpr *Buf, const DefMap &Defs) {
    std::string Owner = raptor_mem::keyOf(Buf->getBase());
    std::string BufK = raptor_mem::keyOf(Buf);
    if (Owner.empty())
      return false;
    for (const std::string &K : slice(Size, Defs)) {
      llvm::StringRef KR(K);
      if (K != BufK && (KR.starts_with(Owner + "->") || KR.starts_with(Owner + ".")))
        return true;
    }
    return false;
  }

  static Keys slice(const Expr *E, const DefMap &Defs) {
    Keys Out;
    std::set<std::string> Done;
    std::vector<const Expr *> Work{E};
    while (!Work.empty()) {
      const Expr *X = Work.back();
      Work.pop_back();
      walk(X, [&](const Stmt *S) {
        if (!isa<DeclRefExpr>(S) && !isa<MemberExpr>(S))
          return;
        std::string K = raptor_mem::keyOf(cast<Expr>(S));
        if (K.empty())
          return;
        Out.insert(K);
        if (isa<DeclRefExpr>(S) && Done.insert(K).second) {
          auto It = Defs.find(K);
          if (It != Defs.end())
            for (const Expr *Dv : It->second)
              Work.push_back(Dv);
        }
      });
    }
    return Out;
  }

  static bool sanitized(const Expr *Size, const Keys &Caps, const DefMap &Defs,
                        const std::vector<const BinaryOperator *> &Compares,
                        const std::vector<const BinaryOperator *> &FieldAssigns) {
    Keys Sl = slice(Size, Defs);
    for (const std::string &K : Sl)
      if (Caps.count(K))
        return true;
    auto shares = [&](const Keys &Other) {
      for (const std::string &K : Other)
        if (!Caps.count(K) && Sl.count(K))
          return true;
      return false;
    };
    for (const BinaryOperator *C : Compares) {
      Keys CS = slice(C, Defs);
      bool HasCap = false;
      for (const std::string &K : CS)
        HasCap |= Caps.count(K) > 0;
      // The function consults the capacity (`j < value->len`, or `p < last`
      // with `last = s.data + s.len`): the size is bounded on that path. An
      // equality test bounds it only against the size itself
      // (`if (enc->data_size != enc_in->data_size) return 0;`), not
      // `if (b->len == 0)`.
      if (HasCap && (C->isRelationalOp() || shares(CS)))
        return true;
    }
    for (const BinaryOperator *A : FieldAssigns)
      if (Caps.count(raptor_mem::keyOf(A->getLHS())) && shares(slice(A->getRHS(), Defs)))
        return true;
    return false;
  }

  // The pointer/array field a pointer value comes from.
  static const MemberExpr *bufferField(const Expr *E, const DefMap &Defs,
                                       std::set<std::string> &Seen, int Depth) {
    E = raptor::strip(E);
    if (!E || Depth > 8)
      return nullptr;
    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      QualType T = ME->getType();
      return T->isPointerType() || T->isArrayType() ? ME : nullptr;
    }
    if (const auto *UO = dyn_cast<UnaryOperator>(E))
      if (UO->getOpcode() == UO_AddrOf)
        if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(raptor::strip(UO->getSubExpr())))
          return bufferField(ASE->getBase(), Defs, Seen, Depth + 1);
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->isAdditiveOp()) {
        const Expr *P = BO->getLHS()->getType()->isPointerType() ? BO->getLHS() : BO->getRHS();
        return bufferField(P, Defs, Seen, Depth + 1);
      }
      return nullptr;
    }
    if (const VarDecl *V = localVar(E)) {
      if (!V->getType()->isPointerType() || !Seen.insert(V->getNameAsString()).second)
        return nullptr;
      auto It = Defs.find(V->getNameAsString());
      if (It != Defs.end())
        for (const Expr *Dv : It->second)
          if (const MemberExpr *M = bufferField(Dv, Defs, Seen, Depth + 1))
            return M;
    }
    return nullptr;
  }

  // Keys of the capacity fields next to Buf (`p->bmpSize` for p->bmpData).
  static Keys capacityKeys(const MemberExpr *Buf) {
    Keys Out;
    const auto *FD = dyn_cast<FieldDecl>(Buf->getMemberDecl());
    std::string Base = raptor_mem::keyOf(Buf->getBase());
    if (!FD || Base.empty())
      return Out;
    std::string Sep = Buf->isArrow() ? "->" : ".";
    for (const FieldDecl *F : FD->getParent()->fields())
      if (F != FD && F->getType()->isIntegerType() && raptor_mem::isSizeField(F, FD))
        Out.insert(Base + Sep + F->getNameAsString());
    return Out;
  }
};
} // namespace

RAPTOR_CHECKER(SizeFieldIgnoresCapacityChecker, "SizeFieldIgnoresCapacity",
               "Size field of a (pointer, size) pair neither derived from nor compared with "
               "the buffer's capacity")
