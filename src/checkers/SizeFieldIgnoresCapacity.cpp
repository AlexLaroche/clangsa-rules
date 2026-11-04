// raptor.SizeFieldIgnoresCapacity: a (pointer, size) pair is set up to
// describe another object's buffer, but the size neither comes from that
// buffer's capacity field nor is compared with it (CWE-787, CWE-125).
//
//   entry->size = entry2.width * entry2.height * 4;
//   entry->data = persistent->bmpData;          // holds persistent->bmpSize
//
// Pair: in one block, `x->p = <buffer>` and `x->s = <size>` on the same
// object, where s is a size field of p (size, len, p_len...).
// Buffer: a pointer or array field `y->b` (directly, plus an offset, or
// through a local pointer set from it) whose struct has a capacity field for
// b (bmpData -> bmpSize, block -> block_size).
// Size: not a constant. Its slice is the variables and fields it uses,
// followed back through the definitions of locals.
// Not reported: the slice contains the size field itself (`x->len =
// x->len - k` keeps the pair's invariant) or a capacity field; a relational comparison
// mentions a capacity field and shares a variable with the slice (`n >
// c->bmpSize`, `allocated > bmpSize` with `allocated` set from `expected`);
// a capacity field is set from the slice.
//
// CVE-2026-111381 (FreeRDP persistent cache v2 parser).
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/Analysis/AnalysisDeclContext.h"
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
    walk(Body, [&](const Stmt *S) {
      if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *Dc : DS->decls())
          if (const auto *VD = dyn_cast<VarDecl>(Dc))
            if (VD->getInit())
              Defs[VD->getNameAsString()].push_back(VD->getInit());
      } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isRelationalOp())
          Compares.push_back(BO);
        else if (BO->isAssignmentOp()) {
          if (const VarDecl *V = localVar(BO->getLHS()))
            Defs[V->getNameAsString()].push_back(BO->getRHS());
          else if (BO->getOpcode() == BO_Assign && isa<MemberExpr>(raptor::strip(BO->getLHS())))
            FieldAssigns.push_back(BO);
        }
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
      std::string Obj = raptor_mem::keyOf(PtrME->getBase());
      for (const BinaryOperator *SizeA : FieldAssigns) {
        const auto *SizeME = cast<MemberExpr>(raptor::strip(SizeA->getLHS()));
        const auto *SizeFD = dyn_cast<FieldDecl>(SizeME->getMemberDecl());
        if (!SizeFD || SizeFD->getParent() != PtrFD->getParent() ||
            !SizeFD->getType()->isIntegerType() || !SizeFD->getIdentifier() ||
            raptor_mem::keyOf(SizeME->getBase()) != Obj ||
            !raptor_mem::isSizeOf(SizeFD->getName(), PtrFD->getName()))
          continue;
        // One pair: both set in the same block.
        if (PM.getParent(SizeA) != PM.getParent(PtrA))
          continue;
        const Expr *Size = raptor::strip(SizeA->getRHS());
        if (Size->isValueDependent() || Size->isIntegerConstantExpr(Ctx))
          continue;
        // Updated from its own old value: the pair's invariant is kept.
        if (slice(Size, Defs).count(raptor_mem::keyOf(SizeME)))
          continue;
        if (sanitized(Size, Caps, Defs, Compares, FieldAssigns))
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
      if (HasCap && shares(CS))
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
      if (F != FD && F->getType()->isIntegerType() && F->getIdentifier() &&
          raptor_mem::isSizeOf(F->getName(), FD->getName()))
        Out.insert(Base + Sep + F->getNameAsString());
    return Out;
  }
};
} // namespace

RAPTOR_CHECKER(SizeFieldIgnoresCapacityChecker, "SizeFieldIgnoresCapacity",
               "Size field of a (pointer, size) pair neither derived from nor compared with "
               "the buffer's capacity")
