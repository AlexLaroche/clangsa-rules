// raptor.CopyIgnoresSourceSize: memcpy/memmove reads from a buffer whose size
// is known, but the copy length neither comes from that size nor is compared
// with it (CWE-125, CWE-126, heap over-read).
//
//   s = exif_format_get_size(e->format) * e->components;
//   memcpy(*d + 6 + doff, e->data, s);          // e->data holds e->size bytes
//
//   unsigned char *p = &s->s3->rrec.data[0], *pl;
//   n2s(p, payload); pl = p;
//   memcpy(bp, pl, payload);                    // record holds rrec.length bytes
//
// Source: the second argument is a pointer or array field `obj->f` (directly,
// as `&obj->f[i]` or `obj->f + off`, or through local pointers set from
// them), and obj's struct has an integer field holding its size: a generic
// name (size, len, length, count...) or the buffer's own name with a size
// suffix (buf_len, finish_md_len, uncompressed_size for uncompressed_buffer).
// Length: the third argument, unless it is a constant. Its slice is the
// variables and fields it uses, followed back through the definitions of
// locals.
// A length that is a plain field (`s->init_num`) is program state, not a
// value computed or decoded here, and is not checked.
// Sanitizers: the slice contains a size field of obj (`MIN(n, e->size)`,
// `len = e->size`); some relational comparison in the function mentions
// both a size field of obj and something in the slice
// (`1 + 2 + payload + 16 > s->s3->rrec.length`); or the size field is set
// from the slice (`s->s3->tmp.finish_md_len = i;`). Locals set from a size
// field stand for it (`len = t->response_len; ... if (len < sig_len)`). A
// source position computed from the size (`&h->data[h->data_len - left]`)
// and an in-place move within the same buffer are not reported.
//
// CVE-2020-0093 (libexif < 0.6.22), CVE-2014-0160 (OpenSSL Heartbleed).
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
using Keys = std::set<std::string>;
using DefMap = llvm::DenseMap<const VarDecl *, std::vector<const Expr *>>;

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

class CopyIgnoresSourceSizeChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();

    DefMap Defs; // every value a local is set to (compound assignments too)
    walk(Body, [&](const Stmt *S) {
      if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *Dc : DS->decls())
          if (const auto *VD = dyn_cast<VarDecl>(Dc))
            if (VD->getInit())
              Defs[VD].push_back(VD->getInit());
      } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isAssignmentOp())
          if (const VarDecl *V = localVar(BO->getLHS()))
            Defs[V].push_back(BO->getRHS());
      }
    });

    std::vector<const BinaryOperator *> Compares, SizeAssigns;
    walk(Body, [&](const Stmt *S) {
      if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isRelationalOp())
          Compares.push_back(BO);
        else if (BO->getOpcode() == BO_Assign && isa<MemberExpr>(raptor::strip(BO->getLHS())))
          SizeAssigns.push_back(BO);
      }
    });

    walk(Body, [&](const Stmt *S) {
      const auto *CE = dyn_cast<CallExpr>(S);
      if (!CE || CE->getNumArgs() < 3 ||
          !raptor::isOneOf(raptor::calleeName(CE),
                           {"memcpy", "memmove", "__builtin_memcpy", "__builtin_memmove",
                            "__builtin___memcpy_chk", "__builtin___memmove_chk"}))
        return;
      const Expr *Len = raptor::strip(CE->getArg(2));
      // A constant, or program state kept in a field (s->init_num).
      if (Len->isValueDependent() || Len->isIntegerConstantExpr(Ctx) || isa<MemberExpr>(Len))
        return;
      llvm::SmallPtrSet<const VarDecl *, 8> Seen;
      const MemberExpr *Src = sourceField(CE->getArg(1), Defs, Seen, 0);
      if (!Src)
        return;
      Keys Sizes = sizeKeys(Src);
      if (Sizes.empty())
        return;
      const std::string SizeField = *Sizes.begin();
      // An in-place move within the same buffer.
      {
        llvm::SmallPtrSet<const VarDecl *, 8> SeenDst;
        const MemberExpr *Dst = sourceField(CE->getArg(0), Defs, SeenDst, 0);
        if (Dst && raptor_mem::keyOf(Dst) == raptor_mem::keyOf(Src))
          return;
      }
      // Locals holding the size, or values computed from it (`len = t->len;`).
      for (bool Changed = true; Changed;) {
        Changed = false;
        for (const auto &KV : Defs)
          if (!Sizes.count(KV.first->getNameAsString()))
            for (const Expr *Dv : KV.second)
              if (raptor_mem::findKey(Dv, Sizes)) {
                Sizes.insert(KV.first->getNameAsString());
                Changed = true;
                break;
              }
      }
      // The source position is computed from the size (`&b[len - left]`).
      if (raptor_mem::findKey(CE->getArg(1), Sizes))
        return;
      Keys Slice = slice(Len, Defs);
      for (const std::string &K : Slice)
        if (Sizes.count(K))
          return;
      for (const BinaryOperator *C : Compares)
        if (raptor_mem::findKey(C, Sizes) && raptor_mem::findKey(C, Slice))
          return;
      // The size field is set from the length (`t->md_len = i;`).
      for (const BinaryOperator *A : SizeAssigns)
        if (Sizes.count(raptor_mem::keyOf(A->getLHS())) && raptor_mem::findKey(A->getRHS(), Slice))
          return;
      std::string Field = raptor_mem::keyOf(Src);
      raptor::reportAt(BR, this, "Copy ignores source size",
                       "Copy reads from '" + Field + "', whose size is '" + SizeField +
                           "', but the length neither comes from that size nor is "
                           "compared with it: heap over-read (CWE-125)",
                       CE, Mgr.getAnalysisDeclContext(D));
    });
  }

private:
  // The pointer/array field the copy reads from.
  static const MemberExpr *sourceField(const Expr *E, const DefMap &Defs,
                                       llvm::SmallPtrSet<const VarDecl *, 8> &Seen, int Depth) {
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
          return sourceField(ASE->getBase(), Defs, Seen, Depth + 1);
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->isAdditiveOp() || BO->getOpcode() == BO_AddAssign || BO->getOpcode() == BO_SubAssign) {
        const Expr *P = BO->getLHS()->getType()->isPointerType() ? BO->getLHS() : BO->getRHS();
        return sourceField(P, Defs, Seen, Depth + 1);
      }
      return nullptr;
    }
    if (const VarDecl *V = localVar(E)) {
      if (!V->getType()->isPointerType() || !Seen.insert(V).second)
        return nullptr;
      auto It = Defs.find(V);
      if (It != Defs.end())
        for (const Expr *Dv : It->second)
          if (const MemberExpr *M = sourceField(Dv, Defs, Seen, Depth + 1))
            return M;
    }
    return nullptr;
  }

  // Keys of the size-like integer fields next to Src (`e->size` for e->data).
  static Keys sizeKeys(const MemberExpr *Src) {
    Keys Out;
    const auto *FD = dyn_cast<FieldDecl>(Src->getMemberDecl());
    std::string Base = raptor_mem::keyOf(Src->getBase());
    if (!FD || Base.empty())
      return Out;
    std::string Sep = Src->isArrow() ? "->" : ".";
    for (const FieldDecl *F : FD->getParent()->fields())
      if (F != FD && F->getType()->isIntegerType() && F->getIdentifier() &&
          raptor_mem::isSizeOf(F->getName(), FD->getName()))
        Out.insert(Base + Sep + F->getNameAsString());
    return Out;
  }

  // Keys used by E, followed back through the definitions of locals.
  static Keys slice(const Expr *E, const DefMap &Defs) {
    Keys Out;
    llvm::SmallPtrSet<const VarDecl *, 16> Done;
    std::vector<const Expr *> Work{E};
    while (!Work.empty()) {
      const Expr *X = Work.back();
      Work.pop_back();
      walk(X, [&](const Stmt *S) {
        if (!isa<DeclRefExpr>(S) && !isa<MemberExpr>(S))
          return;
        std::string K = raptor_mem::keyOf(cast<Expr>(S));
        if (!K.empty())
          Out.insert(K);
        if (const auto *DRE = dyn_cast<DeclRefExpr>(S))
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
            if (Done.insert(VD).second) {
              auto It = Defs.find(VD);
              if (It != Defs.end())
                for (const Expr *Dv : It->second)
                  Work.push_back(Dv);
            }
      });
    }
    return Out;
  }
};
} // namespace

RAPTOR_CHECKER(CopyIgnoresSourceSizeChecker, "CopyIgnoresSourceSize",
               "Copy length neither derived from nor compared with the source's size field")
