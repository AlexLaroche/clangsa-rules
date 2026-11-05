// raptor.NarrowProductWidened: a product computed in 32 bits (or less) and
// then converted to a 64-bit integer type: the conversion says the full
// value is wanted, but the multiplication has already wrapped (CWE-190,
// CWE-681). Size checks and offsets built on it pass with a small number.
//
//   if (nDec + (uint64_t) (w * 3) > outSize)            // explicit widening
//   icUInt64Number nNeededSize = nBytesPerMatrix * nNumMatrices;
//   _numPixels = _pixelsPerRow * _pixelsPerColumn;       // size_t field
//
// Forms: an explicit cast of the product itself (parentheses aside) to a
// 64-bit type, constant factors included; an implicit conversion of a
// product of two run-time values to a 64-bit variable or field in an
// initialisation or an assignment. The operands' value widths must add up to
// more than the product's (raptor::valueBits). Products widened before the
// multiplication (`(uint64_t) w * 3`) are 64-bit and do not match; neither
// do products guarded by a division check on a factor (`a > UINT32_MAX / b`)
// or an overflow helper (`__builtin_mul_overflow`).
//
// CVE-2026-34588 (OpenEXR undo_pxr24), CVE-2026-41142 (OpenEXR
// ImageChannel::resize), CVE-2026-21486 (iccDEV
// CIccTagSparseMatrixArray::Read).
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
template <class F> void walk(const Stmt *S, F &&Fn) {
  if (!S)
    return;
  Fn(S);
  for (const Stmt *C : S->children())
    walk(C, Fn);
}

bool isConst(const Expr *E, const ASTContext &Ctx) {
  return !E->isValueDependent() &&
         E->IgnoreParenImpCasts()->isIntegerConstantExpr(Ctx);
}

// A `*` computed in at most 32 bits whose operands can overflow it.
const BinaryOperator *narrowMul(const Expr *E, const ASTContext &Ctx,
                                bool AllowConst) {
  const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParens());
  if (!BO || BO->getOpcode() != BO_Mul)
    return nullptr;
  QualType T = BO->getType();
  if (!T->isIntegerType() || T->isDependentType() || Ctx.getIntWidth(T) > 32)
    return nullptr;
  bool CL = isConst(BO->getLHS(), Ctx), CR = isConst(BO->getRHS(), Ctx);
  if ((CL && CR) || (!AllowConst && (CL || CR)))
    return nullptr;
  unsigned W = Ctx.getIntWidth(T) - (T->isSignedIntegerType() ? 1 : 0);
  if (raptor::valueBits(BO->getLHS(), Ctx) +
          raptor::valueBits(BO->getRHS(), Ctx) <=
      W)
    return nullptr;
  return BO;
}

bool wide(QualType T, const ASTContext &Ctx) {
  return !T.isNull() && T->isIntegerType() && !T->isDependentType() &&
         Ctx.getIntWidth(T) >= 64;
}

class Visitor : public RecursiveASTVisitor<Visitor> {
public:
  Visitor(const ASTContext &Ctx, std::vector<const BinaryOperator *> &Out)
      : Ctx(Ctx), Out(Out) {}

  bool VisitExplicitCastExpr(ExplicitCastExpr *CE) {
    if (wide(CE->getType(), Ctx))
      if (const BinaryOperator *M =
              narrowMul(CE->getSubExpr()->IgnoreParenImpCasts(), Ctx, true))
        Out.push_back(M);
    return true;
  }
  void implicit(const Expr *E, QualType Dest) {
    if (!E || !wide(Dest, Ctx))
      return;
    const auto *ICE = dyn_cast<ImplicitCastExpr>(E->IgnoreParens());
    if (!ICE || ICE->getCastKind() != CK_IntegralCast)
      return;
    if (const BinaryOperator *M = narrowMul(ICE->getSubExpr(), Ctx, false))
      Out.push_back(M);
  }
  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_Assign)
      implicit(BO->getRHS(), BO->getLHS()->getType());
    return true;
  }
  bool VisitVarDecl(VarDecl *VD) {
    if (VD->hasInit() && !isa<ParmVarDecl>(VD))
      implicit(VD->getInit(), VD->getType());
    return true;
  }
  bool TraverseLambdaExpr(LambdaExpr *) { return true; }

private:
  const ASTContext &Ctx;
  std::vector<const BinaryOperator *> &Out;
};

// A division check or an overflow helper on a factor of M.
bool guarded(const Stmt *Body, const BinaryOperator *M) {
  std::set<std::string> F;
  for (const Expr *Op : {M->getLHS(), M->getRHS()})
    walk(Op, [&](const Stmt *S) {
      if (const auto *E = dyn_cast<Expr>(S))
        if (std::string K = raptor_mem::keyOf(E); !K.empty())
          F.insert(K);
    });
  bool G = false;
  walk(Body, [&](const Stmt *S) {
    if (G)
      return;
    if (const auto *BO = dyn_cast<BinaryOperator>(S);
        BO && BO->isRelationalOp() && raptor_mem::findKey(BO, F))
      walk(BO, [&](const Stmt *X) {
        if (const auto *D = dyn_cast<BinaryOperator>(X);
            D && D->getOpcode() == BO_Div)
          G = true;
      });
    if (const auto *CE = dyn_cast<CallExpr>(S)) {
      std::string N = raptor::calleeName(CE).lower();
      if (N.find("overflow") != std::string::npos ||
          N.find("mult") != std::string::npos)
        for (const Expr *A : CE->arguments())
          if (raptor_mem::findKey(A, F))
            G = true;
    }
  });
  return G;
}

class NarrowProductWidenedChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    std::vector<const BinaryOperator *> Found;
    Visitor V(Ctx, Found);
    V.TraverseStmt(const_cast<Stmt *>(Body));
    std::set<const BinaryOperator *> Seen;
    for (const BinaryOperator *M : Found) {
      if (!Seen.insert(M).second || guarded(Body, M))
        continue;
      if (M->getBeginLoc().isMacroID() &&
          Ctx.getSourceManager().isInSystemMacro(M->getBeginLoc()))
        continue;
      raptor::reportAt(
          BR, this, "Narrow product widened",
          "this product is computed in " +
              std::to_string(Ctx.getIntWidth(M->getType())) +
              " bits and only then converted to a 64-bit type: it wraps "
              "before the conversion; widen an operand instead "
              "(`(uint64_t)a * b`) (CWE-190, CWE-681)",
          M, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(
    NarrowProductWidenedChecker, "NarrowProductWidened",
    "32-bit product converted to a 64-bit type after it may have wrapped")
