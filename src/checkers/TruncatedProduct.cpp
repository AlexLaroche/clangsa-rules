// raptor.TruncatedProduct: a product of two run-time values, computed in
// int by the integer promotions, is implicitly converted to a type narrower
// than int that cannot hold it, in an assignment, an initialisation or a
// return. A count or a size wraps to a small value: the buffer allocated
// from it is too small for the loops that use the real product (CWE-190,
// CWE-681, CWE-787).
//
//   of.numtrk = of.numchn * of.numpat;   // UWORD = UBYTE * UWORD (24 bits)
//   AllocTracks();                       // of.numtrk tracks ...
//   for (t = 0; t < of.numchn * of.numpat; t++) of.tracks[t] = ...;
//
// Product: `a * b` (parentheses and implicit casts aside) with neither
// operand a constant. It can wrap when the operands' widths add up to more
// than the destination's: the width of an operand is that of its declared
// type before promotion (a bit-field's own width), plus one for `x + c` or
// `x - c` (`(v1 + 1) * (v2 + 1)`), and the larger one for `a | b`, `a ^ b`,
// `a ? b : c`; `a & mask` is no wider than the mask.
// Not reported: an explicit cast (`(UWORD)numtrk` after a range check, as in
// the fixes), products into int or wider (UncheckedAllocProduct's), products
// that fit (`UWORD n = u8 * u8;`), constant factors.
//
// CVE-2026-105837 (libmikmod DSM_Load), CVE-2026-105839 (libmikmod
// OKT_doPBOD), CVE-2026-21688 (iccDEV SIccCalcOp::ArgsUsed).
#include "Common.h"
#include "Registry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <algorithm>

using namespace clang;
using namespace ento;

namespace {
bool isConst(const Expr *E, const ASTContext &Ctx) {
  Expr::EvalResult R;
  return !E->isValueDependent() && E->EvaluateAsInt(R, Ctx);
}

// Bits needed for the values E can take, before promotion; 0 when unknown.
unsigned width(const Expr *E, const ASTContext &Ctx) {
  E = E->IgnoreParens();
  Expr::EvalResult R;
  if (!E->isValueDependent() && E->EvaluateAsInt(R, Ctx)) {
    const llvm::APSInt &V = R.Val.getInt();
    return V.isNegative() ? Ctx.getIntWidth(E->getType()) : std::max(1u, V.getActiveBits());
  }
  if (const auto *ICE = dyn_cast<ImplicitCastExpr>(E)) {
    if (ICE->getCastKind() == CK_IntegralCast || ICE->getCastKind() == CK_LValueToRValue ||
        ICE->getCastKind() == CK_NoOp)
      return width(ICE->getSubExpr(), Ctx);
  }
  if (const auto *ME = dyn_cast<MemberExpr>(E))
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl()); FD && FD->isBitField())
      return FD->getBitWidthValue();
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    unsigned L = width(BO->getLHS(), Ctx), Rt = width(BO->getRHS(), Ctx);
    switch (BO->getOpcode()) {
    case BO_Add:
    case BO_Sub:
      return std::max(L, Rt) + 1;
    case BO_Or:
    case BO_Xor:
      return std::max(L, Rt);
    case BO_And:
      return std::min(L, Rt);
    case BO_Shr:
      return L;
    default:
      break;
    }
  }
  if (const auto *CO = dyn_cast<ConditionalOperator>(E))
    return std::max(width(CO->getTrueExpr(), Ctx), width(CO->getFalseExpr(), Ctx));
  QualType T = E->getType();
  if (!T->isIntegerType())
    return 0;
  return Ctx.getIntWidth(T);
}

class Visitor : public RecursiveASTVisitor<Visitor> {
public:
  Visitor(ASTContext &Ctx, std::function<void(const Expr *, QualType, unsigned)> Report)
      : Ctx(Ctx), Report(std::move(Report)) {}

  // E converted to Dest: report when it is a product that does not fit.
  void check(const Expr *E, QualType Dest) {
    if (!E || Dest.isNull() || !Dest->isIntegerType() || Dest->isBooleanType())
      return;
    const auto *ICE = dyn_cast<ImplicitCastExpr>(E->IgnoreParens());
    if (!ICE || ICE->getCastKind() != CK_IntegralCast)
      return;
    unsigned WD = Ctx.getIntWidth(Dest);
    if (WD >= Ctx.getIntWidth(Ctx.IntTy))
      return;
    const auto *Mul = dyn_cast<BinaryOperator>(ICE->getSubExpr()->IgnoreParens());
    if (!Mul || Mul->getOpcode() != BO_Mul || isConst(Mul->getLHS(), Ctx) ||
        isConst(Mul->getRHS(), Ctx))
      return;
    unsigned L = width(Mul->getLHS(), Ctx), R = width(Mul->getRHS(), Ctx);
    if (!L || !R || L + R <= WD)
      return;
    Report(Mul, Dest, L + R);
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_Assign)
      check(BO->getRHS(), BO->getLHS()->getType());
    return true;
  }
  bool VisitVarDecl(VarDecl *VD) {
    if (VD->hasInit() && !isa<ParmVarDecl>(VD))
      check(VD->getInit(), VD->getType());
    return true;
  }
  bool VisitReturnStmt(ReturnStmt *RS) {
    if (Fn && RS->getRetValue())
      check(RS->getRetValue(), Fn->getReturnType());
    return true;
  }
  bool TraverseLambdaExpr(LambdaExpr *) { return true; }
  bool TraverseBlockExpr(BlockExpr *) { return true; }

  const FunctionDecl *Fn = nullptr;

private:
  ASTContext &Ctx;
  std::function<void(const Expr *, QualType, unsigned)> Report;
};

class TruncatedProductChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    Visitor V(Ctx, [&](const Expr *Mul, QualType Dest, unsigned Bits) {
      if (Mul->getBeginLoc().isMacroID() && Mul->getEndLoc().isMacroID() &&
          Ctx.getSourceManager().isInSystemMacro(Mul->getBeginLoc()))
        return;
      raptor::reportAt(BR, this, "Truncated product",
                       "this product of run-time values needs up to " + std::to_string(Bits) +
                           " bits but is stored in the " +
                           std::to_string(Ctx.getIntWidth(Dest)) + "-bit '" +
                           Dest.getUnqualifiedType().getAsString() +
                           "': a count or size computed this way wraps to a small value, "
                           "while the code that uses it still counts to the full product "
                           "(CWE-190, CWE-681)",
                       Mul, Mgr.getAnalysisDeclContext(D));
    });
    V.Fn = dyn_cast<FunctionDecl>(D);
    V.TraverseStmt(const_cast<Stmt *>(D->getBody()));
  }
};
} // namespace

RAPTOR_CHECKER(TruncatedProductChecker, "TruncatedProduct",
               "Product of run-time values implicitly narrowed below int")
