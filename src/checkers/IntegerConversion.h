// Helpers shared by the IntegerTruncation and SignedUnsignedConversion
// checkers (private to the "int" batch, not part of the common framework).
//
// The semgrep rules match `(DEST $_) = <... (SRC $_) ...>`, i.e. a variable of
// declared type DEST assigned from an expression containing an operand of
// declared type SRC. Clang's real types include the integer promotions (char +
// char is int), which semgrep doesn't see, so instead of the type of the whole
// right-hand side we compute the "effective" source type: the type obtained by
// combining the operand types of the arithmetic without promoting them, and
// ignoring integer constants (`x = 0`, `c = c + 1`, `sizeof(...)`).
#pragma once

#include "Common.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <functional>

namespace raptor_int {

using namespace clang;

// Plain integer type the rules care about (no bool, no enums).
inline bool isPlainInt(QualType T) {
  T = T.getCanonicalType();
  if (const auto *BT = T->getAs<BuiltinType>())
    return BT->isInteger() && BT->getKind() != BuiltinType::Bool;
  return false;
}

// Usual-arithmetic-conversion-like combination, without integer promotion.
inline QualType combine(ASTContext &C, QualType A, QualType B) {
  if (A.isNull())
    return B;
  if (B.isNull())
    return A;
  unsigned WA = C.getIntWidth(A), WB = C.getIntWidth(B);
  if (WA != WB)
    return WA > WB ? A : B;
  return B->isUnsignedIntegerType() ? B : A;
}

// Effective integer type of E (null when E is a constant or not an integer).
// ThroughExplicit: also look through explicit integer casts, like semgrep's
// deep `<... (int $_) ...>` does.
inline QualType effectiveType(ASTContext &C, const Expr *E,
                              bool ThroughExplicit) {
  if (!E)
    return {};
  E = E->IgnoreParens();
  if (E->isValueDependent() || E->isTypeDependent())
    return {};
  if (!isPlainInt(E->getType()))
    return {};
  Expr::EvalResult R;
  if (E->EvaluateAsInt(R, C))
    return {};

  if (const auto *CE = dyn_cast<CastExpr>(E)) {
    CastKind K = CE->getCastKind();
    bool Transparent = K == CK_IntegralCast || K == CK_NoOp ||
                       K == CK_LValueToRValue;
    if (Transparent && (isa<ImplicitCastExpr>(CE) || ThroughExplicit))
      return effectiveType(C, CE->getSubExpr(), ThroughExplicit);
    if (isa<ImplicitCastExpr>(CE) && K != CK_IntegralCast)
      return {};
    return E->getType().getCanonicalType();
  }
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    switch (BO->getOpcode()) {
    case BO_Add: case BO_Sub: case BO_Mul: case BO_Div: case BO_Rem:
    case BO_And: case BO_Or: case BO_Xor:
      return combine(C, effectiveType(C, BO->getLHS(), ThroughExplicit),
                     effectiveType(C, BO->getRHS(), ThroughExplicit));
    case BO_Shl: case BO_Shr:
      return effectiveType(C, BO->getLHS(), ThroughExplicit);
    case BO_Comma:
      return effectiveType(C, BO->getRHS(), ThroughExplicit);
    default:
      if (BO->isComparisonOp() || BO->isLogicalOp())
        return {}; // 0 or 1
      return E->getType().getCanonicalType();
    }
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    switch (UO->getOpcode()) {
    case UO_Plus: case UO_Minus: case UO_Not:
      return effectiveType(C, UO->getSubExpr(), ThroughExplicit);
    case UO_LNot:
      return {};
    default:
      return E->getType().getCanonicalType();
    }
  }
  if (const auto *CO = dyn_cast<AbstractConditionalOperator>(E))
    return combine(C, effectiveType(C, CO->getTrueExpr(), ThroughExplicit),
                   effectiveType(C, CO->getFalseExpr(), ThroughExplicit));
  return E->getType().getCanonicalType();
}

// Calls Fn(DestType, RHS, ReportNode) for every `x = e` and `T x = e`, and
// FnRet(Function) for every function whose return statements return a value
// for which RetPred(ReturnType, ReturnValue) holds.
class AssignmentVisitor : public RecursiveASTVisitor<AssignmentVisitor> {
public:
  std::function<void(QualType, const Expr *, const Stmt *)> OnAssign;
  std::function<void(QualType, const Expr *, const VarDecl *, const DeclStmt *)>
      OnInit;
  const DeclStmt *CurDeclStmt = nullptr;

  bool TraverseDeclStmt(DeclStmt *DS) {
    const DeclStmt *Saved = CurDeclStmt;
    CurDeclStmt = DS;
    bool Res = RecursiveASTVisitor::TraverseDeclStmt(DS);
    CurDeclStmt = Saved;
    return Res;
  }
  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_Assign && !BO->getLHS()->isTypeDependent())
      OnAssign(BO->getLHS()->getType(), BO->getRHS(), BO);
    return true;
  }
  bool VisitVarDecl(VarDecl *VD) {
    if (VD->hasInit() && !isa<ParmVarDecl>(VD) && CurDeclStmt &&
        VD->getInitStyle() != VarDecl::ListInit)
      OnInit(VD->getType(), VD->getInit(), VD, CurDeclStmt);
    return true;
  }
  // Nested functions are visited on their own by checkASTCodeBody.
  bool TraverseLambdaExpr(LambdaExpr *) { return true; }
  bool TraverseBlockExpr(BlockExpr *) { return true; }
};

// Return values of the function body D (not of nested lambdas/blocks).
inline void forEachReturn(const Stmt *Body,
                          const std::function<void(const ReturnStmt *)> &Fn) {
  if (!Body)
    return;
  if (const auto *RS = dyn_cast<ReturnStmt>(Body))
    Fn(RS);
  for (const Stmt *Child : Body->children())
    if (Child && !isa<LambdaExpr>(Child) && !isa<BlockExpr>(Child))
      forEachReturn(Child, Fn);
}

// Report at the function name, like semgrep's `focus-metavariable: $FUN`.
inline void reportAtFunctionName(ento::BugReporter &BR,
                                 const ento::CheckerBase *C, StringRef Name,
                                 StringRef Msg, const FunctionDecl *FD) {
  ento::PathDiagnosticLocation L(FD->getLocation(), BR.getSourceManager());
  BR.EmitBasicReport(FD, C, Name, raptor::Category, Msg, L,
                     SourceRange(FD->getLocation()));
}

} // namespace raptor_int
