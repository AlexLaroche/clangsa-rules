#include "Common.h"
#include <algorithm>

using namespace clang;
using namespace ento;

void raptor::reportAt(BugReporter &BR, const CheckerBase *C, StringRef Name,
                      StringRef Msg, const Stmt *S, AnalysisDeclContext *ADC) {
  PathDiagnosticLocation L =
      PathDiagnosticLocation::createBegin(S, BR.getSourceManager(), ADC);
  BR.EmitBasicReport(ADC->getDecl(), C, Name, Category, oneLine(Msg), L,
                     S->getSourceRange());
}

void raptor::reportAt(BugReporter &BR, const CheckerBase *C, StringRef Name,
                      StringRef Msg, const Decl *D) {
  PathDiagnosticLocation L =
      PathDiagnosticLocation::createBegin(D, BR.getSourceManager());
  BR.EmitBasicReport(D, C, Name, Category, oneLine(Msg), L,
                     D->getSourceRange());
}

std::string raptor::oneLine(StringRef S) {
  std::string R;
  bool Space = false;
  for (char C : S) {
    if (C == ' ' || C == '\t' || C == '\n' || C == '\r' || C == '\f' ||
        C == '\v') {
      Space = true;
      continue;
    }
    if (Space && !R.empty())
      R += ' ';
    Space = false;
    R += C;
  }
  return R;
}

StringRef raptor::calleeName(const CallExpr *CE) {
  if (const FunctionDecl *FD = CE->getDirectCallee())
    if (const IdentifierInfo *II = FD->getIdentifier())
      return II->getName();
  return "";
}

bool raptor::isOneOf(StringRef S, std::initializer_list<StringRef> L) {
  for (StringRef X : L)
    if (S == X)
      return true;
  return false;
}

const Expr *raptor::strip(const Expr *E) {
  return E ? E->IgnoreParenCasts() : nullptr;
}

unsigned raptor::valueBits(const clang::Expr *E, const clang::ASTContext &Ctx) {
  using namespace clang;
  E = E->IgnoreParens();
  Expr::EvalResult R;
  if (!E->isValueDependent() && E->EvaluateAsInt(R, Ctx)) {
    const llvm::APSInt &V = R.Val.getInt();
    return V.isNegative() ? Ctx.getIntWidth(E->getType())
                          : std::max(1u, V.getActiveBits());
  }
  if (const auto *ICE = dyn_cast<ImplicitCastExpr>(E)) {
    if (ICE->getCastKind() == CK_IntegralCast ||
        ICE->getCastKind() == CK_LValueToRValue ||
        ICE->getCastKind() == CK_NoOp)
      return valueBits(ICE->getSubExpr(), Ctx);
  }
  if (const auto *ME = dyn_cast<MemberExpr>(E))
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
        FD && FD->isBitField())
      return FD->getBitWidthValue();
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    unsigned L = valueBits(BO->getLHS(), Ctx),
             Rt = valueBits(BO->getRHS(), Ctx);
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
    return std::max(valueBits(CO->getTrueExpr(), Ctx),
                    valueBits(CO->getFalseExpr(), Ctx));
  QualType T = E->getType();
  if (T.isNull() || T->isDependentType() || !T->isIntegerType())
    return 0;
  return Ctx.getIntWidth(T);
}
