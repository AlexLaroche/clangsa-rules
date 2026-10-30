#include "Common.h"

using namespace clang;
using namespace ento;

void raptor::reportAt(BugReporter &BR, const CheckerBase *C, StringRef Name,
                      StringRef Msg, const Stmt *S, AnalysisDeclContext *ADC) {
  PathDiagnosticLocation L =
      PathDiagnosticLocation::createBegin(S, BR.getSourceManager(), ADC);
  BR.EmitBasicReport(ADC->getDecl(), C, Name, Category, Msg, L,
                     S->getSourceRange());
}

void raptor::reportAt(BugReporter &BR, const CheckerBase *C, StringRef Name,
                      StringRef Msg, const Decl *D) {
  PathDiagnosticLocation L =
      PathDiagnosticLocation::createBegin(D, BR.getSourceManager());
  BR.EmitBasicReport(D, C, Name, Category, Msg, L, D->getSourceRange());
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
