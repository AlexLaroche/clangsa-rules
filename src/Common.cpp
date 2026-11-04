#include "Common.h"

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
  BR.EmitBasicReport(D, C, Name, Category, oneLine(Msg), L, D->getSourceRange());
}

std::string raptor::oneLine(StringRef S) {
  std::string R;
  bool Space = false;
  for (char C : S) {
    if (C == ' ' || C == '\t' || C == '\n' || C == '\r' || C == '\f' || C == '\v') {
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
