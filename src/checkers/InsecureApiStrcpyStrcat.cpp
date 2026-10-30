// Port of raptor-insecure-api-strcpy-strcat: calls to strcpy(), strcat() and
// similar functions, unless the source is a constant string.
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
class InsecureApiStrcpyStrcatChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    raptor::api::forEachCall(D, Mgr, [&](const CallExpr *CE) {
      if (!raptor::isOneOf(raptor::api::calleeAsWritten(CE, Ctx),
                           {"strcpy", "stpcpy", "strcat", "wcscpy", "wcpcpy",
                            "wcscat", "_mbscpy", "_mbscat", "strccpy",
                            "strcadd", "streadd", "strecpy", "strtrns"}))
        return;
      // pattern-not: $_($_, "...", ...)
      if (CE->getNumArgs() >= 2 &&
          raptor::api::isConstantString(CE->getArg(1), D->getBody(), Ctx))
        return;
      raptor::reportAt(BR, this, "Potential buffer overflow in strcpy()",
                       "A buffer overflow condition exists when a program "
                       "attempts to put more data in a buffer than it can hold",
                       CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(InsecureApiStrcpyStrcatChecker, "InsecureApiStrcpyStrcat",
               "Use of strcpy()/strcat() and similar functions")
