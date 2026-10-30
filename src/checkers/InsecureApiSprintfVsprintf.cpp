// Port of raptor-insecure-api-sprintf-vsprintf: sprintf()/vsprintf() calls
// whose format, as written, contains %s/%ls/%S or is not a string literal.
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
class InsecureApiSprintfVsprintfChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    raptor::api::forEachCall(D, Mgr, [&](const CallExpr *CE) {
      if (!raptor::isOneOf(raptor::api::calleeAsWritten(CE, Ctx),
                           {"sprintf", "vsprintf"}) ||
          CE->getNumArgs() < 2 ||
          !raptor::api::regexMatchesAtStart(
              raptor::api::textAsWritten(CE->getArg(1), Ctx),
              raptor::api::unsafeFormatRegex()))
        return;
      raptor::reportAt(BR, this, "Potential buffer overflow in sprintf()",
                       "A buffer overflow condition exists when a program "
                       "attempts to put more data in a buffer than it can hold",
                       CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(InsecureApiSprintfVsprintfChecker, "InsecureApiSprintfVsprintf",
               "Use of sprintf()/vsprintf() with unbounded %s")
