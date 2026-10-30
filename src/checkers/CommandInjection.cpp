// Port of raptor-command-injection: calls to system(), popen(), p2open() and
// wordexp() whose first argument is not a constant string.
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
class CommandInjectionChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    raptor::api::forEachCall(D, Mgr, [&](const CallExpr *CE) {
      if (!raptor::isOneOf(raptor::api::calleeAsWritten(CE, Ctx),
                           {"system", "popen", "p2open", "wordexp"}))
        return;
      // pattern-not: $_("...", ...)
      if (CE->getNumArgs() > 0 &&
          raptor::api::isConstantString(CE->getArg(0), D->getBody(), Ctx))
        return;
      raptor::reportAt(BR, this, "Potential command injection",
                       "The software constructs an OS command using "
                       "externally-influenced input, but it does not "
                       "neutralize or incorrectly neutralizes special elements "
                       "that could modify the intended OS command",
                       CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(CommandInjectionChecker, "CommandInjection",
               "OS command built from non-constant input")
