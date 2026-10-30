// Port of raptor-insecure-api-signal: any call to signal(), gsignal(), ssignal().
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
class InsecureApiSignalChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    raptor::api::reportCallsTo(
        D, Mgr, BR, this, "Use of signal()",
        "The signal() API should be regarded as deprecated; when possible, sigaction() should be used instead",
        {"signal", "gsignal", "ssignal"});
  }
};
} // namespace

RAPTOR_CHECKER(InsecureApiSignalChecker, "InsecureApiSignal",
               "Use of the deprecated signal() API")
