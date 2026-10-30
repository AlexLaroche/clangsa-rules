// Port of raptor-insecure-api-ato: any call to atoi(), atol(), atof(), atoll().
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
class InsecureApiAtoChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    raptor::api::reportCallsTo(
        D, Mgr, BR, this, "Use of atoi() and similar functions",
        "The atoi(), atol(), atof(), and similar functions don't handle errors",
        {"atoi", "atol", "atof", "atoll"});
  }
};
} // namespace

RAPTOR_CHECKER(InsecureApiAtoChecker, "InsecureApiAto",
               "Use of the atoi() family of functions, which do not handle errors")
