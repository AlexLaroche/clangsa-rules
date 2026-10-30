// raptor.InsecureApiAlloca: any call to alloca().
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
class InsecureApiAllocaChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    raptor::api::reportCallsTo(
        D, Mgr, BR, this, "Use of alloca()",
        "Use of alloca() is unsafe because it cannot ensure that the pointer returned points to a valid and usable block of memory",
        {"alloca"});
  }
};
} // namespace

RAPTOR_CHECKER(InsecureApiAllocaChecker, "InsecureApiAlloca",
               "Use of the insecure alloca() API")
