// raptor.InsecureApiAccessStat: any call to access(), faccessat(), faccessat2(), stat(), lstat(), fstatat().
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
class InsecureApiAccessStatChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    raptor::api::reportCallsTo(
        D, Mgr, BR, this, "TOCTOU race condition",
        "The software checks the state of a resource before using it, but the resource's state can change between the check and the use in a way that invalidates the results of the check",
        {"access", "faccessat", "faccessat2", "stat", "lstat", "fstatat"});
  }
};
} // namespace

RAPTOR_CHECKER(InsecureApiAccessStatChecker, "InsecureApiAccessStat",
               "Use of access()/stat() and similar functions, prone to TOCTOU races")
