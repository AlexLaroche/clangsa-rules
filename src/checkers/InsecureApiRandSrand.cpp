// Port of raptor-insecure-api-rand-srand: any call to rand(), srand(), drand48(), erand48(), lrand48(), nrand48(), mrand48(), jrand48(), lcong48(), srand48(), seed48().
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
class InsecureApiRandSrandChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    raptor::api::reportCallsTo(
        D, Mgr, BR, this, "Use of weak PRNG",
        "The rand() PRNG should not be used in applications intended to be portable when good randomness is needed",
        {"rand", "srand", "drand48", "erand48", "lrand48", "nrand48", "mrand48", "jrand48", "lcong48", "srand48", "seed48"});
  }
};
} // namespace

RAPTOR_CHECKER(InsecureApiRandSrandChecker, "InsecureApiRandSrand",
               "Use of the weak rand() family of PRNGs")
