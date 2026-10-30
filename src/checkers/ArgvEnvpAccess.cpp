// Port of raptor-argv-envp-access: any use of an identifier named argv or
// envp (by name only, like the semgrep rule: main's parameters under other
// names are not tracked).
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
class ArgvEnvpAccessChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    auto M = declRefExpr(to(namedDecl(hasAnyName("argv", "envp")))).bind("ref");
    for (const BoundNodes &N : match(findAll(M), *D->getBody(), Mgr.getASTContext()))
      raptor::reportAt(BR, this, "Access to argv/envp",
                       "The program accesses command-line arguments or "
                       "environment variables, which are controlled by "
                       "potential attackers",
                       N.getNodeAs<DeclRefExpr>("ref"),
                       Mgr.getAnalysisDeclContext(D));
  }
};
} // namespace

RAPTOR_CHECKER(ArgvEnvpAccessChecker, "ArgvEnvpAccess",
               "Access to command-line arguments or environment variables")
