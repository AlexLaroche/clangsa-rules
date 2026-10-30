// raptor.InsecureApiGets: any call to gets().
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
class InsecureApiGetsChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    auto M = callExpr(callee(functionDecl(hasName("gets")))).bind("call");
    for (const BoundNodes &N : match(findAll(M), *D->getBody(), Mgr.getASTContext()))
      raptor::reportAt(BR, this, "Use of gets()",
                       "The gets() function is always unsafe because it does "
                       "not perform bounds checking on the size of its input",
                       N.getNodeAs<CallExpr>("call"),
                       Mgr.getAnalysisDeclContext(D));
  }
};
} // namespace

RAPTOR_CHECKER(InsecureApiGetsChecker, "InsecureApiGets",
               "Use of the insecure gets() API")
