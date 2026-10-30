// raptor.UnsafeRetStrlcpyStrlcat: the return value of strlcpy()
// and friends (the length of the string it tried to create) is stored, and
// may later be used as if it were the number of bytes actually copied.
#include "Common.h"
#include "Registry.h"
#include "RetUtil.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
class UnsafeRetStrlcpyStrlcatChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    auto M = callExpr(callee(functionDecl(hasAnyName(
                          "strlcpy", "strlcat", "wcslcpy", "wcslcat",
                          "_mbslcpy", "_mbslcat"))))
                 .bind("call");
    for (const BoundNodes &N : match(findAll(M), *D->getBody(), Ctx)) {
      const auto *CE = N.getNodeAs<CallExpr>("call");
      raptor::RetUse U = raptor::retUse(CE, Ctx, /*ThroughNot=*/false);
      const Stmt *Where = nullptr;
      if (raptor::isInitializer(U))
        Where = CE;
      else if (const auto *BO = llvm::dyn_cast_or_null<BinaryOperator>(U.User))
        if ((BO->getOpcode() == BO_Assign || BO->getOpcode() == BO_AddAssign) &&
            BO->getRHS() == U.Operand)
          Where = BO;
      if (!Where)
        continue;
      raptor::reportAt(BR, this, "Unsafe use of strlcpy() return value",
                       raptor::calleeName(CE).str() +
                           "() returns the length of the string it tried to "
                           "create, not the number of bytes copied; using it "
                           "as an offset or size may overflow the buffer",
                       Where, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(UnsafeRetStrlcpyStrlcatChecker, "UnsafeRetStrlcpyStrlcat",
               "Unsafe use of the strlcpy()/strlcat() return value")
