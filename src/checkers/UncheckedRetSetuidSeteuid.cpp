// raptor.UncheckedRetSetuidSeteuid: setuid()/seteuid() whose
// return value is not assigned, compared, negated, or returned.
#include "Common.h"
#include "Registry.h"
#include "RetUtil.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
class UncheckedRetSetuidSeteuidChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    auto M = callExpr(callee(functionDecl(hasAnyName("setuid", "seteuid"))))
                 .bind("call");
    for (const BoundNodes &N : match(findAll(M), *D->getBody(), Ctx)) {
      const auto *CE = N.getNodeAs<CallExpr>("call");
      raptor::RetUse U = raptor::retUse(CE, Ctx, /*ThroughNot=*/true);
      if (U.Negated || raptor::isInitializer(U) ||
          llvm::isa_and_nonnull<ReturnStmt>(U.User))
        continue;
      if (const auto *BO = llvm::dyn_cast_or_null<BinaryOperator>(U.User)) {
        bool IsLHS = BO->getLHS() == U.Operand;
        switch (BO->getOpcode()) {
        case BO_Assign:
          if (!IsLHS)
            continue;
          break;
        case BO_EQ:
        case BO_NE:
          continue;
        case BO_LT: // $FUN(...) < $_
          if (IsLHS)
            continue;
          break;
        case BO_GT: // $_ > $FUN(...)
          if (!IsLHS)
            continue;
          break;
        default:
          break;
        }
      }
      raptor::reportAt(BR, this, "Unchecked return value of setuid()",
                       "The return value of " + raptor::calleeName(CE).str() +
                           "() is not checked; if dropping privileges fails "
                           "the program keeps running with elevated privileges",
                       CE, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(UncheckedRetSetuidSeteuidChecker, "UncheckedRetSetuidSeteuid",
               "Unchecked return value of setuid()/seteuid()")
