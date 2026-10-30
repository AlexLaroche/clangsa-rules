// Port of raptor-unchecked-ret-scanf: a *scanf() call whose return value is
// not assigned, compared, or returned.
#include "Common.h"
#include "Registry.h"
#include "RetUtil.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
class UncheckedRetScanfChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    auto M = callExpr(callee(functionDecl(hasAnyName(
        "scanf", "__isoc99_scanf", "vscanf", "__isoc99_vscanf", "fscanf",
        "__isoc99_fscanf", "vfscanf", "__isoc99_vfscanf", "sscanf",
        "__isoc99_sscanf", "vsscanf", "__isoc99_vsscanf", "wscanf", "vwscanf",
        "fwscanf", "vfwscanf", "swscanf", "vswscanf")))).bind("call");
    for (const BoundNodes &N : match(findAll(M), *D->getBody(), Ctx)) {
      const auto *CE = N.getNodeAs<CallExpr>("call");
      raptor::RetUse U = raptor::retUse(CE, Ctx, /*ThroughNot=*/false);
      if (raptor::isInitializer(U) || llvm::isa_and_nonnull<ReturnStmt>(U.User))
        continue;
      if (const auto *BO = llvm::dyn_cast_or_null<BinaryOperator>(U.User))
        if (BO->isComparisonOp() ||
            (BO->getOpcode() == BO_Assign && BO->getRHS() == U.Operand))
          continue;
      raptor::reportAt(BR, this, "Unchecked return value of scanf()",
                       "The return value of " + raptor::calleeName(CE).str() +
                           "() is not checked, so a failed or partial "
                           "conversion goes unnoticed",
                       CE, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(UncheckedRetScanfChecker, "UncheckedRetScanf",
               "Unchecked return value of a *scanf() function")
