// raptor.UnsafeRetSnprintfVsnprintf: the return value of
// snprintf()/vsnprintf() (the length of the string it tried to create) is
// stored while the format can expand to an arbitrarily long string (%s,
// %ls, %S, or a non-literal format), and may be used as a size or offset.
#include "Common.h"
#include "Registry.h"
#include "RetUtil.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/Support/Regex.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
// Same condition as the semgrep metavariable-regex on $FMT
bool riskyFormat(const Expr *Fmt) {
  if (const auto *SL = dyn_cast<StringLiteral>(raptor::strip(Fmt))) {
    if (!SL->isOrdinary() && !SL->isUTF8())
      return true;
    static llvm::Regex Re("%l?s|%S");
    return Re.match(SL->getString());
  }
  return true; // the format is a variable or other expression
}

class UnsafeRetSnprintfVsnprintfChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    auto M = callExpr(callee(functionDecl(hasAnyName("snprintf", "vsnprintf"))),
                      argumentCountAtLeast(3))
                 .bind("call");
    for (const BoundNodes &N : match(findAll(M), *D->getBody(), Ctx)) {
      const auto *CE = N.getNodeAs<CallExpr>("call");
      if (!riskyFormat(CE->getArg(2)))
        continue;
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
      raptor::reportAt(BR, this, "Unsafe use of snprintf() return value",
                       raptor::calleeName(CE).str() +
                           "() returns the length of the string it tried to "
                           "create, which can exceed the buffer size; using "
                           "it as a size or offset may overflow the buffer",
                       Where, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(UnsafeRetSnprintfVsnprintfChecker, "UnsafeRetSnprintfVsnprintf",
               "Unsafe use of the snprintf()/vsnprintf() return value")
