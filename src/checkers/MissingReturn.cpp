// Port of raptor-missing-return: definition of a non-void function (other
// than main) whose body contains no `return <expr>;` at all.
#include "Common.h"
#include "Registry.h"
#include "clang/AST/DeclCXX.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {

// Any `return $_;` anywhere in S (lambdas and blocks are separate functions).
bool hasValueReturn(const Stmt *S) {
  if (!S || isa<LambdaExpr, BlockExpr>(S))
    return false;
  if (const auto *R = dyn_cast<ReturnStmt>(S))
    if (R->getRetValue())
      return true;
  for (const Stmt *C : S->children())
    if (hasValueReturn(C))
      return true;
  return false;
}

class MissingReturnChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const auto *FD = dyn_cast<FunctionDecl>(D);
    if (!FD || !FD->doesThisDeclarationHaveABody() || FD->isMain() ||
        isa<CXXConstructorDecl, CXXDestructorDecl>(FD) ||
        FD->getReturnType()->isVoidType() || FD->isImplicit())
      return;
    if (hasValueReturn(FD->getBody()))
      return;
    // focus-metavariable: $FUN
    PathDiagnosticLocation L(FD->getLocation(), BR.getSourceManager());
    BR.EmitBasicReport(FD, this, "Missing return", raptor::Category,
                       "A non-void function does not have a return "
                       "statement. Hence, its return value can be considered "
                       "undefined",
                       L, FD->getNameInfo().getSourceRange());
  }
};
} // namespace

RAPTOR_CHECKER(MissingReturnChecker, "MissingReturn",
               "Non-void function without a return statement (CWE-393)")
