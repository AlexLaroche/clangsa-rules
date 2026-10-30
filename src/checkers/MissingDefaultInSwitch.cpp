// raptor.MissingDefaultInSwitch: switch statement without a
// default label.
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
class MissingDefaultInSwitchChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    auto M = switchStmt().bind("sw");
    for (const BoundNodes &N :
         match(findAll(M), *D->getBody(), Mgr.getASTContext())) {
      const auto *SW = N.getNodeAs<SwitchStmt>("sw");
      bool HasDefault = false;
      for (const SwitchCase *SC = SW->getSwitchCaseList(); SC;
           SC = SC->getNextSwitchCase())
        HasDefault |= isa<DefaultStmt>(SC);
      if (HasDefault || !SW->getCond())
        continue;
      // focus-metavariable: $VAR
      raptor::reportAt(BR, this, "Missing default in switch",
                       "The code does not have a default case in an "
                       "expression with multiple conditions, such as a "
                       "switch statement",
                       SW->getCond(), Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(MissingDefaultInSwitchChecker, "MissingDefaultInSwitch",
               "Switch statement without a default case (CWE-478)")
