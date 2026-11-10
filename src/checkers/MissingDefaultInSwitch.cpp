// raptor.MissingDefaultInSwitch: switch statement without a
// default label. Not reported: a switch on an enum-typed value with a case
// for every enumerator (-Wswitch catches a missing one).
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

#include "llvm/ADT/SmallSet.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
// A switch on an enum-typed value with a case for every enumerator: the
// compiler (-Wswitch) flags a missing one, a default would hide that.
bool coversEnum(const SwitchStmt *SW) {
  const auto *ET = SW->getCond()->IgnoreParenImpCasts()->getType()->getAs<EnumType>();
  if (!ET)
    return false;
  const EnumDecl *ED = ET->getDecl()->getDefinition();
  if (!ED)
    return false;
  llvm::SmallSet<int64_t, 16> Cases;
  for (const SwitchCase *SC = SW->getSwitchCaseList(); SC; SC = SC->getNextSwitchCase())
    if (const auto *CS = dyn_cast<CaseStmt>(SC)) {
      Expr::EvalResult R;
      if (CS->getRHS() || !CS->getLHS()->EvaluateAsInt(R, ED->getASTContext()))
        return false; // ranges: keep it simple
      Cases.insert(R.Val.getInt().getExtValue());
    }
  for (const EnumConstantDecl *EC : ED->enumerators())
    if (!Cases.count(EC->getInitVal().getExtValue()))
      return false;
  return true;
}

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
      if (HasDefault || !SW->getCond() || coversEnum(SW))
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
