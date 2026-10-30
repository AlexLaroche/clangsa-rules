// raptor.MissingBreakInSwitch: a case whose statements fall
// through into the next case/default label because they do not end with
// break, return, goto or exit().
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {

// Does S end the case, i.e. is it break/return/goto/exit(...)?
bool isTerminator(const Stmt *S) {
  if (!S)
    return false;
  // case X: { ...; break; }
  if (const auto *CS = dyn_cast<CompoundStmt>(S))
    return isTerminator(CS->body_back());
  if (isa<BreakStmt, ReturnStmt, GotoStmt, IndirectGotoStmt>(S))
    return true;
  if (const auto *E = dyn_cast<Expr>(S))
    if (const auto *CE = dyn_cast<CallExpr>(E->IgnoreParenCasts()))
      return raptor::calleeName(CE) == "exit";
  return false;
}

class MissingBreakInSwitchChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    auto M = switchStmt().bind("sw");
    for (const BoundNodes &N :
         match(findAll(M), *D->getBody(), Mgr.getASTContext())) {
      const auto *SW = N.getNodeAs<SwitchStmt>("sw");
      if (hasFallthrough(SW) && SW->getCond())
        // focus-metavariable: $VAR
        raptor::reportAt(BR, this, "Missing break in switch",
                         "The software omits a break statement within a "
                         "switch or similar construct, causing code "
                         "associated with multiple conditions to execute",
                         SW->getCond(), Mgr.getAnalysisDeclContext(D));
    }
  }

private:
  // Walk the top-level statements of the switch body. Consecutive labels
  // (case A: case B:) form one group; a non-empty group that is followed by
  // another label must end with a terminator.
  static bool hasFallthrough(const SwitchStmt *SW) {
    const auto *Body = dyn_cast_or_null<CompoundStmt>(SW->getBody());
    if (!Body)
      return false;
    bool InGroup = false;
    const Stmt *Last = nullptr; // last statement of the current group
    for (const Stmt *S : Body->body()) {
      if (const auto *SC = dyn_cast<SwitchCase>(S)) {
        if (InGroup && Last && !isTerminator(Last))
          return true;
        InGroup = true;
        // case A: case B: stmt -> nested SwitchCases
        const Stmt *Sub = SC->getSubStmt();
        while (const auto *Inner = dyn_cast<SwitchCase>(Sub))
          Sub = Inner->getSubStmt();
        Last = isa<NullStmt>(Sub) ? nullptr : Sub;
        continue;
      }
      if (InGroup)
        Last = S;
    }
    return false;
  }
};
} // namespace

RAPTOR_CHECKER(MissingBreakInSwitchChecker, "MissingBreakInSwitch",
               "Omitted break statement in switch (CWE-484)")
