// raptor.UseAfterFree: after free($PTR) (and with no
// `$PTR = ...;` in between), a use of $PTR as $PTR->f, $PTR[i], *$PTR,
// `return $PTR;`, or inside an argument of a call to anything but free().
// Flow-sensitive walk of the CFG (may-analysis); path-sensitive tracking
// is not used because unix.Malloc (enabled by default) sinks the path at
// the first use after free.
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
// The use of a freed key made by S itself (not by its sub-expressions,
// which are separate CFG elements), or nullptr.
const Stmt *useOf(const Stmt *S, const raptor_mem::KeySet &Freed) {
  auto In = [&](const Expr *E) {
    std::string K = raptor_mem::keyOf(E);
    return !K.empty() && Freed.count(K);
  };
  if (const auto *ME = dyn_cast<MemberExpr>(S))
    return ME->isArrow() && In(ME->getBase()) ? S : nullptr;
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(S))
    return In(ASE->getBase()) ? S : nullptr;
  if (const auto *UO = dyn_cast<UnaryOperator>(S))
    return UO->getOpcode() == UO_Deref && In(UO->getSubExpr()) ? S : nullptr;
  if (const auto *RS = dyn_cast<ReturnStmt>(S))
    return RS->getRetValue() && In(RS->getRetValue()) ? S : nullptr;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (raptor::calleeName(CE) == "free")
      return nullptr;
    for (const Expr *A : CE->arguments())
      if (raptor_mem::findKey(A, Freed))
        return S;
  }
  return nullptr;
}

class UseAfterFreeChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const CFG *G = Mgr.getCFG(D);
    if (!G)
      return;
    auto In = raptor_mem::solveForward(*G, raptor_mem::trackFrees);
    for (const CFGBlock *B : *G) {
      raptor_mem::KeySet Freed = In[B];
      for (const CFGElement &E : *B) {
        auto CS = E.getAs<CFGStmt>();
        if (!CS)
          continue;
        const Stmt *S = CS->getStmt();
        if (const Stmt *U = useOf(S, Freed))
          raptor::reportAt(
              BR, this, "Use after free",
              "The use of previously-freed memory can have any number of "
              "adverse consequences, ranging from the corruption of valid "
              "data to the execution of arbitrary code",
              U, Mgr.getAnalysisDeclContext(D));
        raptor_mem::trackFrees(S, Freed);
      }
    }
  }
};
} // namespace

RAPTOR_CHECKER(UseAfterFreeChecker, "UseAfterFree",
               "Use of previously-freed memory")
