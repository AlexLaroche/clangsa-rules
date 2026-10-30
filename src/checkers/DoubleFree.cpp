// raptor.DoubleFree: free($PTR); ... free($PTR); with no
// `$PTR = ...;` in between. Flow-sensitive walk of the CFG (may-analysis,
// so a free on any incoming path counts). Path-sensitive tracking of the
// freed symbol is not used because unix.Malloc (enabled by default) sinks
// the path at the first double free.
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
class DoubleFreeChecker : public Checker<check::ASTCodeBody> {
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
        if (raptor_mem::isCallTo(S, "free")) {
          const auto *CE = cast<CallExpr>(S);
          if (CE->getNumArgs() == 1 &&
              Freed.count(raptor_mem::keyOf(CE->getArg(0))))
            raptor::reportAt(
                BR, this, "Double free",
                "The software calls free() twice on the same memory address, "
                "potentially leading to memory corruption",
                CE, Mgr.getAnalysisDeclContext(D));
        }
        raptor_mem::trackFrees(S, Freed);
      }
    }
  }
};
} // namespace

RAPTOR_CHECKER(DoubleFreeChecker, "DoubleFree",
               "free() called twice on the same memory address")
