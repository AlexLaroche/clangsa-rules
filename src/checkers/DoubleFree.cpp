// raptor.DoubleFree: free($PTR); ... free($PTR); with no
// `$PTR = ...;` in between. The releasers are raptor_mem::releasedArg's:
// free() and friends, library destructors (`OCSP_REQUEST_free(req)`,
// mongo-c-driver CVE-2026-84964) and allocator hooks (libssh2
// `SSH2_FREE(session, data)` -> `session->free(data, ...)`, CVE-2026-66032).
// A plain free() after destructors known only by name (`x_free(p); free(p);`)
// is the release of the block whose contents they cleared: not reported.
// Flow-sensitive walk of the CFG (may-analysis, so a free on any incoming path
// counts). Path-sensitive tracking of the freed symbol is not used because
// unix.Malloc (enabled by default) sinks the path at the first double free.
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
        if (const auto *CE = dyn_cast<CallExpr>(S))
          if (const Expr *P = raptor_mem::releasedArg(CE);
              P &&
              (Freed.count(raptor_mem::keyOf(P)) ||
               Freed.count("?" + raptor_mem::keyOf(P))) &&
              !raptor_mem::onlyRetry(Freed, raptor_mem::keyOf(P), CE) &&
              !(raptor_mem::isPlainFreeName(raptor::calleeName(CE)) &&
                raptor_mem::onlyNamedDestructors(Freed, raptor_mem::keyOf(P))))
            raptor::reportAt(
                BR, this, "Double free",
                "The software releases the same memory address twice (free(), "
                "a library destructor or an allocator hook), potentially "
                "leading to memory corruption",
                CE, Mgr.getAnalysisDeclContext(D));
        raptor_mem::trackFrees(S, Freed);
      }
    }
  }
};
} // namespace

RAPTOR_CHECKER(DoubleFreeChecker, "DoubleFree",
               "free() called twice on the same memory address")
