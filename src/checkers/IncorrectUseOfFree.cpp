// raptor.IncorrectUseOfFree: free() of a stack buffer, of a
// pointer to one, or of the address of a local variable. Path-sensitive:
// the argument's value must point into stack memory.
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class IncorrectUseOfFreeChecker : public Checker<check::PreCall> {
  const BugType BT{this, "Free of memory not on the heap", raptor::Category};

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (!Call.isGlobalCFunction("free") || Call.getNumArgs() != 1)
      return;
    const MemRegion *R = Call.getArgSVal(0).getAsRegion();
    if (!R || !isa<StackSpaceRegion>(R->getMemorySpace()))
      return;
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Rep = std::make_unique<PathSensitiveBugReport>(
        BT,
        "The software calls free() on a pointer to memory that was not "
        "allocated using heap allocation functions",
        N);
    Rep->addRange(Call.getSourceRange());
    C.emitReport(std::move(Rep));
  }
};
} // namespace

RAPTOR_CHECKER(IncorrectUseOfFreeChecker, "IncorrectUseOfFree",
               "free() called on memory that is not on the heap")
