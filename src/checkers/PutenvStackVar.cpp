// Port of raptor-putenv-stack-var: putenv() of a non-static local buffer
// (or a pointer to one). Path-sensitive: the argument's value must point
// into the stack locals space (static locals live in the globals space).
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class PutenvStackVarChecker : public Checker<check::PreCall> {
  const BugType BT{this, "putenv() with a stack variable", raptor::Category};

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (!Call.isGlobalCFunction("putenv") || Call.getNumArgs() != 1)
      return;
    const MemRegion *R = Call.getArgSVal(0).getAsRegion();
    if (!R || !isa<StackLocalsSpaceRegion>(R->getMemorySpace()))
      return;
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Rep = std::make_unique<PathSensitiveBugReport>(
        BT,
        "The software calls putenv() with a pointer to an automatic variable "
        "allocated on the stack; use a static/global string instead",
        N);
    Rep->addRange(Call.getSourceRange());
    C.emitReport(std::move(Rep));
  }
};
} // namespace

RAPTOR_CHECKER(PutenvStackVarChecker, "PutenvStackVar",
               "putenv() called with a stack variable")
