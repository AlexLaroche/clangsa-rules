// raptor.MismatchedMemoryManagement: free($PTR) where $PTR is known not to
// come from malloc/calloc/realloc/strdup/strndup: it points into a local or
// global variable, a string literal, alloca() or a compound literal on the
// current path (path-sensitive). Memory of unknown origin (parameters,
// fields, call results: every teardown function) is not reported. free(NULL)
// is a no-op, so a pointer that is NULL on the current path (e.g. freed after
// a failed allocation) is not reported.
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
// True if V points into memory that is never heap memory: a variable
// (local or global), a string literal, alloca() or a compound literal.
bool notHeap(SVal V) {
  if (auto LI = V.getAs<nonloc::LocAsInteger>())
    V = LI->getLoc();
  const MemRegion *R = V.getAsRegion();
  if (!R)
    return false;
  R = R->getBaseRegion();
  return isa<VarRegion>(R) || isa<StringRegion>(R) || isa<AllocaRegion>(R) ||
         isa<CompoundLiteralRegion>(R);
}

// True if V is NULL on the current path: a null constant, or a value the
// path constraints force to be NULL.
bool isNullOnPath(SVal V, ProgramStateRef State) {
  if (V.isZeroConstant())
    return true;
  if (auto DV = V.getAs<DefinedOrUnknownSVal>())
    return State->isNull(*DV).isConstrainedTrue();
  return false;
}

class MismatchedMemoryManagementChecker : public Checker<check::PreCall> {
  const BugType BT{this, "Mismatched memory management routines",
                   raptor::Category};

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (!Call.isGlobalCFunction("free") || Call.getNumArgs() != 1)
      return;
    SVal Arg = Call.getArgSVal(0);
    if (isNullOnPath(Arg, C.getState()))
      return;
    // Only memory known not to come from malloc(): memory of unknown origin
    // (a parameter, a field, a call result) is what teardown code releases.
    if (!notHeap(Arg))
      return;
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Rep = std::make_unique<PathSensitiveBugReport>(
        BT,
        "free() is called on memory that was not allocated with malloc(), "
        "calloc(), realloc(), strdup() or strndup()",
        N);
    Rep->addRange(Call.getSourceRange());
    C.emitReport(std::move(Rep));
  }
};
} // namespace

RAPTOR_CHECKER(MismatchedMemoryManagementChecker, "MismatchedMemoryManagement",
               "Release function incompatible with the allocation function")
