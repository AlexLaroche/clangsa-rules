// raptor.MismatchedMemoryManagement: free($PTR) where $PTR does
// not come from malloc/calloc/realloc/strdup/strndup. Path-sensitive: the
// symbols returned by those functions are recorded, and free() of any
// other value (stack memory, parameters, globals, ...) is reported on the
// paths where it happens. free(NULL) is a no-op, so a pointer that is NULL
// on the current path (e.g. freed after a failed allocation) is not reported.
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"

using namespace clang;
using namespace ento;

REGISTER_SET_WITH_PROGRAMSTATE(RaptorMallocedSyms, SymbolRef)

namespace {
// The symbol of the allocation V points into. Looks through pointer/integer
// round trips such as free((void *)(size_t)p), which turn the pointer into a
// nonloc::LocAsInteger.
SymbolRef baseSymbol(SVal V) {
  if (auto LI = V.getAs<nonloc::LocAsInteger>())
    V = LI->getLoc();
  if (const MemRegion *R = V.getAsRegion())
    if (const auto *SR = dyn_cast<SymbolicRegion>(R->getBaseRegion()))
      return SR->getSymbol();
  return nullptr;
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

class MismatchedMemoryManagementChecker
    : public Checker<check::PostCall, check::PreCall> {
  const BugType BT{this, "Mismatched memory management routines",
                   raptor::Category};

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !Call.isGlobalCFunction() || !FD->getIdentifier() ||
        !raptor::isOneOf(FD->getName(), {"malloc", "calloc", "realloc",
                                         "strdup", "strndup"}))
      return;
    if (SymbolRef S = baseSymbol(Call.getReturnValue()))
      C.addTransition(C.getState()->add<RaptorMallocedSyms>(S));
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (!Call.isGlobalCFunction("free") || Call.getNumArgs() != 1)
      return;
    SVal Arg = Call.getArgSVal(0);
    if (isNullOnPath(Arg, C.getState()))
      return;
    SymbolRef S = baseSymbol(Arg);
    if (S && C.getState()->contains<RaptorMallocedSyms>(S))
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
