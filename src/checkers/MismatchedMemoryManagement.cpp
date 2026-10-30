// Port of raptor-mismatched-memory-management: free($PTR) where $PTR does
// not come from malloc/calloc/realloc/strdup/strndup. Path-sensitive: the
// symbols returned by those functions are recorded, and free() of any
// other value (stack memory, parameters, globals, ...) is reported on the
// paths where it happens.
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
SymbolRef baseSymbol(SVal V) {
  if (const MemRegion *R = V.getAsRegion())
    if (const auto *SR = dyn_cast<SymbolicRegion>(R->getBaseRegion()))
      return SR->getSymbol();
  return nullptr;
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
    SymbolRef S = baseSymbol(Call.getArgSVal(0));
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
