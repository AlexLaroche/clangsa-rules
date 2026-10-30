// raptor.RetStackAddress: `return $PTR;` where $PTR is a
// non-static local array or a pointer to one, or `return &$VAR;` for a
// non-static local. Path-sensitive: the returned value must point into the
// current frame's stack locals (static locals live in the globals space).
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class RetStackAddressChecker : public Checker<check::PreStmt<ReturnStmt>> {
  const BugType BT{this, "Return of stack variable address", raptor::Category};

public:
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
    const Expr *RV = RS->getRetValue();
    if (!RV)
      return;
    const MemRegion *R = C.getSVal(RV).getAsRegion();
    if (!R)
      return;
    const auto *SR = dyn_cast<StackLocalsSpaceRegion>(R->getMemorySpace());
    if (!SR || SR->getStackFrame() != C.getStackFrame())
      return;
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Rep = std::make_unique<PathSensitiveBugReport>(
        BT,
        "A function returns the address of a stack variable, which will "
        "cause unintended program behavior",
        N);
    Rep->addRange(RS->getSourceRange());
    C.emitReport(std::move(Rep));
  }
};
} // namespace

RAPTOR_CHECKER(RetStackAddressChecker, "RetStackAddress",
               "Function returns the address of a stack variable")
