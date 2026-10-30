// Port of raptor-mismatched-memory-management-cpp: free() of memory not
// from malloc/calloc/realloc/strdup/strndup, `delete` of memory not from
// scalar `new`, `delete[]` of memory not from `new[]`. Path-sensitive: the
// allocation family of each returned symbol is recorded, and a release of
// any other value is reported on the paths where it happens.
#include "Common.h"
#include "Registry.h"
#include "clang/AST/ExprCXX.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"

using namespace clang;
using namespace ento;

namespace {
enum Family : unsigned { FamMalloc, FamNew, FamNewArray };
} // namespace

REGISTER_MAP_WITH_PROGRAMSTATE(RaptorAllocFamily, SymbolRef, unsigned)

namespace {
SymbolRef baseSymbol(SVal V) {
  if (const MemRegion *R = V.getAsRegion())
    if (const auto *SR = dyn_cast<SymbolicRegion>(R->getBaseRegion()))
      return SR->getSymbol();
  return nullptr;
}

class MismatchedMemoryManagementCppChecker
    : public Checker<check::PostCall, check::PreCall,
                     check::PostStmt<CXXNewExpr>,
                     check::PreStmt<CXXDeleteExpr>> {
  const BugType BT{this, "Mismatched memory management routines",
                   raptor::Category};

  void track(SVal V, Family F, CheckerContext &C) const {
    if (SymbolRef S = baseSymbol(V))
      C.addTransition(C.getState()->set<RaptorAllocFamily>(S, F));
  }

  void check(SVal V, Family Want, StringRef Msg, SourceRange SR,
             CheckerContext &C) const {
    SymbolRef S = baseSymbol(V);
    const unsigned *F = S ? C.getState()->get<RaptorAllocFamily>(S) : nullptr;
    if (F && *F == Want)
      return;
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Rep = std::make_unique<PathSensitiveBugReport>(BT, Msg, N);
    Rep->addRange(SR);
    C.emitReport(std::move(Rep));
  }

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (FD && Call.isGlobalCFunction() && FD->getIdentifier() &&
        raptor::isOneOf(FD->getName(),
                        {"malloc", "calloc", "realloc", "strdup", "strndup"}))
      track(Call.getReturnValue(), FamMalloc, C);
  }

  void checkPostStmt(const CXXNewExpr *NE, CheckerContext &C) const {
    track(C.getSVal(NE), NE->isArray() ? FamNewArray : FamNew, C);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (Call.isGlobalCFunction("free") && Call.getNumArgs() == 1)
      check(Call.getArgSVal(0), FamMalloc,
            "free() is called on memory that was not allocated with "
            "malloc(), calloc(), realloc(), strdup() or strndup()",
            Call.getSourceRange(), C);
  }

  void checkPreStmt(const CXXDeleteExpr *DE, CheckerContext &C) const {
    if (DE->isArrayForm())
      check(C.getSVal(DE->getArgument()), FamNewArray,
            "delete[] is called on memory that was not allocated with new[]",
            DE->getSourceRange(), C);
    else
      check(C.getSVal(DE->getArgument()), FamNew,
            "delete is called on memory that was not allocated with new",
            DE->getSourceRange(), C);
  }
};
} // namespace

RAPTOR_CHECKER(MismatchedMemoryManagementCppChecker,
               "MismatchedMemoryManagementCpp",
               "Release function incompatible with the allocation function")
