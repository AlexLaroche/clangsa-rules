// raptor.UseAfterFree: after free($PTR) (and with no
// `$PTR = ...;` in between), a use of $PTR as $PTR->f, $PTR[i], *$PTR,
// `return $PTR;`, or inside an argument of a call (not of a nested call,
// checked on its own, nor as the released argument of another release:
// raptor_mem::releasedArg; that is raptor.DoubleFree's report).
// Flow-sensitive walk of the CFG (may-analysis); path-sensitive tracking
// is not used because unix.Malloc (enabled by default) sinks the path at
// the first use after free.
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <functional>
#include <set>

using namespace clang;
using namespace ento;

namespace {
const Expr *findKeyOutsideCalls(const Stmt *S, const raptor_mem::KeySet &Keys) {
  if (!S || isa<CallExpr>(S))
    return nullptr;
  if (const auto *UE = dyn_cast<UnaryExprOrTypeTraitExpr>(S))
    if (!UE->isArgumentType() &&
        !UE->getArgumentExpr()->getType()->isVariableArrayType())
      return nullptr;
  if (const auto *E = dyn_cast<Expr>(S)) {
    std::string K = raptor_mem::keyOf(E);
    if (!K.empty() && Keys.count(K))
      return E;
  }
  for (const Stmt *C : S->children())
    if (const Expr *R = findKeyOutsideCalls(C, Keys))
      return R;
  return nullptr;
}

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
    // A second release is DoubleFree's report.
    const Expr *Rel = raptor_mem::releasedArg(CE);
    for (const Expr *A : CE->arguments()) {
      if (A == Rel)
        continue;
      // &p: the call may set p again, nothing is read through it
      if (const auto *UO = dyn_cast<UnaryOperator>(raptor::strip(A));
          UO && UO->getOpcode() == UO_AddrOf && In(UO->getSubExpr()))
        continue;
      // Calls nested in the argument are checked as CFG elements of their
      // own (`check(archive_read_free(a))` does not use a afterwards).
      if (findKeyOutsideCalls(A, Freed))
        return S;
    }
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
    auto In = raptor_mem::solveForward(*G, raptor_mem::trackStrictFrees);
    // Releases that return a status, inside a loop: non-blocking releases
    // retried until done (libssh2 BLOCK_ADJUST); the loop only goes on when
    // nothing was released.
    std::set<std::string> Retried;
    std::function<void(const Stmt *, bool)> scan = [&](const Stmt *S,
                                                       bool InLoop) {
      if (!S)
        return;
      if (const auto *CE = dyn_cast<CallExpr>(S);
          CE && InLoop && !CE->getType()->isVoidType())
        Retried.insert(std::to_string(reinterpret_cast<uintptr_t>(CE)));
      bool L = InLoop || isa<ForStmt>(S) || isa<WhileStmt>(S) || isa<DoStmt>(S);
      for (const Stmt *C : S->children())
        scan(C, L);
    };
    scan(D->getBody(), false);
    // Is every release of the keys U uses a retried one?
    auto retried = [&](const Stmt *U, const raptor_mem::KeySet &Freed) {
      bool Any = false;
      for (const std::string &K : Freed) {
        if (K.empty() || K[0] == '@' || K[0] == '?' || K[0] == '&' ||
            !raptor_mem::findKey(U, {K}))
          continue;
        std::string Pre = "@" + K + "#";
        for (auto It = Freed.lower_bound(Pre);
             It != Freed.end() && llvm::StringRef(*It).starts_with(Pre); ++It) {
          if (!Retried.count(It->substr(Pre.size())))
            return false;
          Any = true;
        }
      }
      return Any;
    };
    for (const CFGBlock *B : *G) {
      raptor_mem::KeySet Freed = In[B];
      for (const CFGElement &E : *B) {
        auto CS = E.getAs<CFGStmt>();
        if (!CS)
          continue;
        const Stmt *S = CS->getStmt();
        if (const Stmt *U = useOf(S, Freed); U && !retried(U, Freed))
          raptor::reportAt(
              BR, this, "Use after free",
              "The use of previously-freed memory can have any number of "
              "adverse consequences, ranging from the corruption of valid "
              "data to the execution of arbitrary code",
              U, Mgr.getAnalysisDeclContext(D));
        raptor_mem::trackStrictFrees(S, Freed);
      }
    }
  }
};
} // namespace

RAPTOR_CHECKER(UseAfterFreeChecker, "UseAfterFree",
               "Use of previously-freed memory")
