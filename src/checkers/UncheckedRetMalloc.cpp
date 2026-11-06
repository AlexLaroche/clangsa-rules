// raptor.UncheckedRetMalloc: `$RET = $FUN(...)` for an allocation
// function, unless an `if` reachable afterwards in the CFG mentions $RET in
// its condition, or the assignment is part of an expression containing a
// NULL comparison or a logical negation, or $RET (or the assignment itself)
// is passed to a helper whose body tests that parameter for NULL in an `if`
// (OpenVPN `check_malloc_return(p)`, `ALLOC_OBJ`).
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <functional>

using namespace clang;
using namespace ento;

namespace {
bool isAllocCall(const Expr *E) {
  const auto *CE = dyn_cast_or_null<CallExpr>(raptor::strip(E));
  return CE && raptor::isOneOf(raptor::calleeName(CE),
                               {"malloc", "calloc", "realloc", "reallocf",
                                "valloc", "aligned_alloc", "strdup",
                                "strndup"});
}

// <... $_ == NULL ...>, <... $_ != NULL ...> (either order), <... !$_ ...>
bool hasNullCheck(const Stmt *S, ASTContext &Ctx) {
  if (!S)
    return false;
  if (const auto *UO = dyn_cast<UnaryOperator>(S))
    if (UO->getOpcode() == UO_LNot)
      return true;
  if (const auto *BO = dyn_cast<BinaryOperator>(S))
    if (BO->isEqualityOp())
      for (const Expr *Op : {BO->getLHS(), BO->getRHS()})
        if (Op->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNotNull))
          return true;
  for (const Stmt *C : S->children())
    if (hasNullCheck(C, Ctx))
      return true;
  return false;
}

// FD's body tests its parameter I for NULL in an `if` condition
// (`if (!p) out_of_memory();`).
bool nullChecksParam(const FunctionDecl *FD, unsigned I, ASTContext &Ctx) {
  const FunctionDecl *Def = nullptr;
  if (!FD || !FD->hasBody(Def) || !Def || I >= Def->getNumParams())
    return false;
  const ParmVarDecl *P = Def->getParamDecl(I);
  bool Found = false;
  std::function<void(const Stmt *)> Walk = [&](const Stmt *S) {
    if (!S || Found)
      return;
    if (const auto *If = dyn_cast<IfStmt>(S))
      if (hasNullCheck(If->getCond(), Ctx) &&
          raptor_mem::findKey(If->getCond(), raptor_mem::KeySet{P->getNameAsString()}))
        Found = true;
    for (const Stmt *C : S->children())
      Walk(C);
  };
  Walk(Def->getBody());
  return Found;
}

// Call passes Key (or the expression Arg) to a null-checking helper.
bool helperChecks(const CallExpr *Call, const std::string &Key, const Expr *Arg,
                  ASTContext &Ctx) {
  const FunctionDecl *FD = Call->getDirectCallee();
  if (!FD)
    return false;
  for (unsigned I = 0; I < Call->getNumArgs(); ++I) {
    const Expr *A = Call->getArg(I)->IgnoreParenCasts();
    bool Match = (Arg && A == Arg->IgnoreParenCasts()) ||
                 (!Key.empty() && raptor_mem::keyOf(A) == Key);
    if (Match && nullChecksParam(FD, I, Ctx))
      return true;
  }
  return false;
}

// Is there an `if` whose condition mentions Key in a block reachable from
// B (B's own terminator included, as it follows B's elements)?
bool checkedLater(const CFGBlock *B, const std::string &Key, ASTContext &Ctx) {
  raptor_mem::KeySet Keys{Key};
  llvm::SmallPtrSet<const CFGBlock *, 32> Seen;
  llvm::SmallVector<const CFGBlock *, 32> Work{B};
  while (!Work.empty()) {
    const CFGBlock *X = Work.pop_back_val();
    if (!X || !Seen.insert(X).second)
      continue;
    if (const auto *If = dyn_cast_or_null<IfStmt>(X->getTerminatorStmt()))
      if (raptor_mem::findKey(If->getCond(), Keys))
        return true;
    for (const CFGElement &E : *X)
      if (auto CS = E.getAs<CFGStmt>())
        if (const auto *Call = dyn_cast<CallExpr>(CS->getStmt());
            Call && helperChecks(Call, Key, nullptr, Ctx))
          return true;
    for (const CFGBlock *S : X->succs())
      Work.push_back(S);
  }
  return false;
}

class UncheckedRetMallocChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const CFG *G = Mgr.getCFG(D);
    if (!G)
      return;
    AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(D);
    ParentMap &PM = ADC->getParentMap();
    ASTContext &Ctx = Mgr.getASTContext();
    for (const CFGBlock *B : *G)
      for (const CFGElement &E : *B) {
        auto CS = E.getAs<CFGStmt>();
        if (!CS)
          continue;
        const Stmt *S = CS->getStmt();
        std::string Key;
        const Stmt *Full = S; // the enclosing full expression
        if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
          if (BO->getOpcode() != BO_Assign || !isAllocCall(BO->getRHS()))
            continue;
          Key = raptor_mem::keyOf(BO->getLHS());
          bool ByHelper = false;
          while (const Stmt *P = PM.getParent(Full)) {
            if (!isa<Expr>(P))
              break;
            if (const auto *Call = dyn_cast<CallExpr>(P);
                Call && helperChecks(Call, "", cast<Expr>(Full), Ctx))
              ByHelper = true;
            Full = P;
          }
          if (ByHelper)
            continue;
        } else if (const auto *DS = dyn_cast<DeclStmt>(S)) {
          const auto *VD = DS->isSingleDecl()
                               ? dyn_cast<VarDecl>(DS->getSingleDecl())
                               : nullptr;
          if (!VD || !isAllocCall(VD->getInit()))
            continue;
          Key = VD->getNameAsString();
          Full = VD->getInit();
        } else {
          continue;
        }
        if (Key.empty() || hasNullCheck(Full, Ctx) || checkedLater(B, Key, Ctx))
          continue;
        raptor::reportAt(BR, this, "Unchecked return value of allocation",
                         "The software does not check the return value from "
                         "a memory allocation function",
                         S, ADC);
      }
  }
};
} // namespace

RAPTOR_CHECKER(UncheckedRetMallocChecker, "UncheckedRetMalloc",
               "Return value of malloc() and friends not checked")
