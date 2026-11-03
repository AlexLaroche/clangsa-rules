// raptor.IgnoredStatusReturn: a call whose result is discarded, to a function
// defined in the same translation unit that reports success or failure
// through its return value (CWE-252, leading to CWE-787 and friends).
//
// A function is a status function when it returns an integer, bool or enum
// and every `return` yields either a constant or the result of another
// status function, with at least two distinct constants or one forwarded
// status. `return BROTLI_TRUE;` / `return BROTLI_FALSE;` qualifies;
// `return 0;` alone, or `return a + b;`, does not.
//
// A result is discarded when the call is an expression statement (in a
// block, as an if/loop body, after a label) or the left operand of a comma
// whose value is itself discarded. `(void)f();` is an explicit opt-out.
//
// This is the CVE-2026-111497 ("Broccoli2Shell") pattern in google/brotli
// <= 1.0.9, c/dec/decode.c:
//   static void DecodeLiteralBlockSwitch(BrotliDecoderState* s) {
//     DecodeLiteralBlockSwitchInternal(0, s);   // BROTLI_FALSE dropped
//   }
#include "Common.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallSet.h"

using namespace clang;
using namespace ento;

namespace {
enum class Status { InProgress, Yes, No };
using StatusCache = llvm::DenseMap<const FunctionDecl *, Status>;

void collectReturns(const Stmt *S, llvm::SmallVectorImpl<const ReturnStmt *> &Out) {
  if (!S || isa<LambdaExpr>(S) || isa<BlockExpr>(S))
    return;
  if (const auto *R = dyn_cast<ReturnStmt>(S))
    Out.push_back(R);
  for (const Stmt *C : S->children())
    collectReturns(C, Out);
}

bool isStatusFunction(const FunctionDecl *FD, ASTContext &Ctx, StatusCache &Cache);

// The function directly called by E, if E is (after parens/casts) a call.
const FunctionDecl *calledFunction(const Expr *E) {
  const auto *CE = dyn_cast_or_null<CallExpr>(raptor::strip(E));
  return CE ? CE->getDirectCallee() : nullptr;
}

bool isStatusFunction(const FunctionDecl *FD, ASTContext &Ctx, StatusCache &Cache) {
  const FunctionDecl *Def = nullptr;
  if (!FD || !FD->hasBody(Def) || !Def)
    return false;
  if (!Def->getReturnType()->isIntegralOrEnumerationType())
    return false;
  auto [It, Inserted] = Cache.try_emplace(Def, Status::InProgress);
  if (!Inserted)
    return It->second == Status::Yes; // InProgress (recursion) counts as no

  llvm::SmallVector<const ReturnStmt *, 8> Returns;
  collectReturns(Def->getBody(), Returns);
  llvm::SmallSet<int64_t, 4> Constants;
  bool Forwards = false, Ok = !Returns.empty();
  for (const ReturnStmt *R : Returns) {
    const Expr *V = R->getRetValue();
    if (!V) {
      Ok = false;
      break;
    }
    Expr::EvalResult ER;
    if (!V->isValueDependent() && V->EvaluateAsInt(ER, Ctx)) {
      Constants.insert(ER.Val.getInt().getExtValue());
      continue;
    }
    if (isStatusFunction(calledFunction(V), Ctx, Cache)) {
      Forwards = true;
      continue;
    }
    Ok = false;
    break;
  }
  bool Result = Ok && (Constants.size() >= 2 || Forwards);
  Cache[Def] = Result ? Status::Yes : Status::No;
  return Result;
}

// Is the value of E thrown away by its context?
bool isDiscarded(const Expr *E, ParentMap &PM) {
  const Stmt *Child = E;
  const Stmt *P = PM.getParent(Child);
  while (P && (isa<ParenExpr>(P) || isa<ExprWithCleanups>(P))) {
    Child = P;
    P = PM.getParent(P);
  }
  if (!P)
    return false;
  if (isa<CompoundStmt>(P) || isa<LabelStmt>(P) || isa<SwitchCase>(P) ||
      isa<AttributedStmt>(P))
    return true;
  if (const auto *If = dyn_cast<IfStmt>(P))
    return Child == If->getThen() || Child == If->getElse();
  if (const auto *W = dyn_cast<WhileStmt>(P))
    return Child == W->getBody();
  if (const auto *D = dyn_cast<DoStmt>(P))
    return Child == D->getBody();
  if (const auto *F = dyn_cast<ForStmt>(P))
    return Child == F->getBody() || Child == F->getInit() || Child == F->getInc();
  if (const auto *BO = dyn_cast<BinaryOperator>(P))
    if (BO->getOpcode() == BO_Comma)
      return Child == BO->getLHS() || isDiscarded(BO, PM);
  return false;
}

void findCalls(const Stmt *S, llvm::SmallVectorImpl<const CallExpr *> &Out) {
  if (!S)
    return;
  if (const auto *CE = dyn_cast<CallExpr>(S))
    Out.push_back(CE);
  for (const Stmt *C : S->children())
    findCalls(C, Out);
}

class IgnoredStatusReturnChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    if (!D->getBody())
      return;
    AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(D);
    ParentMap &PM = ADC->getParentMap();
    ASTContext &Ctx = Mgr.getASTContext();
    StatusCache Cache;
    llvm::SmallVector<const CallExpr *, 32> Calls;
    findCalls(D->getBody(), Calls);
    for (const CallExpr *CE : Calls) {
      const FunctionDecl *FD = CE->getDirectCallee();
      if (!FD || !isDiscarded(CE, PM) || !isStatusFunction(FD, Ctx, Cache))
        continue;
      raptor::reportAt(
          BR, this, "Ignored status return value",
          ("The return value of '" + FD->getNameAsString() +
           "', which signals success or failure, is ignored; on failure "
           "execution continues with inconsistent state"),
          CE, ADC);
    }
  }
};
} // namespace

RAPTOR_CHECKER(IgnoredStatusReturnChecker, "IgnoredStatusReturn",
               "Result of a success/failure status function is discarded")
