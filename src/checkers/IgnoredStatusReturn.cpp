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
// A function is also treated as a status function when it returns an integer,
// enum, bool or pointer and its result is checked at most of its other call
// sites in the file, and at least one: used as a condition, compared,
// negated, returned, or stored in a variable that some condition of the
// caller tests. Discarding it at one call site is then a deviation
// (`ret = create_merkle_leaf_value(...); if (ret != 0)` elsewhere,
// `if ((ptr = rr_decode(...)) == NULL)` elsewhere).
//
// Either way, the file must check the result at least once and at least as
// often as it discards it: a status that is discarded at most call sites
// (debug printers, consume-after-peek helpers) is not reported. Except when
// the call is what initialises the caller's buffer: a status function given
// a local of the caller that has no initialiser and is not used before the
// call (`BYTE mac[32]; core(data, len, mac); ... mac[i] ^ expect[i]`), where
// ignoring a failure reads uninitialised memory (CWE-457) even if no other
// call site exists (microsoft/SymCrypt SymCryptTlsCbcHmacVerify).
//
// Not reported: calls that cannot fail, because the callee only ever returns
// one value, or its failure values sit under `if`s that the call's constant
// arguments rule out (`if (cbKey != 32) err = WRONG_KEY_SIZE;` called with a
// 32-byte test key in a self-test); teardown functions (close, cleanup, destroy, free, final,
// exit, shutdown...), and cleanup on a path that is already failing, where
// the next statement is a break, a goto, or a return of a variable or a
// negative constant
// (`exit_zlib(...); break;`, `machine(ERROR); return result;`).
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
// and of CVE-2025-49600 (Mbed TLS < 3.6.4, mbedtls_lms_verify ignoring
// create_merkle_leaf_value) and CVE-2020-6072 (libmicrodns 0.1.0, recursive
// rr_decode ignoring a NULL result).
#include "Common.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallSet.h"
#include <functional>
#include <optional>

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

// `return err;` where err is a local of Def that only ever holds constants
// or results of status functions (`int err = OK; ... err = TOO_SMALL; goto
// out; ... out: return err;`): adds those constants to Constants.
const VarDecl *statusVariable(const Expr *V, const FunctionDecl *Def, ASTContext &Ctx,
                              StatusCache &Cache, llvm::SmallSet<int64_t, 4> &Constants) {
  const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(V));
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  if (!VD || !VD->hasLocalStorage() || isa<ParmVarDecl>(VD) ||
      !VD->getType()->isIntegralOrEnumerationType())
    return nullptr;
  llvm::SmallVector<const Expr *, 8> Values;
  if (VD->getInit())
    Values.push_back(VD->getInit());
  bool Ok = true;
  std::function<void(const Stmt *)> Walk = [&](const Stmt *S) {
    if (!S || !Ok)
      return;
    if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      const auto *L = dyn_cast<DeclRefExpr>(raptor::strip(BO->getLHS()));
      if (L && L->getDecl() == VD && BO->isAssignmentOp()) {
        if (BO->getOpcode() != BO_Assign) {
          Ok = false; // err |= ..., err += ...: not a status
          return;
        }
        Values.push_back(BO->getRHS());
      }
    }
    if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
      const auto *Sub = dyn_cast<DeclRefExpr>(raptor::strip(UO->getSubExpr()));
      if (Sub && Sub->getDecl() == VD && (UO->isIncrementDecrementOp() || UO->getOpcode() == UO_AddrOf)) {
        Ok = false;
        return;
      }
    }
    for (const Stmt *C : S->children())
      Walk(C);
  };
  Walk(Def->getBody());
  if (!Ok || Values.empty())
    return nullptr;
  for (const Expr *E : Values) {
    Expr::EvalResult ER;
    if (!E->isValueDependent() && E->EvaluateAsInt(ER, Ctx))
      Constants.insert(ER.Val.getInt().getExtValue());
    else if (!isStatusFunction(calledFunction(E), Ctx, Cache))
      return nullptr;
  }
  return VD;
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
    if (statusVariable(V, Def, Ctx, Cache, Constants))
      continue;
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

// Is the value of the call E checked by its context?
bool isChecked(const Expr *E, ParentMap &PM, const llvm::SmallPtrSetImpl<const VarDecl *> &CondVars) {
  const Stmt *Child = E;
  for (const Stmt *P = PM.getParent(Child); P; Child = P, P = PM.getParent(P)) {
    if (isa<ParenExpr>(P) || isa<ImplicitCastExpr>(P) || isa<ExprWithCleanups>(P))
      continue;
    if (isa<ReturnStmt>(P))
      return true;
    if (const auto *UO = dyn_cast<UnaryOperator>(P))
      return UO->getOpcode() == UO_LNot;
    if (const auto *CO = dyn_cast<ConditionalOperator>(P))
      return Child == CO->getCond();
    if (const auto *If = dyn_cast<IfStmt>(P))
      return Child == If->getCond();
    if (const auto *W = dyn_cast<WhileStmt>(P))
      return Child == W->getCond();
    if (const auto *D = dyn_cast<DoStmt>(P))
      return Child == D->getCond();
    if (const auto *F = dyn_cast<ForStmt>(P))
      return Child == F->getCond();
    if (const auto *Sw = dyn_cast<SwitchStmt>(P))
      return Child == Sw->getCond();
    if (const auto *DS = dyn_cast<DeclStmt>(P)) {
      for (const Decl *Dc : DS->decls())
        if (const auto *VD = dyn_cast<VarDecl>(Dc))
          if (VD->getInit() && raptor::strip(VD->getInit()) == raptor::strip(E))
            return CondVars.count(VD) > 0;
      return false;
    }
    if (const auto *BO = dyn_cast<BinaryOperator>(P)) {
      if (BO->isComparisonOp() || BO->isLogicalOp())
        return true;
      if (BO->getOpcode() == BO_Assign && Child == BO->getRHS()) {
        if (isChecked(BO, PM, CondVars))
          return true;
        const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(BO->getLHS()));
        const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
        return VD && CondVars.count(VD);
      }
      return false;
    }
    return false;
  }
  return false;
}

// Variables read by a condition or a comparison in Body.
void conditionVars(const Stmt *Body, llvm::SmallPtrSetImpl<const VarDecl *> &Out) {
  std::function<void(const Stmt *, bool)> Walk = [&](const Stmt *S, bool InCond) {
    if (!S)
      return;
    if (InCond)
      if (const auto *DRE = dyn_cast<DeclRefExpr>(S))
        if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
          Out.insert(VD);
    const Stmt *Cond = nullptr;
    if (const auto *If = dyn_cast<IfStmt>(S))
      Cond = If->getCond();
    else if (const auto *W = dyn_cast<WhileStmt>(S))
      Cond = W->getCond();
    else if (const auto *D = dyn_cast<DoStmt>(S))
      Cond = D->getCond();
    else if (const auto *F = dyn_cast<ForStmt>(S))
      Cond = F->getCond();
    else if (const auto *Sw = dyn_cast<SwitchStmt>(S))
      Cond = Sw->getCond();
    else if (const auto *CO = dyn_cast<ConditionalOperator>(S))
      Cond = CO->getCond();
    bool Here = InCond;
    if (const auto *BO = dyn_cast<BinaryOperator>(S))
      Here |= BO->isComparisonOp() || BO->isLogicalOp();
    if (const auto *UO = dyn_cast<UnaryOperator>(S))
      Here |= UO->getOpcode() == UO_LNot;
    for (const Stmt *C : S->children())
      Walk(C, Here || C == Cond);
  };
  Walk(Body, false);
}

// Is the discarded call E cleanup on a path that is already failing: the
// next statement of its block is a break, a goto, or a return of a variable
// or a negative constant (`exit_zlib(...); break;`, `f(ERROR); return result;`)?
bool onErrorPath(const Expr *E, ParentMap &PM, ASTContext &Ctx) {
  const Stmt *Child = E;
  const Stmt *P = PM.getParent(Child);
  while (P && (isa<ParenExpr>(P) || isa<ExprWithCleanups>(P))) {
    Child = P;
    P = PM.getParent(P);
  }
  const auto *CS = dyn_cast_or_null<CompoundStmt>(P);
  if (!CS)
    return false;
  bool Next = false;
  for (const Stmt *S : CS->body()) {
    if (Next) {
      if (isa<BreakStmt>(S) || isa<GotoStmt>(S))
        return true;
      if (const auto *R = dyn_cast<ReturnStmt>(S)) {
        // `return result;` or `return -1;`: propagating a failure.
        const Expr *V = R->getRetValue() ? raptor::strip(R->getRetValue()) : nullptr;
        if (!V || V->isValueDependent())
          return false;
        if (isa<DeclRefExpr>(V))
          return true;
        Expr::EvalResult ER;
        return V->EvaluateAsInt(ER, Ctx) && ER.Val.getInt().isNegative();
      }
      return false;
    }
    Next = S == Child;
  }
  return false;
}

// Teardown functions, whose status the caller cannot act on.
bool isTeardown(StringRef Name) {
  std::string L = Name.lower();
  for (const char *W : {"close", "cleanup", "destroy", "free", "final", "exit", "shutdown", "done",
                        "release", "dispose", "teardown"})
    if (L.find(W) != std::string::npos)
      return true;
  return false;
}

class FunctionCollector : public RecursiveASTVisitor<FunctionCollector> {
public:
  std::vector<const FunctionDecl *> Defs;
  bool VisitFunctionDecl(FunctionDecl *FD) {
    if (FD->doesThisDeclarationHaveABody() && !FD->isDependentContext())
      Defs.push_back(FD);
    return true;
  }
};

// Value of E inside Def when called by CE: constants, Def's parameters bound
// to constant arguments of CE, and arithmetic/comparisons of those.
std::optional<int64_t> evalAt(const Expr *E, const CallExpr *CE, const FunctionDecl *Def,
                              ASTContext &Ctx) {
  E = E->IgnoreParenCasts();
  Expr::EvalResult ER;
  if (!E->isValueDependent() && E->EvaluateAsInt(ER, Ctx))
    return ER.Val.getInt().getExtValue();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    const auto *P = dyn_cast<ParmVarDecl>(DRE->getDecl());
    if (!P || P->getDeclContext() != Def)
      return std::nullopt;
    unsigned I = P->getFunctionScopeIndex();
    const Expr *A = I < CE->getNumArgs() ? CE->getArg(I) : nullptr;
    if (A && !A->isValueDependent() && A->EvaluateAsInt(ER, Ctx))
      return ER.Val.getInt().getExtValue();
    return std::nullopt;
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    auto V = evalAt(UO->getSubExpr(), CE, Def, Ctx);
    if (!V)
      return std::nullopt;
    switch (UO->getOpcode()) {
    case UO_LNot: return !*V;
    case UO_Minus: return -*V;
    case UO_Not: return ~*V;
    default: return std::nullopt;
    }
  }
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO)
    return std::nullopt;
  auto L = evalAt(BO->getLHS(), CE, Def, Ctx);
  if (BO->getOpcode() == BO_LAnd && L && !*L)
    return 0;
  if (BO->getOpcode() == BO_LOr && L && *L)
    return 1;
  auto R = evalAt(BO->getRHS(), CE, Def, Ctx);
  if (!L || !R)
    return std::nullopt;
  bool U = BO->getLHS()->getType()->isUnsignedIntegerOrEnumerationType() ||
           BO->getRHS()->getType()->isUnsignedIntegerOrEnumerationType();
  uint64_t UL = *L, UR = *R;
  switch (BO->getOpcode()) {
  case BO_EQ: return *L == *R;
  case BO_NE: return *L != *R;
  case BO_LT: return U ? UL < UR : *L < *R;
  case BO_GT: return U ? UL > UR : *L > *R;
  case BO_LE: return U ? UL <= UR : *L <= *R;
  case BO_GE: return U ? UL >= UR : *L >= *R;
  case BO_LAnd: return *L && *R;
  case BO_LOr: return *L || *R;
  case BO_Add: return *L + *R;
  case BO_Sub: return *L - *R;
  case BO_Mul: return *L * *R;
  case BO_And: return *L & *R;
  case BO_Or: return *L | *R;
  case BO_Xor: return *L ^ *R;
  default: return std::nullopt;
  }
}

// Can the call CE to Def return more than one status value? Collects the
// values Def can return (constants returned directly or held by a returned
// status variable); a value under an `if` whose condition, with CE's constant
// arguments, sends control the other way is not reachable from this call.
// `return OK;` everywhere (SymCryptKmac128ExpandKeyEx), or `if (cbKey != 32)
// err = WRONG_KEY_SIZE;` called with a 32-byte key, cannot fail.
bool canFailAt(const CallExpr *CE, const FunctionDecl *Def, ASTContext &Ctx) {
  llvm::SmallVector<const ReturnStmt *, 8> Returns;
  collectReturns(Def->getBody(), Returns);
  llvm::SmallVector<const Stmt *, 16> Points; // expression, or VarDecl init
  for (const ReturnStmt *R : Returns) {
    const Expr *V = R->getRetValue();
    if (!V)
      return true;
    const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(V));
    const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
    if (!VD || !VD->hasLocalStorage() || isa<ParmVarDecl>(VD)) {
      Points.push_back(V);
      continue;
    }
    if (VD->getInit())
      Points.push_back(VD->getInit());
    std::function<void(const Stmt *)> Walk = [&](const Stmt *S) {
      if (!S)
        return;
      if (const auto *BO = dyn_cast<BinaryOperator>(S))
        if (const auto *L = dyn_cast<DeclRefExpr>(raptor::strip(BO->getLHS())))
          if (L->getDecl() == VD && BO->isAssignmentOp())
            Points.push_back(BO);
      for (const Stmt *C : S->children())
        Walk(C);
    };
    Walk(Def->getBody());
  }
  ParentMap PM(Def->getBody());
  llvm::SmallSet<int64_t, 4> Values;
  for (const Stmt *P : Points) {
    const Expr *V = nullptr;
    if (const auto *BO = dyn_cast<BinaryOperator>(P)) {
      if (BO->getOpcode() != BO_Assign)
        return true;
      V = BO->getRHS();
    } else {
      V = cast<Expr>(P);
    }
    // Unreachable from this call?
    bool Dead = false;
    const Stmt *Child = P;
    for (const Stmt *Up = PM.getParent(Child); Up && !Dead; Child = Up, Up = PM.getParent(Up))
      if (const auto *If = dyn_cast<IfStmt>(Up))
        if (Child == If->getThen() || Child == If->getElse())
          if (auto C = evalAt(If->getCond(), CE, Def, Ctx))
            Dead = (Child == If->getThen()) != (*C != 0);
    if (Dead)
      continue;
    Expr::EvalResult ER;
    if (V->isValueDependent() || !V->EvaluateAsInt(ER, Ctx))
      return true;
    Values.insert(ER.Val.getInt().getExtValue());
  }
  return Values.size() > 1;
}

struct Site {
  const CallExpr *CE;
  const FunctionDecl *In;
  bool Discarded, Checked, Excused;
  const VarDecl *UninitOut; // caller's uninitialised local the callee fills
};

// A local of the caller, without initialiser and not mentioned before the
// call, passed to it as `buf` (array) or `&x`: the call is what initialises
// it, so ignoring its failure leaves the caller reading uninitialised memory.
const VarDecl *uninitOutArg(const CallExpr *CE, const FunctionDecl *Caller, const SourceManager &SM) {
  for (const Expr *A : CE->arguments()) {
    const Expr *E = A->IgnoreParenImpCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(E))
      E = UO->getOpcode() == UO_AddrOf ? UO->getSubExpr()->IgnoreParenImpCasts() : nullptr;
    else if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
      E = DRE->getType()->isArrayType() ? E : nullptr;
    else
      E = nullptr;
    const auto *DRE = dyn_cast_or_null<DeclRefExpr>(E);
    const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
    if (!VD || !VD->hasLocalStorage() || isa<ParmVarDecl>(VD) || VD->hasInit())
      continue;
    bool UsedBefore = false;
    std::function<void(const Stmt *)> Walk = [&](const Stmt *S) {
      if (!S || UsedBefore)
        return;
      if (const auto *R = dyn_cast<DeclRefExpr>(S))
        if (R->getDecl() == VD && R != DRE &&
            SM.isBeforeInTranslationUnit(R->getBeginLoc(), CE->getBeginLoc()))
          UsedBefore = true;
      for (const Stmt *C : S->children())
        Walk(C);
    };
    Walk(Caller->getBody());
    if (!UsedBefore)
      return VD;
  }
  return nullptr;
}

class IgnoredStatusReturnChecker : public Checker<check::EndOfTranslationUnit> {
public:
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                                 BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();
    FunctionCollector Col;
    Col.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));

    // Every call to a function defined in this file, by callee.
    llvm::DenseMap<const FunctionDecl *, std::vector<Site>> Sites;
    for (const FunctionDecl *FD : Col.Defs) {
      AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(FD);
      ParentMap &PM = ADC->getParentMap();
      llvm::SmallPtrSet<const VarDecl *, 16> CondVars;
      conditionVars(FD->getBody(), CondVars);
      llvm::SmallVector<const CallExpr *, 32> Calls;
      findCalls(FD->getBody(), Calls);
      for (const CallExpr *CE : Calls) {
        const FunctionDecl *Callee = CE->getDirectCallee();
        const FunctionDecl *Def = nullptr;
        if (!Callee || !Callee->hasBody(Def) || !Def)
          continue;
        QualType RT = Def->getReturnType();
        if (!RT->isIntegralOrEnumerationType() && !RT->isPointerType())
          continue;
        if (isTeardown(Def->getName()))
          continue;
        bool Disc = isDiscarded(CE, PM);
        Sites[Def->getCanonicalDecl()].push_back(
            {CE, FD, Disc, isChecked(CE, PM, CondVars), Disc && onErrorPath(CE, PM, Ctx),
             Disc ? uninitOutArg(CE, FD, SM) : nullptr});
      }
    }

    StatusCache Cache;
    for (auto &[Callee, List] : Sites) {
      unsigned Checked = 0, Discarded = 0;
      for (const Site &S : List) {
        Checked += S.Checked;
        Discarded += S.Discarded && !S.Excused;
      }
      // Where the file discards a result more often than it checks it
      // (debug printers, consume-after-peek helpers), discarding is the
      // norm: nothing to report, unless the call is what initialises the
      // caller's buffer (below).
      bool Norm = Checked == 0 || Checked < Discarded;
      const FunctionDecl *Def = nullptr;
      Callee->hasBody(Def);
      bool Status = isStatusFunction(Def, Ctx, Cache);
      for (const Site &S : List) {
        if (!S.Discarded || S.Excused || !SM.isInMainFile(SM.getExpansionLoc(S.CE->getBeginLoc())))
          continue;
        // Checked at most of the other call sites, and at least one.
        unsigned Others = List.size() - 1;
        bool Deviant = 2 * Checked >= Others;
        bool Uninit = Status && S.UninitOut;
        if (!Uninit && (Norm || (!Status && !Deviant)))
          continue;
        if (!canFailAt(S.CE, Def, Ctx))
          continue;
        std::string Why =
            Uninit ? "which signals success or failure and is the only initialisation of '" +
                         S.UninitOut->getNameAsString() + "'"
            : Status ? "which signals success or failure"
                     : "which its other callers check (" + std::to_string(Checked) + " of " +
                           std::to_string(Others) + " call sites)";
        raptor::reportAt(BR, this, "Ignored status return value",
                         "The return value of '" + Def->getNameAsString() + "', " + Why +
                             ", is ignored; on failure execution continues with "
                             "inconsistent state",
                         S.CE, Mgr.getAnalysisDeclContext(S.In));
      }
    }
  }
};
} // namespace

RAPTOR_CHECKER(IgnoredStatusReturnChecker, "IgnoredStatusReturn",
               "Result of a success/failure status function is discarded")
