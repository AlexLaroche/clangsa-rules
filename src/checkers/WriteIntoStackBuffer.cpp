// raptor.WriteIntoStackBuffer: a non-static local array passed
// as the destination of a copy/format/read function. Syntactic, like the
// semgrep rule ($BUF must be the array itself, declared with a size).
//
// Not reported: byte-counted copies (mem*, strncpy, strlcpy...) whose length
// cannot exceed the array: a constant or sizeof no larger than it, a
// `MIN(sizeof(buf), len)`, `x & (N-1)` or `x % N` with N no larger, or a
// length checked against such a bound by an enclosing `if` or by an earlier
// `if (len > N) return;` (strncat is still reported: its bound ignores the
// current contents).
#include "Common.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/Support/Regex.h"
#include <functional>
#include <optional>

using namespace clang;
using namespace ento;

namespace {
// Buffer to buffer copy functions (buffer in 1st arg; a string literal
// source is fine).
bool isCopyFn(StringRef N) {
  return raptor::isOneOf(
      N, {"strcpy",   "strncpy",  "stpcpy",   "stpncpy", "strlcpy",
          "strscpy",  "wcscpy",   "wcsncpy",  "wcpcpy",  "wcpncpy",
          "wcslcpy",  "_mbscpy",  "_mbsncpy", "_mbpcpy", "_mbpncpy",
          "_mbslcpy", "strccpy",  "strcadd",  "streadd", "strecpy",
          "strcat",   "strncat",  "strlcat",  "wcscat",  "wcsncat",
          "wcslcat",  "_mbscat",  "_mbsncat", "_mbslcat", "memcpy",
          "memccpy",  "mempcpy",  "memmove",  "memset",  "wmemcpy",
          "wmempcpy", "wmemmove", "wmemset"});
}

// `$_ $BUF[$_];` not `static`: a sized local array with automatic storage.
// A parameter declared as `char buf[16]` is a pointer, not a stack buffer.
bool isStackArray(const Expr *E) {
  const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  if (!VD || isa<ParmVarDecl>(VD) || !VD->hasLocalStorage() ||
      !VD->getTypeSourceInfo())
    return false;
  auto AT = VD->getTypeSourceInfo()->getTypeLoc().getAs<ArrayTypeLoc>();
  return AT && AT.getSizeExpr();
}

// Size in bytes of the stack array E refers to.
uint64_t arrayBytes(const Expr *E, ASTContext &Ctx) {
  const auto *DRE = cast<DeclRefExpr>(E->IgnoreParenImpCasts());
  return Ctx.getTypeSizeInChars(DRE->getDecl()->getType()).getQuantity();
}

bool sameExpr(const Expr *A, const Expr *B, ASTContext &Ctx) {
  llvm::FoldingSetNodeID IA, IB;
  A->IgnoreParenImpCasts()->Profile(IA, Ctx, true);
  B->IgnoreParenImpCasts()->Profile(IB, Ctx, true);
  return IA == IB;
}

// Largest value E can take, when its shape bounds it: a constant (sizeof
// included), `MIN(a, b)` i.e. `a < b ? a : b`, `x & C`, `x % C`.
std::optional<uint64_t> upperBound(const Expr *E, ASTContext &Ctx) {
  E = E->IgnoreParenImpCasts();
  Expr::EvalResult R;
  if (!E->isValueDependent() && E->EvaluateAsInt(R, Ctx))
    return R.Val.getInt().isNegative() ? std::nullopt
                                       : std::optional<uint64_t>(R.Val.getInt().getZExtValue());
  if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
    auto T = upperBound(CO->getTrueExpr(), Ctx), F = upperBound(CO->getFalseExpr(), Ctx);
    if (T && F)
      return std::max(*T, *F);
    // MIN(a, b): the arm chosen when it is the smaller one bounds the result
    if (const auto *Cmp = dyn_cast<BinaryOperator>(CO->getCond()->IgnoreParenImpCasts())) {
      const Expr *L = Cmp->getLHS()->IgnoreParenImpCasts(), *Rh = Cmp->getRHS()->IgnoreParenImpCasts();
      const Expr *TA = CO->getTrueExpr()->IgnoreParenImpCasts(), *FA = CO->getFalseExpr()->IgnoreParenImpCasts();
      bool LtPicksLhs = (Cmp->getOpcode() == BO_LT || Cmp->getOpcode() == BO_LE) &&
                        sameExpr(L, TA, Ctx) && sameExpr(Rh, FA, Ctx);
      bool GtPicksRhs = (Cmp->getOpcode() == BO_GT || Cmp->getOpcode() == BO_GE) &&
                        sameExpr(L, FA, Ctx) && sameExpr(Rh, TA, Ctx);
      if (LtPicksLhs || GtPicksRhs) {
        if (T)
          return T;
        if (F)
          return F;
      }
    }
    return std::nullopt;
  }
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_And) {
      auto L = upperBound(BO->getLHS(), Ctx), Rb = upperBound(BO->getRHS(), Ctx);
      if (L && Rb)
        return std::min(*L, *Rb);
      return L ? L : Rb;
    }
    if (BO->getOpcode() == BO_Rem && BO->getLHS()->getType()->isUnsignedIntegerType())
      if (auto Rb = upperBound(BO->getRHS(), Ctx); Rb && *Rb > 0)
        return *Rb - 1;
  }
  return std::nullopt;
}

// Does Cond being true imply Len <= Max (`len <= C`, `len < C`, `C >= len`,
// `C > len`, or a && with such a side)?
bool impliesAtMost(const Expr *Cond, const Expr *Len, uint64_t Max, ASTContext &Ctx) {
  const auto *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
  if (!BO)
    return false;
  if (BO->getOpcode() == BO_LAnd)
    return impliesAtMost(BO->getLHS(), Len, Max, Ctx) || impliesAtMost(BO->getRHS(), Len, Max, Ctx);
  const Expr *L = BO->getLHS(), *R = BO->getRHS();
  BinaryOperatorKind Op = BO->getOpcode();
  if (!sameExpr(L, Len, Ctx)) {
    if (!sameExpr(R, Len, Ctx))
      return false;
    std::swap(L, R);
    Op = BinaryOperator::reverseComparisonOp(Op);
  }
  auto B = upperBound(R, Ctx);
  if (!B)
    return false;
  if (Op == BO_LE || Op == BO_EQ)
    return *B <= Max;
  if (Op == BO_LT)
    return *B <= Max + 1;
  return false;
}

// Does Cond being false imply Len <= Max (`len > C`, `len >= C`)?
bool negationImpliesAtMost(const Expr *Cond, const Expr *Len, uint64_t Max, ASTContext &Ctx) {
  const auto *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
  if (!BO)
    return false;
  if (BO->getOpcode() == BO_LOr)
    return negationImpliesAtMost(BO->getLHS(), Len, Max, Ctx) ||
           negationImpliesAtMost(BO->getRHS(), Len, Max, Ctx);
  if (!BO->isComparisonOp())
    return false;
  const Expr *L = BO->getLHS(), *R = BO->getRHS();
  BinaryOperatorKind Op = BO->getOpcode();
  if (!sameExpr(L, Len, Ctx)) {
    if (!sameExpr(R, Len, Ctx))
      return false;
    std::swap(L, R);
    Op = BinaryOperator::reverseComparisonOp(Op);
  }
  auto B = upperBound(R, Ctx);
  if (!B)
    return false;
  if (Op == BO_GT)
    return *B <= Max;  // !(len > C)  =>  len <= C
  if (Op == BO_GE || Op == BO_NE)
    return Op == BO_GE ? *B <= Max + 1 : false;
  return false;
}

bool exits(const Stmt *S) {
  if (!S)
    return false;
  if (isa<ReturnStmt>(S) || isa<GotoStmt>(S) || isa<BreakStmt>(S) || isa<ContinueStmt>(S))
    return true;
  if (const auto *CS = dyn_cast<CompoundStmt>(S))
    return !CS->body_empty() && exits(CS->body_back());
  return false;
}

bool isStringLit(const Expr *E) {
  return isa<StringLiteral>(E->IgnoreParenImpCasts());
}

class Visitor : public RecursiveASTVisitor<Visitor> {
public:
  Visitor(BugReporter &BR, const CheckerBase *C, AnalysisDeclContext *ADC)
      : BR(BR), C(C), ADC(ADC) {}

  // Byte-counted copies whose length cannot exceed the destination array:
  // a bounded length, or one checked against a bound by an enclosing `if`
  // or by an earlier `if (len > N) return/goto/break;`.
  bool lengthFits(const CallExpr *CE, StringRef N) const {
    int Idx = raptor::isOneOf(N, {"memcpy", "memmove", "mempcpy", "memset", "strncpy",
                                  "stpncpy", "strlcpy", "strscpy", "strlcat"})
                  ? 2
              : N == "memccpy" ? 3
                               : -1;
    if (Idx < 0 || (unsigned)Idx >= CE->getNumArgs())
      return false;
    ASTContext &Ctx = ADC->getASTContext();
    uint64_t Max = arrayBytes(CE->getArg(0), Ctx);
    const Expr *Len = CE->getArg(Idx);
    if (auto B = upperBound(Len, Ctx))
      return *B <= Max;
    ParentMap &PM = ADC->getParentMap();
    const Stmt *Child = CE;
    for (const Stmt *P = PM.getParent(Child); P; Child = P, P = PM.getParent(P)) {
      if (const auto *If = dyn_cast<IfStmt>(P)) {
        if (Child == If->getThen() && impliesAtMost(If->getCond(), Len, Max, Ctx))
          return true;
        if (Child == If->getElse() && negationImpliesAtMost(If->getCond(), Len, Max, Ctx))
          return true;
      }
      if (const auto *CS = dyn_cast<CompoundStmt>(P))
        for (const Stmt *S : CS->body()) {
          if (S == Child)
            break;
          const auto *If = dyn_cast<IfStmt>(S);
          if (If && !If->getElse() && exits(If->getThen()) &&
              negationImpliesAtMost(If->getCond(), Len, Max, Ctx) && !writesTo(CS, Len, If, Child))
            return true;
        }
    }
    return false;
  }

  bool VisitCallExpr(CallExpr *CE) {
    StringRef N = raptor::calleeName(CE);
    unsigned NA = CE->getNumArgs();
    if (N.empty() || NA == 0)
      return true;
    auto Arg = [&](unsigned I) { return CE->getArg(I); };
    bool Bad = false;
    if (isCopyFn(N))
      Bad = isStackArray(Arg(0)) && !(NA > 1 && isStringLit(Arg(1))) && !lengthFits(CE, N);
    else if (raptor::isOneOf(N, {"sprintf", "vsprintf"}))
      Bad = NA > 1 && isStackArray(Arg(0)) && riskyFormat(Arg(1));
    else if (raptor::isOneOf(N, {"snprintf", "vsnprintf", "swprintf",
                                 "vswprintf"}))
      Bad = NA > 2 && isStackArray(Arg(0)) && riskyFormat(Arg(2));
    else if (raptor::isOneOf(N, {"gets", "fgets", "getwd", "getcwd", "fread"}))
      Bad = isStackArray(Arg(0));
    else if (N == "bcopy")
      Bad = NA > 1 && isStackArray(Arg(1)) && !isStringLit(Arg(0));
    else if (raptor::isOneOf(N, {"read", "pread", "recv", "recvfrom"}))
      Bad = NA > 1 && isStackArray(Arg(1));
    if (Bad)
      raptor::reportAt(BR, C, "Write into stack buffer",
                       "The software directly writes into a stack buffer. "
                       "This might lead to a stack-based buffer overflow",
                       CE, ADC);
    return true;
  }

private:
  // Is the variable Len refers to written between the guard From and To
  // (siblings in CS)? Then the guard no longer bounds it.
  bool writesTo(const CompoundStmt *CS, const Expr *Len, const Stmt *From, const Stmt *To) const {
    const auto *DRE = dyn_cast<DeclRefExpr>(Len->IgnoreParenImpCasts());
    if (!DRE)
      return false; // a field or expression: assume unchanged
    bool In = false, W = false;
    std::function<void(const Stmt *)> Walk = [&](const Stmt *S) {
      if (!S || W)
        return;
      if (const auto *BO = dyn_cast<BinaryOperator>(S))
        if (BO->isAssignmentOp())
          if (const auto *L = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts()))
            W |= L->getDecl() == DRE->getDecl();
      if (const auto *UO = dyn_cast<UnaryOperator>(S))
        if (UO->isIncrementDecrementOp() || UO->getOpcode() == UO_AddrOf)
          if (const auto *L = dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts()))
            W |= L->getDecl() == DRE->getDecl();
      for (const Stmt *C : S->children())
        Walk(C);
    };
    for (const Stmt *S : CS->body()) {
      if (S == To)
        break;
      if (In)
        Walk(S);
      if (S == From)
        In = true;
    }
    return W;
  }

  // metavariable-regex on the source text of $FMT (anchored at the start,
  // like semgrep's re.match).
  bool riskyFormat(const Expr *E) const {
    const SourceManager &SM = BR.getSourceManager();
    CharSourceRange R = CharSourceRange::getTokenRange(
        SM.getExpansionRange(E->getSourceRange()).getAsRange());
    StringRef Text = Lexer::getSourceText(R, SM, ADC->getASTContext().getLangOpts());
    static const llvm::Regex Re(
        "^(\".*%l?s.*\"|\".*%S.*\"|[a-zA-Z_][a-zA-Z0-9_]*)");
    return Re.match(Text);
  }

  BugReporter &BR;
  const CheckerBase *C;
  AnalysisDeclContext *ADC;
};

class WriteIntoStackBufferChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    Visitor(BR, this, Mgr.getAnalysisDeclContext(D))
        .TraverseStmt(D->getBody());
  }
};
} // namespace

RAPTOR_CHECKER(WriteIntoStackBufferChecker, "WriteIntoStackBuffer",
               "Direct write into a stack buffer")
