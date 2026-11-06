// raptor.UnsafeRetSnprintfVsnprintf: the return value of
// snprintf()/vsnprintf() (the length of the string it tried to create) is
// stored while the format can expand to an arbitrarily long string (%s,
// %ls, %S, or a non-literal format), and may be used as a size or offset.
// Not reported: the measuring call `snprintf(NULL, 0, fmt, ...)` whose
// result is used plus at least one (room for the NUL), and a call
// whose size was derived from such a measure of the same format and
// arguments (`n = snprintf(NULL, 0, F, a); buf = malloc(n + 1);
// snprintf(buf, n + 1, F, a)`: nghttp2, nghttp3).
#include "ApiUtil.h"
#include "Common.h"
#include "Registry.h"
#include "RetUtil.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/Support/Regex.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
// Same condition as the semgrep metavariable-regex on $FMT
bool riskyFormat(const Expr *Fmt) {
  if (const auto *SL = dyn_cast<StringLiteral>(raptor::strip(Fmt))) {
    if (!SL->isOrdinary() && !SL->isUTF8())
      return true;
    static llvm::Regex Re("%l?s|%S");
    return Re.match(SL->getString());
  }
  return true; // the format is a variable or other expression
}

bool isMeasure(const CallExpr *CE, ASTContext &Ctx) {
  const Expr *B = CE->getArg(0), *N = CE->getArg(1);
  if (!B->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNotNull))
    return false;
  Expr::EvalResult R;
  return N->EvaluateAsInt(R, Ctx) && R.Val.getInt() == 0;
}

std::string squeezed(const Expr *E, ASTContext &Ctx) {
  std::string T;
  for (char Ch : raptor::api::textAsWritten(E, Ctx))
    if (!isspace(static_cast<unsigned char>(Ch)))
      T += Ch;
  return T;
}

// The format and arguments of a printf-like call, as written.
std::string formatAndArgs(const CallExpr *CE, ASTContext &Ctx) {
  std::string T;
  for (unsigned I = 2; I < CE->getNumArgs(); ++I)
    T += squeezed(CE->getArg(I), Ctx) + ",";
  return T;
}

// Values given to the local V in Body (its initializer and assignments).
void valuesOf(const VarDecl *V, const Stmt *Body,
              llvm::SmallVectorImpl<const Expr *> &Out) {
  if (V->getInit())
    Out.push_back(V->getInit());
  for (const BoundNodes &N :
       match(findAll(binaryOperator(isAssignmentOperator()).bind("a")), *Body,
             V->getASTContext())) {
    const auto *A = N.getNodeAs<BinaryOperator>("a");
    if (const auto *R = dyn_cast<DeclRefExpr>(A->getLHS()->IgnoreParenImpCasts());
        R && R->getDecl() == V)
      Out.push_back(A->getRHS());
  }
}

// Was CE's size computed from the result of a measuring call with the same
// format and arguments (through at most one local holding the size)?
bool sizedByMeasure(const CallExpr *CE, const Stmt *Body, ASTContext &Ctx) {
  std::string Want = formatAndArgs(CE, Ctx);
  llvm::SmallVector<const Expr *, 8> Sizes{CE->getArg(1)};
  if (const auto *R = dyn_cast<DeclRefExpr>(CE->getArg(1)->IgnoreParenImpCasts()))
    if (const auto *V = dyn_cast<VarDecl>(R->getDecl()); V && V->hasLocalStorage())
      valuesOf(V, Body, Sizes);
  for (const Expr *S : Sizes)
    for (const BoundNodes &N : match(findAll(declRefExpr().bind("r")), *S, Ctx)) {
      const auto *V = dyn_cast<VarDecl>(N.getNodeAs<DeclRefExpr>("r")->getDecl());
      if (!V || !V->hasLocalStorage())
        continue;
      llvm::SmallVector<const Expr *, 4> Vs;
      valuesOf(V, Body, Vs);
      for (const Expr *X : Vs)
        if (const auto *M = dyn_cast<CallExpr>(raptor::strip(X));
            M && M != CE && M->getNumArgs() >= 3 &&
            raptor::isOneOf(raptor::calleeName(M), {"snprintf", "vsnprintf"}) &&
            isMeasure(M, Ctx) && formatAndArgs(M, Ctx) == Want)
          return true;
    }
  return false;
}

// Is the local V used as `V + k` (k >= 1) somewhere in Body?
bool usedPlusOne(const VarDecl *V, const Stmt *Body, ASTContext &Ctx) {
  for (const BoundNodes &N :
       match(findAll(binaryOperator(hasOperatorName("+")).bind("b")), *Body,
             Ctx)) {
    const auto *B = N.getNodeAs<BinaryOperator>("b");
    for (auto [X, K] : {std::pair{B->getLHS(), B->getRHS()},
                        std::pair{B->getRHS(), B->getLHS()}}) {
      const auto *R = dyn_cast<DeclRefExpr>(X->IgnoreParenCasts());
      Expr::EvalResult E;
      if (R && R->getDecl() == V && K->EvaluateAsInt(E, Ctx) &&
          E.Val.getInt().isStrictlyPositive())
        return true;
    }
  }
  return false;
}

// The local receiving the result at Where (`int n = call;` or `n = call`).
const VarDecl *resultVar(const Stmt *Where, const CallExpr *CE,
                         const Stmt *Body, ASTContext &Ctx) {
  if (const auto *BO = dyn_cast<BinaryOperator>(Where))
    if (const auto *R = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts()))
      return dyn_cast<VarDecl>(R->getDecl());
  for (const BoundNodes &N : match(findAll(declStmt().bind("d")), *Body, Ctx))
    for (const Decl *X : N.getNodeAs<DeclStmt>("d")->decls())
      if (const auto *V = dyn_cast<VarDecl>(X);
          V && V->getInit() && raptor::strip(V->getInit()) == CE)
        return V;
  return nullptr;
}

class UnsafeRetSnprintfVsnprintfChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    auto M = callExpr(callee(functionDecl(hasAnyName("snprintf", "vsnprintf"))),
                      argumentCountAtLeast(3))
                 .bind("call");
    for (const BoundNodes &N : match(findAll(M), *D->getBody(), Ctx)) {
      const auto *CE = N.getNodeAs<CallExpr>("call");
      if (!riskyFormat(CE->getArg(2)) || sizedByMeasure(CE, D->getBody(), Ctx))
        continue;
      raptor::RetUse U = raptor::retUse(CE, Ctx, /*ThroughNot=*/false);
      const Stmt *Where = nullptr;
      if (raptor::isInitializer(U))
        Where = CE;
      else if (const auto *BO = llvm::dyn_cast_or_null<BinaryOperator>(U.User))
        if ((BO->getOpcode() == BO_Assign || BO->getOpcode() == BO_AddAssign) &&
            BO->getRHS() == U.Operand)
          Where = BO;
      if (!Where)
        continue;
      if (isMeasure(CE, Ctx))
        if (const VarDecl *V = resultVar(Where, CE, D->getBody(), Ctx);
            V && usedPlusOne(V, D->getBody(), Ctx))
          continue;
      raptor::reportAt(BR, this, "Unsafe use of snprintf() return value",
                       raptor::calleeName(CE).str() +
                           "() returns the length of the string it tried to "
                           "create, which can exceed the buffer size; using "
                           "it as a size or offset may overflow the buffer",
                       Where, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(UnsafeRetSnprintfVsnprintfChecker, "UnsafeRetSnprintfVsnprintf",
               "Unsafe use of the snprintf()/vsnprintf() return value")
