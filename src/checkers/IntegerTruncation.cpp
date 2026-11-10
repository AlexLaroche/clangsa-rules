// raptor.IntegerTruncation: an integer is assigned (or returned) to
// a narrower integer type, or to a signed type of the same width as its
// unsigned source (e.g. `short s = i;`, `int i = l + 1;`, `char f() { return
// i; }`). The semgrep rule lists the (destination, source) type pairs
// char/short/int/long <- wider or same-width-unsigned types; here the widths
// come from the real types.
//
// Not reported: values that provably fit (`x & 0x3f`, `n % 16`, `v >> 56`,
// constant-time masks `(UINT32)(((UINT64)a - b) >> 32)`), and a wide value
// deliberately split into limbs or bytes, i.e. `(T)x` / `(T)(x >> k)` in a
// function that also shifts x right by a multiple of T's width (multiprecision
// carries, 64-bit halves, big-endian serialisation).
#include "IntegerConversion.h"
#include "Registry.h"
#include <optional>

using namespace clang;
using namespace ento;
using namespace raptor_int;

namespace {
constexpr const char *BugName = "Integer truncation";
constexpr const char *BugMsg =
    "Truncation errors occur when a primitive is cast to a primitive of a "
    "smaller size and data is lost in the conversion";

// Structurally identical expressions (`st->ull[0]` twice).
bool sameExpr(ASTContext &C, const Expr *A, const Expr *B) {
  llvm::FoldingSetNodeID IA, IB;
  A->Profile(IA, C, /*Canonical=*/true);
  B->Profile(IB, C, /*Canonical=*/true);
  return IA == IB;
}

// `(T)x` or `(T)(x >> k)` where the function also shifts x right by a
// multiple of T's width: a wide value deliberately split into limbs or bytes
// (`dst[i] = (UINT32)t; t >>= 32;`, `p[0] = (BYTE)(n >> 8); p[1] = (BYTE)n;`).
bool isDeliberateSplit(ASTContext &C, const Expr *RHS, const Stmt *Body) {
  const auto *Cast = dyn_cast<ExplicitCastExpr>(stripImplicit(RHS));
  if (!Cast || !Cast->getType()->isIntegerType())
    return false;
  unsigned W = C.getIntWidth(Cast->getType());
  const Expr *X = Cast->getSubExpr()->IgnoreParenImpCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(X))
    if (BO->getOpcode() == BO_Shr)
      X = BO->getLHS()->IgnoreParenImpCasts();
  bool Found = false;
  std::function<void(const Stmt *)> Walk = [&](const Stmt *S) {
    if (!S || Found)
      return;
    if (const auto *BO = dyn_cast<BinaryOperator>(S))
      if (BO->getOpcode() == BO_Shr || BO->getOpcode() == BO_ShrAssign) {
        Expr::EvalResult R;
        if (BO->getRHS()->EvaluateAsInt(R, C)) {
          uint64_t K = R.Val.getInt().getZExtValue();
          if (K && K % W == 0 && sameExpr(C, BO->getLHS()->IgnoreParenImpCasts(), X))
            Found = true;
        }
      }
    for (const Stmt *Ch : S->children())
      Walk(Ch);
  };
  Walk(Body);
  return Found;
}

bool truncates(ASTContext &C, QualType Dest, QualType Src) {
  if (Src.isNull() || !isPlainInt(Dest) || !isPlainInt(Src))
    return false;
  unsigned WD = C.getIntWidth(Dest), WS = C.getIntWidth(Src);
  return WS > WD || (WS == WD && Src->isUnsignedIntegerType() &&
                     Dest->isSignedIntegerType());
}

class IntegerTruncationChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &C = Mgr.getASTContext();
    AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(D);

    // (DEST $_) = <... (SRC $_) ...>, minus `$_ = 0`
    AssignmentVisitor V;
    auto Lossy = [&](QualType Dest, const Expr *RHS) {
      return truncates(C, Dest, effectiveType(C, RHS, true)) && !fits(C, Dest, RHS, D->getBody()) &&
             !isDeliberateSplit(C, RHS, D->getBody());
    };
    V.OnAssign = [&](QualType Dest, const Expr *RHS, const Stmt *S) {
      if (Lossy(Dest, RHS))
        raptor::reportAt(BR, this, BugName, BugMsg, S, ADC);
    };
    V.OnInit = [&](QualType Dest, const Expr *Init, const VarDecl *,
                   const DeclStmt *DS) {
      if (Lossy(Dest, Init))
        raptor::reportAt(BR, this, BugName, BugMsg, DS, ADC);
    };
    V.TraverseStmt(D->getBody());

    // DEST $FUN(...) { ... return (SRC $_); }
    const auto *FD = dyn_cast<FunctionDecl>(D);
    if (!FD)
      return;
    QualType Ret = FD->getReturnType();
    bool Found = false;
    forEachReturn(D->getBody(), [&](const ReturnStmt *RS) {
      if (RS->getRetValue() &&
          truncates(C, Ret, effectiveType(C, RS->getRetValue(), false)))
        Found = true;
    });
    if (Found)
      reportAtFunctionName(BR, this, BugName, BugMsg, FD);
  }
};
} // namespace

RAPTOR_CHECKER(IntegerTruncationChecker, "IntegerTruncation",
               "Integer value truncated by an assignment or return")
