// raptor.IntegerTruncation: an integer is assigned (or returned) to
// a narrower integer type, or to a signed type of the same width as its
// unsigned source (e.g. `short s = i;`, `int i = l + 1;`, `char f() { return
// i; }`). The semgrep rule lists the (destination, source) type pairs
// char/short/int/long <- wider or same-width-unsigned types; here the widths
// come from the real types.
#include "IntegerConversion.h"
#include "Registry.h"

using namespace clang;
using namespace ento;
using namespace raptor_int;

namespace {
constexpr const char *BugName = "Integer truncation";
constexpr const char *BugMsg =
    "Truncation errors occur when a primitive is cast to a primitive of a "
    "smaller size and data is lost in the conversion";

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
    V.OnAssign = [&](QualType Dest, const Expr *RHS, const Stmt *S) {
      if (truncates(C, Dest, effectiveType(C, RHS, true)))
        raptor::reportAt(BR, this, BugName, BugMsg, S, ADC);
    };
    V.OnInit = [&](QualType Dest, const Expr *Init, const VarDecl *,
                   const DeclStmt *DS) {
      if (truncates(C, Dest, effectiveType(C, Init, true)))
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
