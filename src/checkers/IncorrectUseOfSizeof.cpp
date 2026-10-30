// Port of raptor-incorrect-use-of-sizeof: sizeof() applied to a pointer
// (which yields the word size, not the size of the pointed-to memory):
//  - sizeof(e) where e has type char *, int *, float * or double *
//    (string literals excluded);
//  - sizeof(p), sizeof(p + x), sizeof(x + p) where p is a variable or
//    parameter declared as a pointer (including array parameters);
//  - sizeof(this) in C++;
//  - sizeof('c') in C, where a character literal is an int (the semgrep rule
//    would like to match it but semgrep cannot).
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {
// (char * $_), (int * $_), (float * $_), (double * $_)
bool hasTypedPointerType(const Expr *E) {
  const auto *PT = E->getType().getCanonicalType()->getAs<PointerType>();
  if (!PT)
    return false;
  QualType P = PT->getPointeeType().getUnqualifiedType();
  return P->isSpecificBuiltinType(BuiltinType::Char_S) ||
         P->isSpecificBuiltinType(BuiltinType::Char_U) ||
         P->isSpecificBuiltinType(BuiltinType::Int) ||
         P->isSpecificBuiltinType(BuiltinType::Float) ||
         P->isSpecificBuiltinType(BuiltinType::Double);
}

// $PTR declared as `$_ * $PTR` (variable or parameter) or `$_ $PTR[]`
// (parameter, adjusted to a pointer by the compiler).
bool isPointerVar(const Expr *E) {
  const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParens());
  if (!DRE || !isa<VarDecl>(DRE->getDecl()))
    return false;
  QualType T = DRE->getDecl()->getType();
  return T->isPointerType() && !T->isFunctionPointerType();
}

class IncorrectUseOfSizeofChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const LangOptions &LO = Mgr.getASTContext().getLangOpts();
    forEach<UnaryExprOrTypeTraitExpr>(
        D->getBody(), [&](const UnaryExprOrTypeTraitExpr *U) {
          if (U->getKind() != UETT_SizeOf || U->isArgumentType())
            return;
          const Expr *Arg = U->getArgumentExpr()->IgnoreParens();
          if (Arg->isTypeDependent())
            return;
          bool Bad = false;
          if (hasTypedPointerType(Arg) && !isa<StringLiteral>(Arg))
            Bad = true;
          else if (isPointerVar(Arg))
            Bad = true;
          else if (const auto *BO = dyn_cast<BinaryOperator>(Arg))
            Bad = BO->getOpcode() == BO_Add &&
                  (isPointerVar(BO->getLHS()->IgnoreImpCasts()) ||
                   isPointerVar(BO->getRHS()->IgnoreImpCasts()));
          else if (isa<CXXThisExpr>(Arg))
            Bad = true;
          else if (isa<CharacterLiteral>(Arg) && !LO.CPlusPlus)
            Bad = true;
          if (Bad)
            raptor::reportAt(
                BR, this, "Incorrect use of sizeof()",
                "The code calls sizeof() on a pointer type, which always "
                "returns the wordsize (8 on 64-bit architectures). This can "
                "produce an unexpected result if the programmer intended to "
                "determine how much memory has been allocated.",
                U, Mgr.getAnalysisDeclContext(D));
        });
  }
};
} // namespace

RAPTOR_CHECKER(IncorrectUseOfSizeofChecker, "IncorrectUseOfSizeof",
               "sizeof() applied to a pointer")
