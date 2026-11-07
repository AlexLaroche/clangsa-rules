// raptor.IncorrectUseOfSizeof: sizeof() applied to a pointer
// (which yields the word size, not the size of the pointed-to memory):
//  - sizeof(e) where e has type char *, int *, float * or double *
//    (string literals and elements of arrays, as in sizeof(a) / sizeof(a[0]),
//    excluded);
//  - sizeof(p), sizeof(p + x), sizeof(x + p) where p is a variable or
//    parameter declared as a pointer (including array parameters);
//  - sizeof(this) in C++;
//  - sizeof('c') in C, where a character literal is an int (the semgrep rule
//    would like to match it but semgrep cannot).
// The pointer variable itself as data (sizeof(v) beside &v in an initializer
// list or call, or compared for equality with a received size) is not
// reported either. A sizeof compared with a constant or switched on checks a width, not a memory
// size (kernel READ_ONCE `sizeof(x) == sizeof(long)`, this_cpu_read
// `switch (sizeof(var))`), and is not reported.
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

// a[i] or *a where a is an array or a pointer to pointers: the element size,
// as in the element-count idiom sizeof(a) / sizeof(a[0]) or an allocation
// calloc(n, sizeof(*pp)), even when the elements are pointers.
bool isArrayElement(const Expr *E) {
  const Expr *Base = nullptr;
  if (const auto *AS = dyn_cast<ArraySubscriptExpr>(E))
    Base = AS->getBase();
  else if (const auto *UO = dyn_cast<UnaryOperator>(E))
    if (UO->getOpcode() == UO_Deref)
      Base = UO->getSubExpr();
  if (!Base)
    return false;
  QualType T = Base->IgnoreParenImpCasts()->getType();
  // an array, or a pointer to pointers (`calloc(n, sizeof(*pp))`, OpenSSH
  // `sizeof(*key->cert->principals)`): the element is a pointer on purpose
  return T->isArrayType() ||
         (T->isPointerType() && T->getPointeeType()->isPointerType());
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

// sizeof(...) (through parentheses and implicit casts) is compared with a
// constant or is the condition of a switch.
bool isWidthCheck(const Expr *E, ASTContext &Ctx) {
  const Stmt *Cur = E;
  while (true) {
    auto Parents = Ctx.getParents(*Cur);
    if (Parents.empty())
      return false;
    if (const auto *P = Parents[0].get<Expr>();
        P && (isa<ParenExpr>(P) || isa<ImplicitCastExpr>(P))) {
      Cur = P;
      continue;
    }
    if (const auto *BO = Parents[0].get<BinaryOperator>()) {
      // compared with another constant (sizeof(long), 8), or for equality
      // with a size received for the pointer (`p->data_size ==
      // sizeof(pkey)`); `i < sizeof(arr)` is a bound and still reported
      const Expr *Other = BO->getLHS() == Cur ? BO->getRHS() : BO->getLHS();
      return BO->isEqualityOp() ||
             (BO->isComparisonOp() && !Other->isValueDependent() &&
              Other->isIntegerConstantExpr(Ctx));
    }
    if (const auto *SW = Parents[0].get<SwitchStmt>())
      return SW->getCond() == Cur;
    return false;
  }
}

// sizeof(v) next to &v in the same initializer list or call: the pointer
// variable itself is the data, given by address and size (OpenSSL
// OSSL_PARAM `{ "handle", OSSL_PARAM_OCTET_PTR, &handle, sizeof(handle) }`).
bool besideItsAddress(const UnaryExprOrTypeTraitExpr *U, const Expr *Arg,
                      ASTContext &Ctx) {
  const auto *DRE = dyn_cast<DeclRefExpr>(Arg->IgnoreParens());
  if (!DRE)
    return false;
  const Stmt *Cur = U;
  while (true) {
    auto Parents = Ctx.getParents(*Cur);
    if (Parents.empty())
      return false;
    if (const auto *P = Parents[0].get<Expr>();
        P && (isa<ParenExpr>(P) || isa<ImplicitCastExpr>(P))) {
      Cur = P;
      continue;
    }
    llvm::SmallVector<const Expr *, 8> Tmp;
    if (const auto *IL = Parents[0].get<InitListExpr>())
      Tmp.append(IL->inits().begin(), IL->inits().end());
    else if (const auto *CE = Parents[0].get<CallExpr>())
      Tmp.append(CE->arg_begin(), CE->arg_end());
    else
      return false;
    for (const Expr *E : Tmp) {
      const auto *UO = dyn_cast<UnaryOperator>(E->IgnoreParenCasts());
      if (UO && UO->getOpcode() == UO_AddrOf)
        if (const auto *R = dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenCasts());
            R && R->getDecl() == DRE->getDecl())
          return true;
    }
    return false;
  }
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
          if (hasTypedPointerType(Arg) && !isa<StringLiteral>(Arg) &&
              !isArrayElement(Arg))
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
          if (Bad && !isWidthCheck(U, Mgr.getASTContext()) &&
              !besideItsAddress(U, Arg, Mgr.getASTContext()))
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
