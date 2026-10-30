// Helpers shared by the buffer/string checkers of the "buf" batch
// (memset, sizeof, strncat, off-by-one, overlap, strncpy, copy size,
// strlen, format strings). Header-only so that each checker can be built
// alone with RAPTOR_ONLY.
#pragma once

#include "Common.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include <functional>
#include <optional>
#include <type_traits>

namespace raptor {
namespace buf {

using namespace clang;

inline const Expr *ign(const Expr *E) {
  return E ? E->IgnoreParenImpCasts() : nullptr;
}

// Structural equality of two expressions, ignoring parentheses and implicit
// casts at every level (the moral equivalent of a semgrep metavariable
// matching the same expression twice).
inline bool sameExpr(const Expr *A, const Expr *B) {
  A = ign(A);
  B = ign(B);
  if (!A || !B)
    return A == B;
  if (A->getStmtClass() != B->getStmtClass())
    return false;
  if (const auto *DA = dyn_cast<DeclRefExpr>(A))
    return DA->getDecl()->getCanonicalDecl() ==
           cast<DeclRefExpr>(B)->getDecl()->getCanonicalDecl();
  if (const auto *MA = dyn_cast<MemberExpr>(A)) {
    const auto *MB = cast<MemberExpr>(B);
    return MA->getMemberDecl() == MB->getMemberDecl() &&
           MA->isArrow() == MB->isArrow() && sameExpr(MA->getBase(), MB->getBase());
  }
  if (const auto *IA = dyn_cast<IntegerLiteral>(A))
    return IA->getValue() == cast<IntegerLiteral>(B)->getValue();
  if (const auto *CA = dyn_cast<CharacterLiteral>(A))
    return CA->getValue() == cast<CharacterLiteral>(B)->getValue();
  if (const auto *SA = dyn_cast<StringLiteral>(A))
    return SA->getBytes() == cast<StringLiteral>(B)->getBytes();
  if (const auto *BA = dyn_cast<BinaryOperator>(A))
    if (BA->getOpcode() != cast<BinaryOperator>(B)->getOpcode())
      return false;
  if (const auto *UA = dyn_cast<UnaryOperator>(A))
    if (UA->getOpcode() != cast<UnaryOperator>(B)->getOpcode())
      return false;
  if (const auto *UA = dyn_cast<UnaryExprOrTypeTraitExpr>(A)) {
    const auto *UB = cast<UnaryExprOrTypeTraitExpr>(B);
    if (UA->getKind() != UB->getKind() ||
        UA->isArgumentType() != UB->isArgumentType())
      return false;
    if (UA->isArgumentType())
      return UA->getArgumentType().getCanonicalType() ==
             UB->getArgumentType().getCanonicalType();
    return sameExpr(UA->getArgumentExpr(), UB->getArgumentExpr());
  }
  if (const auto *CA = dyn_cast<ExplicitCastExpr>(A))
    if (CA->getTypeAsWritten().getCanonicalType() !=
        cast<ExplicitCastExpr>(B)->getTypeAsWritten().getCanonicalType())
      return false;
  if (isa<CXXThisExpr>(A))
    return true;
  // Generic case: same class and pairwise equal children.
  auto IA = A->child_begin(), EA = A->child_end();
  auto IB = B->child_begin(), EB = B->child_end();
  for (; IA != EA && IB != EB; ++IA, ++IB) {
    const auto *XA = dyn_cast_or_null<Expr>(*IA);
    const auto *XB = dyn_cast_or_null<Expr>(*IB);
    if (!XA || !XB) {
      if (XA != XB || *IA != *IB)
        return false;
      continue;
    }
    if (!sameExpr(XA, XB))
      return false;
  }
  return IA == EA && IB == EB;
}

// True if Needle occurs (structurally) anywhere inside Hay, Hay included
// (semgrep's <... $X ...>).
inline bool containsExpr(const Stmt *Hay, const Expr *Needle) {
  if (!Hay)
    return false;
  if (const auto *E = dyn_cast<Expr>(Hay))
    if (sameExpr(E, Needle))
      return true;
  // sizeof(expr) keeps its operand out of children() in some versions.
  if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(Hay))
    if (!U->isArgumentType())
      return containsExpr(U->getArgumentExpr(), Needle);
  for (const Stmt *C : Hay->children())
    if (containsExpr(C, Needle))
      return true;
  return false;
}

inline bool isStringLit(const Expr *E) {
  return isa_and_nonnull<StringLiteral>(ign(E));
}

// Integer value of E if it is a constant expression.
inline std::optional<llvm::APSInt> intValue(const Expr *E,
                                            const ASTContext &Ctx) {
  if (!E || E->isValueDependent() || E->isTypeDependent())
    return std::nullopt;
  Expr::EvalResult R;
  if (E->EvaluateAsInt(R, Ctx))
    return R.Val.getInt();
  return std::nullopt;
}

inline bool equalsInt(const Expr *E, const llvm::APInt &V,
                      const ASTContext &Ctx) {
  auto I = intValue(E, Ctx);
  return I && llvm::APSInt::isSameValue(*I, llvm::APSInt(V, true));
}

// Declaration referenced by E (variable, parameter or field), if any.
inline const ValueDecl *refDecl(const Expr *E) {
  E = ign(E);
  if (const auto *D = dyn_cast_or_null<DeclRefExpr>(E))
    return D->getDecl();
  if (const auto *M = dyn_cast_or_null<MemberExpr>(E))
    return M->getMemberDecl();
  return nullptr;
}

// "$_ $BUF[$LEN]" : true if E names an array declared with a size equal to
// Len (by value for constant arrays, by expression for VLAs).
inline bool declaredWithSize(const Expr *E, const Expr *Len,
                             const ASTContext &Ctx) {
  const ValueDecl *D = refDecl(E);
  if (!D)
    return false;
  QualType T = D->getType();
  if (const auto *CA = Ctx.getAsConstantArrayType(T))
    return equalsInt(Len, CA->getSize(), Ctx);
  if (const auto *VA = Ctx.getAsVariableArrayType(T))
    return sameExpr(VA->getSizeExpr(), Len);
  return false;
}

// Calls a function on every node of type T below S (lambdas and blocks
// included, like semgrep).
template <typename T> class Walker : public RecursiveASTVisitor<Walker<T>> {
  std::function<void(const T *)> F;

public:
  explicit Walker(std::function<void(const T *)> F) : F(std::move(F)) {}
  bool shouldVisitTemplateInstantiations() const { return false; }
  bool shouldVisitImplicitCode() const { return false; }
  bool VisitStmt(Stmt *S) {
    if constexpr (std::is_base_of_v<Stmt, T>)
      if (const auto *N = dyn_cast<T>(S))
        F(N);
    return true;
  }
  bool VisitDecl(Decl *D) {
    if constexpr (std::is_base_of_v<Decl, T>)
      if (const auto *N = dyn_cast<T>(D))
        F(N);
    return true;
  }
};

template <typename T>
inline void forEach(const Stmt *S, std::function<void(const T *)> F) {
  if (S)
    Walker<T>(std::move(F)).TraverseStmt(const_cast<Stmt *>(S));
}

} // namespace buf
} // namespace raptor

namespace raptor {
namespace buf {

// Innermost compound statement enclosing S (semgrep's statement sequence
// for `A; ... B`).
inline const CompoundStmt *enclosingBlock(const Stmt *S, const ParentMap &PM) {
  for (const Stmt *P = PM.getParent(S); P; P = PM.getParent(P))
    if (const auto *CS = dyn_cast<CompoundStmt>(P))
      return CS;
  return nullptr;
}

// B comes after A in the source (semgrep's `A; ... B`).
inline bool isAfter(const Stmt *B, const Stmt *A, const SourceManager &SM) {
  return SM.isBeforeInTranslationUnit(A->getEndLoc(), B->getBeginLoc());
}

} // namespace buf
} // namespace raptor
