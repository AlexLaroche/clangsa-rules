// Helpers shared by the IntegerTruncation and SignedUnsignedConversion
// checkers (private to the "int" batch, not part of the common framework).
//
// The semgrep rules match `(DEST $_) = <... (SRC $_) ...>`, i.e. a variable of
// declared type DEST assigned from an expression containing an operand of
// declared type SRC. Clang's real types include the integer promotions (char +
// char is int), which semgrep doesn't see, so instead of the type of the whole
// right-hand side we compute the "effective" source type: the type obtained by
// combining the operand types of the arithmetic without promoting them, and
// ignoring integer constants (`x = 0`, `c = c + 1`, `sizeof(...)`).
#pragma once

#include "Common.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/Basic/Builtins.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <functional>
#include <optional>

namespace raptor_int {

using namespace clang;

// Plain integer type the rules care about (no bool, no enums).
inline bool isPlainInt(QualType T) {
  T = T.getCanonicalType();
  if (const auto *BT = T->getAs<BuiltinType>())
    return BT->isInteger() && BT->getKind() != BuiltinType::Bool;
  return false;
}

// Usual-arithmetic-conversion-like combination, without integer promotion.
inline QualType combine(ASTContext &C, QualType A, QualType B) {
  if (A.isNull())
    return B;
  if (B.isNull())
    return A;
  unsigned WA = C.getIntWidth(A), WB = C.getIntWidth(B);
  if (WA != WB)
    return WA > WB ? A : B;
  return B->isUnsignedIntegerType() ? B : A;
}

// Effective integer type of E (null when E is a constant or not an integer).
// ThroughExplicit: also look through explicit integer casts, like semgrep's
// deep `<... (int $_) ...>` does.
inline QualType effectiveType(ASTContext &C, const Expr *E,
                              bool ThroughExplicit) {
  if (!E)
    return {};
  E = E->IgnoreParens();
  if (E->isValueDependent() || E->isTypeDependent())
    return {};
  if (!isPlainInt(E->getType()))
    return {};
  Expr::EvalResult R;
  if (E->EvaluateAsInt(R, C))
    return {};

  if (const auto *CE = dyn_cast<CastExpr>(E)) {
    CastKind K = CE->getCastKind();
    bool Transparent = K == CK_IntegralCast || K == CK_NoOp ||
                       K == CK_LValueToRValue;
    if (Transparent && (isa<ImplicitCastExpr>(CE) || ThroughExplicit))
      return effectiveType(C, CE->getSubExpr(), ThroughExplicit);
    if (isa<ImplicitCastExpr>(CE) && K != CK_IntegralCast)
      return {};
    return E->getType().getCanonicalType();
  }
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    switch (BO->getOpcode()) {
    case BO_Add: case BO_Sub: case BO_Mul: case BO_Div: case BO_Rem:
    case BO_And: case BO_Or: case BO_Xor:
      return combine(C, effectiveType(C, BO->getLHS(), ThroughExplicit),
                     effectiveType(C, BO->getRHS(), ThroughExplicit));
    case BO_Shl: case BO_Shr:
      return effectiveType(C, BO->getLHS(), ThroughExplicit);
    case BO_Comma:
      return effectiveType(C, BO->getRHS(), ThroughExplicit);
    default:
      if (BO->isComparisonOp() || BO->isLogicalOp())
        return {}; // 0 or 1
      return E->getType().getCanonicalType();
    }
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    switch (UO->getOpcode()) {
    case UO_Plus: case UO_Minus: case UO_Not:
      return effectiveType(C, UO->getSubExpr(), ThroughExplicit);
    case UO_LNot:
      return {};
    default:
      return E->getType().getCanonicalType();
    }
  }
  if (const auto *CO = dyn_cast<AbstractConditionalOperator>(E))
    return combine(C, effectiveType(C, CO->getTrueExpr(), ThroughExplicit),
                   effectiveType(C, CO->getFalseExpr(), ThroughExplicit));
  return E->getType().getCanonicalType();
}

// Upper bound on the number of value bits of E (its value is in
// [0, 2^bits)), or nullopt when E may be negative or nothing better than its
// type is known. Follows `& C`, `% C`, `>> k` on unsigned values, `|`, `^`,
// conditionals, and constants; explicit casts are looked through like the
// rule does, and every node is capped by the width of its own type.
inline std::optional<unsigned> valueBits(ASTContext &C, const Expr *E,
                                         const Stmt *Body = nullptr);

// Is VD the counter of a `for` loop in Body that starts at a non-negative
// constant and only ever counts up (`for (int i = 0; i < n; i++)`)?
inline bool isUpCountingCounter(ASTContext &C, const VarDecl *VD, const Stmt *Body) {
  if (!Body || !VD->hasLocalStorage())
    return false;
  const ForStmt *Loop = nullptr;
  std::function<void(const Stmt *)> Find = [&](const Stmt *S) {
    if (!S || Loop)
      return;
    if (const auto *F = dyn_cast<ForStmt>(S))
      if (const auto *DS = dyn_cast_or_null<DeclStmt>(F->getInit()))
        for (const Decl *D : DS->decls())
          if (D == VD)
            Loop = F;
    for (const Stmt *Ch : S->children())
      Find(Ch);
  };
  Find(Body);
  if (!Loop || !VD->getInit())
    return false;
  Expr::EvalResult R;
  if (!VD->getInit()->EvaluateAsInt(R, C) || R.Val.getInt().isNegative())
    return false;
  // every write is `i++`, `++i` or `i += <positive constant>`
  bool Ok = true;
  std::function<void(const Stmt *)> Writes = [&](const Stmt *S) {
    if (!S || !Ok)
      return;
    auto IsVD = [&](const Expr *E) {
      const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
      return DRE && DRE->getDecl() == VD;
    };
    if (const auto *UO = dyn_cast<UnaryOperator>(S))
      if (IsVD(UO->getSubExpr()) &&
          (UO->isDecrementOp() || UO->getOpcode() == UO_AddrOf))
        Ok = false;
    if (const auto *BO = dyn_cast<BinaryOperator>(S))
      if (BO->isAssignmentOp() && IsVD(BO->getLHS())) {
        Expr::EvalResult K;
        if (!(BO->getOpcode() == BO_AddAssign && BO->getRHS()->EvaluateAsInt(K, C) &&
              K.Val.getInt().isStrictlyPositive()))
          Ok = false;
      }
    for (const Stmt *Ch : S->children())
      Writes(Ch);
  };
  Writes(Body);
  return Ok;
}

inline std::optional<unsigned> valueBits(ASTContext &C, const Expr *E, const Stmt *Body) {
  E = E->IgnoreParens();
  if (E->isValueDependent() || !E->getType()->isIntegerType())
    return std::nullopt;
  unsigned TypeW = C.getIntWidth(E->getType());
  bool Unsigned = E->getType()->isUnsignedIntegerType();
  (void)Body;
  auto Cap = [&](std::optional<unsigned> B) -> std::optional<unsigned> {
    if (B)
      return std::min(*B, TypeW);
    return Unsigned ? std::optional<unsigned>(TypeW) : std::nullopt;
  };
  Expr::EvalResult R;
  if (E->EvaluateAsInt(R, C)) {
    const llvm::APSInt &V = R.Val.getInt();
    if (V.isSigned() && V.isNegative())
      return std::nullopt;
    return V.getActiveBits();
  }
  if (const auto *CE = dyn_cast<CastExpr>(E)) {
    if (CE->getCastKind() == CK_IntegralCast || CE->getCastKind() == CK_NoOp ||
        CE->getCastKind() == CK_LValueToRValue) {
      // A non-negative value that fits survives the cast; one that may not
      // fit is what the rule reports, explicit cast or not.
      auto B = valueBits(C, CE->getSubExpr(), Body);
      if (B && *B <= TypeW)
        return B;
      return std::nullopt;
    }
    return Cap(std::nullopt);
  }
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    auto L = valueBits(C, BO->getLHS(), Body), Rb = valueBits(C, BO->getRHS(), Body);
    switch (BO->getOpcode()) {
    case BO_And:
      if (L && Rb)
        return Cap(std::min(*L, *Rb));
      return Cap(L ? L : Rb); // a non-negative side bounds the result
    case BO_Or:
    case BO_Xor:
      return Cap(L && Rb ? std::optional<unsigned>(std::max(*L, *Rb)) : std::nullopt);
    case BO_Rem:
      if (Rb && BO->getLHS()->getType()->isUnsignedIntegerType() &&
          BO->getRHS()->EvaluateAsInt(R, C) && raptor::toInt64(R.Val.getInt()) > 0)
        return Cap((R.Val.getInt() - 1).getActiveBits());
      return Cap(std::nullopt);
    case BO_Shr:
      if (L && BO->getRHS()->EvaluateAsInt(R, C)) {
        uint64_t K = R.Val.getInt().getZExtValue();
        return Cap(*L > K ? *L - K : 0);
      }
      return Cap(std::nullopt);
    default:
      return Cap(std::nullopt);
    }
  }
  if (const auto *Call = dyn_cast<CallExpr>(E)) {
    // bit counts: 0..64
    switch (Call->getBuiltinCallee()) {
    case Builtin::BI__builtin_ctz: case Builtin::BI__builtin_ctzl: case Builtin::BI__builtin_ctzll:
    case Builtin::BI__builtin_clz: case Builtin::BI__builtin_clzl: case Builtin::BI__builtin_clzll:
    case Builtin::BI__builtin_popcount: case Builtin::BI__builtin_popcountl:
    case Builtin::BI__builtin_popcountll: case Builtin::BI__builtin_ffs:
    case Builtin::BI__builtin_ffsl: case Builtin::BI__builtin_ffsll:
      return 7u;
    default:
      return Cap(std::nullopt);
    }
  }
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      if (isUpCountingCounter(C, VD, Body))
        return Cap(TypeW - 1);
  if (const auto *CO = dyn_cast<AbstractConditionalOperator>(E)) {
    auto T = valueBits(C, CO->getTrueExpr(), Body), F = valueBits(C, CO->getFalseExpr(), Body);
    return Cap(T && F ? std::optional<unsigned>(std::max(*T, *F)) : std::nullopt);
  }
  return Cap(std::nullopt);
}

// Strip parens and implicit casts, not explicit ones.
inline const Expr *stripImplicit(const Expr *E) {
  while (true) {
    const Expr *N = E->IgnoreParens();
    if (const auto *IC = dyn_cast<ImplicitCastExpr>(N))
      N = IC->getSubExpr();
    if (N == E)
      return E;
    E = N;
  }
}

// Does the value of RHS provably fit Dest?
inline bool fits(ASTContext &C, QualType Dest, const Expr *RHS, const Stmt *Body) {
  // the value before the implicit conversion to Dest
  auto B = valueBits(C, stripImplicit(RHS), Body);
  if (!B)
    return false;
  unsigned WD = C.getIntWidth(Dest);
  return *B <= (Dest->isSignedIntegerType() ? WD - 1 : WD);
}

// Structurally identical expressions (`st->ull[0]` twice).
inline bool sameExpr(ASTContext &C, const Expr *A, const Expr *B) {
  llvm::FoldingSetNodeID IA, IB;
  A->Profile(IA, C, /*Canonical=*/true);
  B->Profile(IB, C, /*Canonical=*/true);
  return IA == IB;
}

// A same-width save/restore round trip: `L = E; ...; E = L;` (or `T L = E`),
// where L is a local of E's width that differs only in sign. The value comes
// back unchanged, so neither conversion changes it (httpd h2_mplx.c
// `old_aborted = m->c1->aborted; ... m->c1->aborted = old_aborted;`).
// Required: the save is L's only write, L's address is never taken, and L is
// otherwise read only by restores into the same E or as a truth value
// (`if (old)`, `!old`); `old < 0` or arithmetic on L keeps the warnings.
// Save is `L = E` / `T L = E`; Restore is `E = L`. Dst is the assigned
// lvalue (null for an initialisation `T L = E`, whose variable is InitVar).
inline bool isSaveRestore(ASTContext &C, const Expr *Dst, const VarDecl *InitVar,
                          const Expr *RHS, const Stmt *Body) {
  if (!Body)
    return false;
  const Expr *Src = stripImplicit(RHS);
  const VarDecl *L = nullptr;
  const Expr *E = nullptr; // the saved lvalue
  auto LocalOf = [](const Expr *X) -> const VarDecl * {
    const auto *DRE = dyn_cast<DeclRefExpr>(X->IgnoreParens());
    const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
    return VD && VD->hasLocalStorage() && !isa<ParmVarDecl>(VD) ? VD : nullptr;
  };
  if (InitVar) { // T L = E
    L = InitVar->hasLocalStorage() && !isa<ParmVarDecl>(InitVar) ? InitVar : nullptr;
    E = Src;
  } else if (const VarDecl *V = LocalOf(Dst)) { // L = E
    L = V;
    E = Src;
  } else if (const VarDecl *V = LocalOf(Src)) { // E = L: find the save
    L = V;
    if (L->getInit())
      E = stripImplicit(L->getInit());
    std::function<void(const Stmt *)> FindSave = [&](const Stmt *S) {
      if (!S)
        return;
      if (const auto *BO = dyn_cast<BinaryOperator>(S))
        if (BO->getOpcode() == BO_Assign && LocalOf(BO->getLHS()) == L)
          E = stripImplicit(BO->getRHS());
      for (const Stmt *Ch : S->children())
        FindSave(Ch);
    };
    if (!E)
      FindSave(Body);
    if (!E || !sameExpr(C, E, Dst->IgnoreParens()))
      return false;
  }
  if (!L || !E || LocalOf(E))
    return false;
  if (!isa<MemberExpr>(E) && !isa<DeclRefExpr>(E) && !isa<ArraySubscriptExpr>(E))
    return false;
  QualType TL = L->getType(), TE = E->getType();
  if (!TL->isIntegerType() || !TE->isIntegerType() || C.getIntWidth(TL) != C.getIntWidth(TE))
    return false;

  // Every use of L: one write (the save), restores into E, truth values.
  unsigned Writes = L->getInit() ? 1 : 0, Restores = 0;
  bool Bad = false;
  llvm::SmallPtrSet<const DeclRefExpr *, 8> Allowed;
  auto Truth = [&](const Expr *X) {
    if (!X)
      return;
    X = stripImplicit(X);
    if (const auto *U = dyn_cast<UnaryOperator>(X))
      if (U->getOpcode() == UO_LNot)
        X = stripImplicit(U->getSubExpr());
    if (const auto *DRE = dyn_cast<DeclRefExpr>(X))
      if (DRE->getDecl() == L)
        Allowed.insert(DRE);
  };
  std::function<void(const Stmt *)> Walk = [&](const Stmt *S) {
    if (!S)
      return;
    if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->isAssignmentOp() && LocalOf(BO->getLHS()) == L) {
        if (BO->getOpcode() != BO_Assign)
          Bad = true;
        ++Writes;
        Allowed.insert(cast<DeclRefExpr>(BO->getLHS()->IgnoreParens()));
      } else if (BO->getOpcode() == BO_Assign && LocalOf(stripImplicit(BO->getRHS())) == L) {
        if (sameExpr(C, BO->getLHS()->IgnoreParens(), E)) {
          ++Restores;
          Allowed.insert(cast<DeclRefExpr>(stripImplicit(BO->getRHS())));
        }
      } else if (BO->isLogicalOp()) {
        Truth(BO->getLHS());
        Truth(BO->getRHS());
      }
    } else if (const auto *U = dyn_cast<UnaryOperator>(S)) {
      if ((U->isIncrementDecrementOp() || U->getOpcode() == UO_AddrOf) &&
          LocalOf(U->getSubExpr()) == L)
        Bad = true;
      if (U->getOpcode() == UO_LNot)
        Truth(U->getSubExpr());
    } else if (const auto *If = dyn_cast<IfStmt>(S)) {
      Truth(If->getCond());
    } else if (const auto *W = dyn_cast<WhileStmt>(S)) {
      Truth(W->getCond());
    } else if (const auto *CO = dyn_cast<ConditionalOperator>(S)) {
      Truth(CO->getCond());
    }
    for (const Stmt *Ch : S->children())
      Walk(Ch);
  };
  Walk(Body);
  if (Bad || Writes != 1 || Restores == 0)
    return false;
  // Any other read of L (`old < 0`, `old + 1`, a call argument) disqualifies.
  std::function<bool(const Stmt *)> OtherRead = [&](const Stmt *S) -> bool {
    if (!S)
      return false;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(S))
      if (DRE->getDecl() == L && !Allowed.count(DRE))
        return true;
    for (const Stmt *Ch : S->children())
      if (OtherRead(Ch))
        return true;
    return false;
  };
  return !OtherRead(Body);
}

// Calls Fn(DestType, RHS, ReportNode) for every `x = e` and `T x = e`, and
// FnRet(Function) for every function whose return statements return a value
// for which RetPred(ReturnType, ReturnValue) holds.
class AssignmentVisitor : public RecursiveASTVisitor<AssignmentVisitor> {
public:
  std::function<void(QualType, const Expr *, const Stmt *)> OnAssign;
  std::function<void(QualType, const Expr *, const VarDecl *, const DeclStmt *)>
      OnInit;
  const DeclStmt *CurDeclStmt = nullptr;

  bool TraverseDeclStmt(DeclStmt *DS) {
    const DeclStmt *Saved = CurDeclStmt;
    CurDeclStmt = DS;
    bool Res = RecursiveASTVisitor::TraverseDeclStmt(DS);
    CurDeclStmt = Saved;
    return Res;
  }
  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_Assign && !BO->getLHS()->isTypeDependent())
      OnAssign(BO->getLHS()->getType(), BO->getRHS(), BO);
    return true;
  }
  bool VisitVarDecl(VarDecl *VD) {
    if (VD->hasInit() && !isa<ParmVarDecl>(VD) && CurDeclStmt &&
        VD->getInitStyle() != VarDecl::ListInit)
      OnInit(VD->getType(), VD->getInit(), VD, CurDeclStmt);
    return true;
  }
  // Nested functions are visited on their own by checkASTCodeBody.
  bool TraverseLambdaExpr(LambdaExpr *) { return true; }
  bool TraverseBlockExpr(BlockExpr *) { return true; }
};

// Return values of the function body D (not of nested lambdas/blocks).
inline void forEachReturn(const Stmt *Body,
                          const std::function<void(const ReturnStmt *)> &Fn) {
  if (!Body)
    return;
  if (const auto *RS = dyn_cast<ReturnStmt>(Body))
    Fn(RS);
  for (const Stmt *Child : Body->children())
    if (Child && !isa<LambdaExpr>(Child) && !isa<BlockExpr>(Child))
      forEachReturn(Child, Fn);
}

// Report at the function name, like semgrep's `focus-metavariable: $FUN`.
inline void reportAtFunctionName(ento::BugReporter &BR,
                                 const ento::CheckerBase *C, StringRef Name,
                                 StringRef Msg, const FunctionDecl *FD) {
  ento::PathDiagnosticLocation L(FD->getLocation(), BR.getSourceManager());
  BR.EmitBasicReport(FD, C, Name, raptor::Category, Msg, L,
                     SourceRange(FD->getLocation()));
}

} // namespace raptor_int
