// raptor.NegativeLengthUnchecked: a signed length read from the data is
// checked only from above, then used as a size or a pointer advance. A
// negative value passes the check and becomes a huge size_t (CWE-839,
// CWE-195).
//
//   int32_t strLen;
//   readVarint32(ptr, &strLen, end);
//   if (strLen > end - ptr) throw ...;       // no strLen < 0
//   str.assign((const char *)ptr, strLen);   // size_t(-1)
//
// Length: a local of signed integer type set from the data: its address is
// passed to a call that also takes a byte buffer (an out-parameter of a
// decoder), or it is set from an expression with a
// call, a dereference or a subscript (a value kept in a field is program
// state, not decoded here), and not a narrower unsigned value widened
// (`int n = p[0]`) or a string length (`(long)strlen(s)`), which cannot be
// negative.
// Upper check: a relational comparison of the length, done in a signed type,
// against something other than a constant <= 1, that bounds it from above on
// the path that goes on: `if (len > X) fail;` or `if (len < X) use;`. One
// that bounds it from below there (`if (len >= need) use;`, `while (i < n)`)
// clears the length, as does any comparison with a constant <= 1. A
// comparison done in an
// unsigned type (`(size_t)len > room`, `len > sizeof_t_value`) also rejects
// negative values and clears the length.
// Lower check: any relational comparison of the length with a constant <= 1
// (`len < 0`, `len <= 0`, `len >= 0`, `0 > len`).
// Sink, after the upper check: the length passed for a parameter of unsigned
// type (memcpy's size, std::string::assign's count, read()'s nbyte), or used
// to move a pointer (`p += len`, `p + len`).
//
// CVE-2026-58662 (Apache Thrift THeaderTransport::readString).
#include "Common.h"
#include "Registry.h"
#include "clang/AST/ExprCXX.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <functional>

using namespace clang;
using namespace ento;

namespace {
template <class F> void walk(const Stmt *S, F &&Fn) {
  if (!S)
    return;
  Fn(S);
  for (const Stmt *C : S->children())
    walk(C, Fn);
}

const VarDecl *localOf(const Expr *E) {
  E = raptor::strip(E);
  while (const auto *CE = dyn_cast_or_null<ExplicitCastExpr>(E))
    E = raptor::strip(CE->getSubExpr());
  const auto *DRE = dyn_cast_or_null<DeclRefExpr>(E);
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  return VD && VD->hasLocalStorage() && !isa<ParmVarDecl>(VD) ? VD : nullptr;
}

// A value from the data that may be negative in V: not a narrower unsigned
// value widened (`int n = p[0]`, `long off = le32dec(p)`).
bool fromData(const Expr *E, const VarDecl *V, ASTContext &Ctx) {
  QualType T = E->IgnoreParenImpCasts()->getType();
  if (T->isUnsignedIntegerType() && Ctx.getTypeSize(T) < Ctx.getTypeSize(V->getType()))
    return false;
  // A string length (`(long)strlen(s)`): never negative in practice, even
  // when kept in a signed type of the same width.
  const Expr *X = raptor::strip(E);
  while (const auto *C = dyn_cast<ExplicitCastExpr>(X))
    X = raptor::strip(C->getSubExpr());
  if (const auto *CE = dyn_cast<CallExpr>(X))
    if (raptor::isOneOf(raptor::calleeName(CE), {"strlen", "strnlen", "wcslen", "wcsnlen"}))
      return false;
  bool Found = false;
  walk(E, [&](const Stmt *S) {
    if (isa<CallExpr>(S) || isa<ArraySubscriptExpr>(S))
      Found = true;
    else if (const auto *UO = dyn_cast<UnaryOperator>(S))
      if (UO->getOpcode() == UO_Deref)
        Found = true;
  });
  return Found;
}

// Does the call take a byte buffer (a pointer to char-sized or void data)?
bool readsBytes(const CallExpr *CE) {
  for (const Expr *A : CE->arguments()) {
    QualType T = A->IgnoreParenImpCasts()->getType();
    if (const auto *PT = T->getAs<PointerType>()) {
      QualType P = PT->getPointeeType();
      if (P->isVoidType() || P->isCharType())
        return true;
    }
  }
  return false;
}

bool isSmallConst(const Expr *E, ASTContext &Ctx) {
  Expr::EvalResult R;
  return !E->isValueDependent() && E->EvaluateAsInt(R, Ctx) && R.Val.getInt().getSExtValue() <= 1;
}

// Does the branch leave the enclosing code (return, throw, goto, break,
// continue, or a call to a noreturn function)?
bool exits(const Stmt *S) {
  bool Found = false;
  walk(S, [&](const Stmt *X) {
    if (isa<ReturnStmt>(X) || isa<CXXThrowExpr>(X) || isa<GotoStmt>(X) || isa<BreakStmt>(X) ||
        isa<ContinueStmt>(X))
      Found = true;
    else if (const auto *CE = dyn_cast<CallExpr>(X))
      if (const FunctionDecl *FD = CE->getDirectCallee())
        if (FD->isNoReturn())
          Found = true;
  });
  return Found;
}

class NegativeLengthUncheckedChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();

    // Lengths set from the data.
    llvm::SmallPtrSet<const VarDecl *, 8> Data;
    auto signedInt = [](const VarDecl *V) {
      QualType T = V->getType();
      return T->isIntegerType() && T->isSignedIntegerType() && !T->isBooleanType() &&
             !T->isCharType();
    };
    walk(Body, [&](const Stmt *S) {
      if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *Dc : DS->decls())
          if (const auto *V = dyn_cast<VarDecl>(Dc))
            if (V->hasLocalStorage() && V->getInit() && signedInt(V) && fromData(V->getInit(), V, Ctx))
              Data.insert(V);
      } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->getOpcode() == BO_Assign)
          if (const VarDecl *V = localOf(BO->getLHS()))
            if (signedInt(V) && fromData(BO->getRHS(), V, Ctx))
              Data.insert(V);
      } else if (const auto *CE = dyn_cast<CallExpr>(S)) {
        // An out-parameter is decoded from the data only when the call also
        // reads bytes (`readVarint32(ptr, &len, end)`); one filled from a
        // table (`key_sizes(ctx, &encKeySz, &keysLen)`) is not.
        if (!readsBytes(CE))
          return;
        for (const Expr *A : CE->arguments()) {
          const Expr *X = raptor::strip(A);
          while (const auto *C = dyn_cast<ExplicitCastExpr>(X))
            X = raptor::strip(C->getSubExpr());
          if (const auto *UO = dyn_cast<UnaryOperator>(X))
            if (UO->getOpcode() == UO_AddrOf)
              if (const VarDecl *V = localOf(UO->getSubExpr()))
                if (signedInt(V))
                  Data.insert(V);
        }
      }
    });
    if (Data.empty())
      return;

    // Comparisons in if conditions: does the guarded branch exit, and is the
    // comparison under an odd number of `!`?
    llvm::DenseMap<const BinaryOperator *, std::pair<bool, bool>> Guard;
    walk(Body, [&](const Stmt *S) {
      const auto *If = dyn_cast<IfStmt>(S);
      if (!If || !If->getCond())
        return;
      bool Exits = exits(If->getThen());
      std::function<void(const Stmt *, bool)> Visit = [&](const Stmt *X, bool Neg) {
        if (!X)
          return;
        if (const auto *UO = dyn_cast<UnaryOperator>(X))
          if (UO->getOpcode() == UO_LNot)
            return Visit(UO->getSubExpr(), !Neg);
        if (const auto *BO = dyn_cast<BinaryOperator>(X))
          if (BO->isRelationalOp())
            Guard[BO] = {Exits, Neg};
        for (const Stmt *C : X->children())
          Visit(C, Neg);
      };
      Visit(If->getCond(), false);
    });

    // Upper checks (first location); lower and unsigned checks clear.
    llvm::DenseMap<const VarDecl *, SourceLocation> Upper;
    llvm::SmallPtrSet<const VarDecl *, 8> Cleared;
    walk(Body, [&](const Stmt *S) {
      const auto *BO = dyn_cast<BinaryOperator>(S);
      if (!BO || !BO->isRelationalOp())
        return;
      for (int Side = 0; Side < 2; ++Side) {
        const Expr *Me = Side ? BO->getRHS() : BO->getLHS();
        const Expr *Other = Side ? BO->getLHS() : BO->getRHS();
        const VarDecl *V = localOf(Me);
        if (!V || !Data.count(V))
          continue;
        if (isSmallConst(Other, Ctx) || Me->getType()->isUnsignedIntegerType()) {
          Cleared.insert(V);
          continue;
        }
        // On the path that goes on (past an exiting branch, or into a
        // non-exiting one), is V bounded from above or from below?
        // `if (len > X) fail;` and `if (len < X) use;` bound it from above;
        // `if (len >= need) use;` and `while (i < n)` from below.
        BinaryOperatorKind Op = BO->getOpcode();
        bool Greater = Side == 0 ? (Op == BO_GT || Op == BO_GE) : (Op == BO_LT || Op == BO_LE);
        auto G = Guard.find(BO);
        bool Exits = G != Guard.end() && G->second.first;
        bool Neg = G != Guard.end() && G->second.second;
        if ((Greater == Exits) == Neg) {
          Cleared.insert(V);
          continue;
        }
        auto It = Upper.find(V);
        if (It == Upper.end() || SM.isBeforeInTranslationUnit(BO->getBeginLoc(), It->second))
          Upper[V] = BO->getBeginLoc();
      }
    });

    llvm::SmallPtrSet<const Stmt *, 8> Reported;
    auto sink = [&](const Expr *Use, const Stmt *At) {
      const VarDecl *V = localOf(Use);
      if (!V || !Data.count(V) || Cleared.count(V))
        return;
      auto It = Upper.find(V);
      if (It == Upper.end() || !SM.isBeforeInTranslationUnit(It->second, At->getBeginLoc()))
        return;
      if (!Reported.insert(At).second)
        return;
      raptor::reportAt(BR, this, "Negative length unchecked",
                       "'" + V->getNameAsString() +
                           "' is signed and checked only against an upper bound: a negative "
                           "value passes the check and becomes a huge size here (CWE-839, CWE-195)",
                       At, Mgr.getAnalysisDeclContext(D));
    };
    auto unsignedParam = [](QualType T) {
      return T->isIntegerType() && T->isUnsignedIntegerType() && !T->isBooleanType();
    };
    walk(Body, [&](const Stmt *S) {
      if (const auto *CE = dyn_cast<CallExpr>(S)) {
        const FunctionDecl *FD = CE->getDirectCallee();
        if (!FD)
          return;
        unsigned Skip = isa<CXXOperatorCallExpr>(CE) && isa<CXXMethodDecl>(FD) ? 1 : 0;
        for (unsigned I = Skip; I < CE->getNumArgs(); ++I) {
          unsigned P = I - Skip;
          if (P < FD->getNumParams() && unsignedParam(FD->getParamDecl(P)->getType()))
            sink(CE->getArg(I), CE);
        }
      } else if (const auto *CC = dyn_cast<CXXConstructExpr>(S)) {
        const CXXConstructorDecl *CD = CC->getConstructor();
        for (unsigned I = 0; I < CC->getNumArgs() && I < CD->getNumParams(); ++I)
          if (unsignedParam(CD->getParamDecl(I)->getType()))
            sink(CC->getArg(I), CC);
      } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        BinaryOperatorKind Op = BO->getOpcode();
        if ((Op == BO_AddAssign || Op == BO_SubAssign) && BO->getLHS()->getType()->isPointerType())
          sink(BO->getRHS(), BO);
        else if (Op == BO_Add || Op == BO_Sub) {
          if (BO->getLHS()->getType()->isPointerType())
            sink(BO->getRHS(), BO);
          else if (Op == BO_Add && BO->getRHS()->getType()->isPointerType())
            sink(BO->getLHS(), BO);
        }
      }
    });
  }
};
} // namespace

RAPTOR_CHECKER(NegativeLengthUncheckedChecker, "NegativeLengthUnchecked",
               "Signed length checked only from above, then used as a size")
