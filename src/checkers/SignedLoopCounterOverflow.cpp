// raptor.SignedLoopCounterOverflow: a for loop runs a signed 32-bit counter
// up to an int length parameter that nothing range-checks, and arithmetic on
// the counter overflows before the loop ends when the length is near INT_MAX
// (CWE-190 -> CWE-787, CWE-125):
//
//   for (i = 0; i + 2 < dlen; i += 3)     // dlen = INT_MAX: i + 2 wraps
//       *(t++) = f[i]; ...                // negative, the guard stays true
//
//   for (int i = 0; i < pixels; i++)      // pixels > INT_MAX / 4
//       output[i * 4 + 0] = input[i * 4 + 3];   // i * 4 wraps negative
//
// The counter: a signed 32-bit variable moved by the for increment (`i++`,
// `i += S`, `i = i + S`, S constant). The bound: a 32-bit integer parameter
// N in a conjunct of the condition, compared with the counter or with
// `i + K` (K constant >= 1).
//   - guard: `i + K < N` (or `!=`) when the step S >= 2 can jump past
//     N - K, `i + K <= N` for any step; the counter must index memory in the
//     body;
//   - index: `i * M` (M constant >= 2), alone or plus a constant, as an
//     array index (plus constants only: `i * W + j` is row i, column j of
//     a matrix), or as a pointer offset that is dereferenced or
//     subscripted (a row pointer `s + i * N` handed to a callee walks a
//     matrix of few rows); one report per loop.
// Not reported when N is compared with anything but 0 or 1 before the loop
// (outside a loop condition: `while (i < n)` runs up to n, it does not bound it),
// or is assigned, incremented or has its address taken in the function.
//
// OpenSSL CVE-2026-121481 (evp_encodeblock_int, encode_base64_avx2),
// OpenImageIO CVE-2026-43909 (SwapRGBABytes in DPXColorConverter.cpp).
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {

const VarDecl *varOf(const Expr *E) {
  const auto *DR = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
  return DR ? dyn_cast<VarDecl>(DR->getDecl()) : nullptr;
}

class SignedLoopCounterOverflowChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();
    ParentMap PM(const_cast<Stmt *>(Body));
    auto before = [&](const Stmt *A, const Stmt *B) {
      return SM.isBeforeInTranslationUnit(SM.getExpansionLoc(A->getBeginLoc()),
                                          SM.getExpansionLoc(B->getBeginLoc()));
    };
    auto signed32 = [&](QualType T) {
      return T->isSignedIntegerType() && Ctx.getTypeSize(T) == 32;
    };
    auto constOf = [&](const Expr *E) -> std::optional<int64_t> {
      if (auto V = intValue(E, Ctx))
        return V->getExtValue();
      return std::nullopt;
    };

    // Parameters that are changed in the function, and comparisons.
    std::set<const VarDecl *> Changed;
    std::vector<const BinaryOperator *> Cmps;
    std::vector<const Expr *> LoopConds; // `while (i < n)` runs up to n, it does not bound it
    forEach<Stmt>(Body, [&](const Stmt *S) {
      if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isAssignmentOp())
          if (const VarDecl *V = varOf(BO->getLHS()))
            Changed.insert(V);
        if (BO->isComparisonOp())
          Cmps.push_back(BO);
      } else if (isa<ForStmt>(S) || isa<WhileStmt>(S) || isa<DoStmt>(S)) {
        const Expr *C = isa<ForStmt>(S)     ? cast<ForStmt>(S)->getCond()
                        : isa<WhileStmt>(S) ? cast<WhileStmt>(S)->getCond()
                                            : cast<DoStmt>(S)->getCond();
        if (C)
          LoopConds.push_back(C);
      } else if (const auto *U = dyn_cast<UnaryOperator>(S)) {
        if (U->isIncrementDecrementOp() || U->getOpcode() == UO_AddrOf)
          if (const VarDecl *V = varOf(U->getSubExpr()))
            Changed.insert(V);
      }
    });
    // Is N compared with something other than 0 or 1 before Loop?
    auto bounded = [&](const VarDecl *N, const ForStmt *Loop) {
      for (const BinaryOperator *C : Cmps) {
        if (!before(C, Loop) || containsExpr(Loop, C))
          continue;
        bool InLoopCond = false;
        for (const Expr *LC : LoopConds)
          InLoopCond |= containsExpr(LC, C);
        if (InLoopCond)
          continue;
        for (int Side = 0; Side < 2; ++Side) {
          const Expr *Mine = Side ? C->getRHS() : C->getLHS();
          const Expr *Them = Side ? C->getLHS() : C->getRHS();
          if (varOf(Mine) != N)
            continue;
          if (auto K = constOf(Them); K && *K <= 1)
            continue;
          return true;
        }
      }
      return false;
    };
    // The step of the counter in a for increment.
    auto stepOf = [&](const Expr *Inc) -> std::pair<const VarDecl *, int64_t> {
      if (!Inc)
        return {nullptr, 0};
      Inc = Inc->IgnoreParenImpCasts();
      if (const auto *U = dyn_cast<UnaryOperator>(Inc); U && U->isIncrementOp())
        return {varOf(U->getSubExpr()), 1};
      if (const auto *B = dyn_cast<BinaryOperator>(Inc)) {
        if (B->getOpcode() == BO_AddAssign)
          if (auto S = constOf(B->getRHS()))
            return {varOf(B->getLHS()), *S};
        if (B->getOpcode() == BO_Assign)
          if (const auto *A = dyn_cast<BinaryOperator>(B->getRHS()->IgnoreParenImpCasts());
              A && A->getOpcode() == BO_Add && varOf(A->getLHS()) == varOf(B->getLHS()))
            if (auto S = constOf(A->getRHS()))
              return {varOf(B->getLHS()), *S};
      }
      return {nullptr, 0};
    };
    // `i + K` (K >= 1) in int arithmetic, or `i`: K (0 for `i`), or -1.
    auto offsetOf = [&](const Expr *E, const VarDecl *I) -> int64_t {
      E = E->IgnoreParenImpCasts();
      if (varOf(E) == I)
        return 0;
      if (const auto *B = dyn_cast<BinaryOperator>(E);
          B && B->getOpcode() == BO_Add && signed32(B->getType()))
        for (int Side = 0; Side < 2; ++Side)
          if (varOf(Side ? B->getRHS() : B->getLHS()) == I)
            if (auto K = constOf(Side ? B->getLHS() : B->getRHS()); K && *K >= 1)
              return *K;
      return -1;
    };
    // Does E (an int expression) end up as an array index or pointer offset?
    auto indexes = [&](const Expr *E) {
      const Stmt *Cur = E;
      for (const Stmt *P = PM.getParent(Cur); P; Cur = P, P = PM.getParent(P)) {
        if (isa<ParenExpr>(P) || isa<ImplicitCastExpr>(P) || isa<CStyleCastExpr>(P))
          continue;
        if (const auto *AS = dyn_cast<ArraySubscriptExpr>(P))
          return Cur == AS->getIdx();
        if (const auto *B = dyn_cast<BinaryOperator>(P)) {
          if (B->getType()->isPointerType())
            return B->isAdditiveOp();
          if (B->isAdditiveOp() && B->getType()->isIntegerType())
            continue;
        }
        return false;
      }
      return false;
    };

    // Does E (an int expression) address one element: an array index, or a
    // pointer offset that is dereferenced or subscripted? (`p + i * N` handed
    // to a callee is a row of a matrix, `ntt(s + i * MLKEM_N)`.)
    auto elementAccess = [&](const Expr *E) {
      const Stmt *Cur = E;
      bool Ptr = false;
      for (const Stmt *P = PM.getParent(Cur); P; Cur = P, P = PM.getParent(P)) {
        if (isa<ParenExpr>(P) || isa<ImplicitCastExpr>(P) || isa<CStyleCastExpr>(P))
          continue;
        if (const auto *AS = dyn_cast<ArraySubscriptExpr>(P))
          return Ptr ? Cur == AS->getBase() : Cur == AS->getIdx();
        if (const auto *U = dyn_cast<UnaryOperator>(P))
          return Ptr && U->getOpcode() == UO_Deref;
        if (const auto *B = dyn_cast<BinaryOperator>(P); B && B->isAdditiveOp()) {
          Ptr |= B->getType()->isPointerType();
          if (B->getType()->isPointerType())
            continue;
          // `i * M + c`; `i * W + j` is row i, column j of a matrix of few rows
          const Expr *Other = B->getLHS() == Cur ? B->getRHS() : B->getLHS();
          if (!Ptr && B->getType()->isIntegerType() && constOf(Other))
            continue;
        }
        return false;
      }
      return false;
    };

    forEach<ForStmt>(Body, [&](const ForStmt *F) {
      const auto Inc = stepOf(F->getInc());
      const VarDecl *I = Inc.first;
      const int64_t Step = Inc.second;
      if (!I || Step < 1 || !signed32(I->getType()) || !F->getCond())
        return;
      // conjuncts of the condition
      std::vector<const Expr *> Conj;
      std::function<void(const Expr *)> split = [&](const Expr *E) {
        E = E->IgnoreParenImpCasts();
        if (const auto *B = dyn_cast<BinaryOperator>(E); B && B->getOpcode() == BO_LAnd) {
          split(B->getLHS());
          split(B->getRHS());
        } else
          Conj.push_back(E);
      };
      split(F->getCond());
      for (const Expr *E : Conj) {
        const auto *C = dyn_cast<BinaryOperator>(E);
        if (!C || !(C->isRelationalOp() || C->getOpcode() == BO_NE))
          continue;
        BinaryOperatorKind Op = C->getOpcode();
        const Expr *X = C->getLHS(), *NE = C->getRHS();
        if (Op == BO_GT || Op == BO_GE) {
          std::swap(X, NE);
          Op = Op == BO_GT ? BO_LT : BO_LE;
        }
        const VarDecl *N = varOf(NE);
        if (!N || !isa<ParmVarDecl>(N) || !N->getType()->isIntegerType() ||
            Ctx.getTypeSize(N->getType()) != 32 || Changed.count(N))
          continue;
        int64_t K = offsetOf(X, I);
        if (K < 0 || bounded(N, F))
          continue;

        // the guard itself wraps
        bool Wraps = K >= 1 && (Op == BO_LE || Step >= 2);
        if (Wraps) {
          bool Used = false;
          forEach<DeclRefExpr>(F->getBody(), [&](const DeclRefExpr *U) {
            Used |= U->getDecl() == I && indexes(U);
          });
          if (Used) {
            raptor::reportAt(
                BR, this, "Loop guard overflows near INT_MAX",
                "'" + I->getNameAsString() + " + " + std::to_string(K) +
                    "' is computed in int and '" + N->getNameAsString() +
                    "' is not bounded: when it is near INT_MAX the step of " +
                    std::to_string(Step) +
                    " takes the sum past INT_MAX, it wraps negative and the loop "
                    "keeps reading and writing past the buffers (CWE-190). Bound '" +
                    N->getNameAsString() + "' or use size_t",
                F, Mgr.getAnalysisDeclContext(D));
            return;
          }
        }
        // `i * M` as an index
        const BinaryOperator *Mul = nullptr;
        forEach<BinaryOperator>(F->getBody(), [&](const BinaryOperator *B) {
          if (Mul || B->getOpcode() != BO_Mul || !signed32(B->getType()))
            return;
          for (int Side = 0; Side < 2; ++Side)
            if (varOf(Side ? B->getRHS() : B->getLHS()) == I)
              if (auto M = constOf(Side ? B->getLHS() : B->getRHS()); M && *M >= 2 && elementAccess(B))
                Mul = B;
        });
        if (Mul) {
          raptor::reportAt(BR, this, "Loop index overflows near INT_MAX",
                           "'" + I->getNameAsString() + "' runs up to '" +
                               N->getNameAsString() +
                               "', an int that is not bounded, and this product is "
                               "computed in int: past INT_MAX / factor it wraps negative "
                               "and the access goes before the buffer (CWE-190). Bound '" +
                               N->getNameAsString() + "' or use size_t",
                           Mul, Mgr.getAnalysisDeclContext(D));
          return;
        }
      }
    });
  }
};
} // namespace

RAPTOR_CHECKER(SignedLoopCounterOverflowChecker, "SignedLoopCounterOverflow",
               "int loop counter arithmetic that overflows when an unbounded int length is near INT_MAX")
