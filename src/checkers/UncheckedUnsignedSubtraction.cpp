// raptor.UncheckedUnsignedSubtraction: an unsigned length X is checked from
// below, then reduced by more than the check guarantees (CWE-191 -> CWE-787,
// CWE-125):
//
//   if ((int) io->len < mp_stream->boundary.len + 6) return 0;
//   size_t data_len = io->len - (mp_stream->boundary.len + 8);  // wraps
//
// Guards: `if (X < Y + K1) exit;` (and `<=`, mirrored forms, `!`, `||`)
// before the subtraction, or `if (X >= Y + K1)` around it; they give
// X >= Y + K1. Subtraction: `X - (Y + K2)`, `X - Y - K2`, with the same
// non-constant terms Y and K2 > K1 for the strongest guard. X is a variable
// or field of unsigned type (casts aside); it is not reassigned after the
// guard. Values never checked from below are not this rule's form. The
// else branch of `if (X <= K)` gives X >= K + 1. A narrow slot promoted to
// int (`uint8_t - 64`) goes negative rather than wrapping: it is reported
// when stored, returned, passed or used as an index, not as an operand of
// further arithmetic (`(lumshift - 64) * 64`).
//
// CVE-2026-28525 (swupdate mg_http_multipart_continue_wait_for_chunk),
// CVE-2026-73252 (mongoose mg_tls_recv_record: `if (msgsz < 16) return -1;`
// then `msg[msgsz - 16 - 1]`).
#include "Common.h"
#include "clang/AST/ParentMap.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <map>
#include <optional>
#include <set>

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

const Expr *stripCasts(const Expr *E) {
  while (true) {
    E = E->IgnoreParenImpCasts();
    if (const auto *C = dyn_cast<ExplicitCastExpr>(E))
      E = C->getSubExpr();
    else
      return E;
  }
}

// E as a sum of keyed terms (with their signs) and a constant.
struct Linear {
  std::map<std::string, int> Terms;
  int64_t K = 0;
};
bool linear(const Expr *E, int Sign, Linear &L, const ASTContext &Ctx) {
  E = stripCasts(E);
  if (!E->isValueDependent())
    if (std::optional<llvm::APSInt> V = E->getIntegerConstantExpr(Ctx)) {
      L.K += Sign * V->getExtValue();
      return true;
    }
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Add)
      return linear(BO->getLHS(), Sign, L, Ctx) &&
             linear(BO->getRHS(), Sign, L, Ctx);
    if (BO->getOpcode() == BO_Sub)
      return linear(BO->getLHS(), Sign, L, Ctx) &&
             linear(BO->getRHS(), -Sign, L, Ctx);
    return false;
  }
  std::string Key = raptor_mem::keyOf(E);
  if (Key.empty())
    return false;
  if ((L.Terms[Key] += Sign) == 0)
    L.Terms.erase(Key);
  return true;
}

bool isUnsignedSlot(const Expr *E) {
  E = stripCasts(E);
  return (isa<DeclRefExpr>(E) || isa<MemberExpr>(E)) &&
         E->getType()->isUnsignedIntegerType() &&
         !E->getType()->isBooleanType();
}

bool exits(const Stmt *S) {
  bool X = false;
  walk(S, [&](const Stmt *N) {
    if (isa<ReturnStmt>(N) || isa<GotoStmt>(N) || isa<BreakStmt>(N) ||
        isa<ContinueStmt>(N) || isa<CXXThrowExpr>(N))
      X = true;
    else if (const auto *C = dyn_cast<CallExpr>(N);
             C && raptor_mem::neverReturns(C))
      X = true;
  });
  return X;
}

// Relational tests in Cond with the truth value each has where the code
// goes on.
void tests(const Expr *Cond, bool True,
           std::vector<std::pair<const BinaryOperator *, bool>> &Out) {
  Cond = Cond->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(Cond);
      UO && UO->getOpcode() == UO_LNot)
    return tests(UO->getSubExpr(), !True, Out);
  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if ((BO->getOpcode() == BO_LAnd && True) ||
        (BO->getOpcode() == BO_LOr && !True)) {
      tests(BO->getLHS(), True, Out);
      tests(BO->getRHS(), True, Out);
    } else if (BO->isRelationalOp())
      Out.push_back({BO, True});
  }
}

using TermSet = std::map<std::string, int>;
struct Bound {
  std::string X;
  TermSet Y;
  int64_t K;
  const IfStmt *If;
  bool Around;
  bool Else = false; // holds in the else branch of If
};

// `A op B` holding with truth V: the lower bounds it gives on each
// unsigned slot X with coefficient 1 on one side (`desclen < cols - 2` gives
// cols >= desclen + 3).
void lowerBounds(const BinaryOperator *BO, bool V, const ASTContext &Ctx,
                 std::vector<Bound> &Out) {
  Linear L, R;
  if (!linear(BO->getLHS(), 1, L, Ctx) || !linear(BO->getRHS(), 1, R, Ctx))
    return;
  std::map<std::string, const Expr *> Slots;
  for (const Expr *Side : {BO->getLHS(), BO->getRHS()})
    walk(Side, [&](const Stmt *S) {
      if (const auto *E = dyn_cast<Expr>(S); E && isUnsignedSlot(E))
        Slots.emplace(raptor_mem::keyOf(stripCasts(E)), E);
    });
  for (int Side = 0; Side < 2; ++Side) {
    const Linear &A = Side ? R : L, &B = Side ? L : R;
    BinaryOperatorKind Op =
        Side ? BinaryOperator::reverseComparisonOp(BO->getOpcode())
             : BO->getOpcode();
    if (!V)
      Op = BinaryOperator::negateComparisonOp(Op);
    // A op B with A = X + rest.
    if (Op != BO_GE && Op != BO_GT)
      continue;
    for (auto &[X, C] : A.Terms) {
      if (C != 1 || !Slots.count(X))
        continue;
      TermSet Y = B.Terms;
      bool Ok = true;
      for (auto &[K, CA] : A.Terms)
        if (K != X && (Y[K] -= CA) == 0)
          Y.erase(K);
      for (auto &[K, CY] : Y)
        Ok &= CY > 0;
      if (!Ok)
        continue;
      int64_t K1 = B.K - A.K + (Op == BO_GT ? 1 : 0);
      Out.push_back(Bound{X, Y, K1, nullptr, false});
    }
  }
}

class UncheckedUnsignedSubtractionChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();
    auto loc = [&](const Stmt *S, bool End) {
      return SM.getExpansionLoc(End ? S->getEndLoc() : S->getBeginLoc());
    };
    auto before = [&](SourceLocation A, SourceLocation B) {
      return SM.isBeforeInTranslationUnit(A, B);
    };

    std::vector<Bound> Bounds;
    std::vector<std::pair<std::string, SourceLocation>> Assigns;
    std::vector<const BinaryOperator *> Subs;
    walk(Body, [&](const Stmt *S) {
      if (const auto *If = dyn_cast<IfStmt>(S); If && If->getCond()) {
        bool Exit = exits(If->getThen());
        std::vector<std::pair<const BinaryOperator *, bool>> Ts;
        tests(If->getCond(), true, Ts);
        for (auto [BO, V] : Ts) {
          std::vector<Bound> Bs;
          lowerBounds(BO, V, Ctx, Bs);
          for (Bound &Bd : Bs) {
            Bd.If = If;
            Bd.Around = true;
            Bounds.push_back(Bd);
          }
        }
        // `if (x <= 8) ... else x - 9`: the else branch has x >= 9.
        if (If->getElse()) {
          Ts.clear();
          tests(If->getCond(), false, Ts);
          for (auto [BO, V] : Ts) {
            std::vector<Bound> Bs;
            lowerBounds(BO, V, Ctx, Bs);
            for (Bound &Bd : Bs) {
              Bd.If = If;
              Bd.Around = true;
              Bd.Else = true;
              Bounds.push_back(Bd);
            }
          }
        }
        if (Exit) {
          Ts.clear();
          tests(If->getCond(), false, Ts);
          for (auto [BO, V] : Ts) {
            std::vector<Bound> Bs;
            lowerBounds(BO, V, Ctx, Bs);
            for (Bound &Bd : Bs) {
              Bd.If = If;
              Bd.Around = false;
              Bounds.push_back(Bd);
            }
          }
        }
      }
      if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isAssignmentOp())
          Assigns.push_back({raptor_mem::keyOf(BO->getLHS()), loc(BO, false)});
        if (BO->getOpcode() == BO_Sub && BO->getType()->isIntegerType())
          Subs.push_back(BO);
      }
      if (const auto *UO = dyn_cast<UnaryOperator>(S);
          UO && UO->isIncrementDecrementOp())
        Assigns.push_back(
            {raptor_mem::keyOf(UO->getSubExpr()), loc(UO, false)});
    });

    // A narrow slot promoted to int (`uint8_t - 64`) gives a negative value,
    // not a wrapped one. Inside a larger signed computation that is meant
    // (FFmpeg vc1 INIT_LUT `(lumshift - 64) * 64`); stored, returned, passed
    // or used as an index it is the bug (mongoose `r = msgsz - 16 - 1;`,
    // `msg[msgsz - 16 - 1]`).
    ParentMap PM(const_cast<Stmt *>(Body));
    auto inArithmetic = [&](const BinaryOperator *Sub) {
      const Stmt *P = PM.getParentIgnoreParenCasts(Sub);
      while (P && isa<BinaryOperator>(P) &&
             cast<BinaryOperator>(P)->getOpcode() == BO_Sub &&
             !cast<BinaryOperator>(P)->getType()->isPointerType())
        P = PM.getParentIgnoreParenCasts(P);
      const auto *BO = dyn_cast_or_null<BinaryOperator>(P);
      return BO && !BO->getType()->isPointerType() &&
             (BO->isMultiplicativeOp() || BO->isShiftOp() || BO->isAdditiveOp() ||
              BO->isBitwiseOp());
    };
    llvm::erase_if(Subs, [&](const BinaryOperator *Sub) {
      return !Sub->getType()->isUnsignedIntegerType() && inArithmetic(Sub);
    });

    // Only whole chains: `(cols - 3) - desclen` is one subtraction.
    std::set<const Expr *> Inner;
    for (const BinaryOperator *Sub : Subs)
      Inner.insert(stripCasts(Sub->getLHS()));
    std::vector<std::pair<const BinaryOperator *, std::string>> Found;
    for (const BinaryOperator *Sub : Subs) {
      if (Inner.count(Sub))
        continue;
      Linear L;
      if (!linear(Sub, 1, L, Ctx) || L.K >= 0)
        continue;
      // One unsigned slot X minus terms Y and the constant K2.
      std::string X;
      TermSet Y;
      bool Ok = true;
      for (auto &[K, C] : L.Terms) {
        if (C == 1 && X.empty())
          X = K;
        else if (C < 0)
          Y[K] = -C;
        else
          Ok = false;
      }
      const Expr *Left = Sub;
      while (const auto *B = dyn_cast<BinaryOperator>(stripCasts(Left)))
        Left = B->getLHS();
      if (!Ok || X.empty() || raptor_mem::keyOf(stripCasts(Left)) != X ||
          !isUnsignedSlot(Left))
        continue;
      int64_t K2 = -L.K;
      SourceLocation At = loc(Sub, false);
      std::optional<int64_t> Best;
      SourceLocation First;
      for (const Bound &Bd : Bounds) {
        if (Bd.X != X || Bd.Y != Y)
          continue;
        bool Inside = false;
        walk(Bd.Else ? Bd.If->getElse() : Bd.If->getThen(),
             [&](const Stmt *N) { Inside |= N == Sub; });
        if (Bd.Around ? !Inside : (Inside || !before(loc(Bd.If, true), At)))
          continue;
        if (!Best || Bd.K > *Best)
          Best = Bd.K;
        if (First.isInvalid() || before(loc(Bd.If, false), First))
          First = loc(Bd.If, false);
      }
      if (!Best || K2 <= *Best)
        continue;
      bool Reassigned = false;
      for (auto &[K, Where] : Assigns)
        Reassigned |= K == X && before(First, Where) && before(Where, At);
      if (Reassigned)
        continue;
      Found.push_back(
          {Sub, "'" + X + "' is checked to be at least " +
                    std::to_string(*Best) +
                    (Y.empty() ? "" : " more than the subtracted terms") +
                    " but " + std::to_string(K2) + " is subtracted"});
    }
    for (auto &[Sub, Why] : Found) {
      raptor::reportAt(
          BR, this, "Unchecked unsigned subtraction",
          Why +
              ": when the value lies between the two, the unsigned difference "
              "wraps around to a huge length or a negative index (CWE-191)",
          Sub, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(
    UncheckedUnsignedSubtractionChecker, "UncheckedUnsignedSubtraction",
    "Unsigned length reduced by more than its lower-bound check allows")
