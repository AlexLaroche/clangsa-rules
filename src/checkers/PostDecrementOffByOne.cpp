// raptor.PostDecrementOffByOne: a loop that writes or reads through a
// pointer is bounded by a post-decremented counter tested for going
// negative, so it runs one time too many (CWE-193, CWE-787):
//
//   while ((ch = *cp) != stop) {
//     if (term-- < 0) break;      // tests term before the decrement
//     *out++ = ch;                // term + 1 bytes
//   }
//   while (n-- >= 0) *p++ = 0;    // n + 1 bytes
//
// Exit form: an if inside the loop whose condition is `X-- < 0`, `X-- <= -1`
// (or mirrored, `0 > X--`) and whose branch leaves the loop (break, return,
// goto). Loop form: a loop condition `X-- >= 0` or `X-- > -1`. The loop body
// must dereference or subscript something. `--X < 0`, `X-- <= 0` and
// `X-- > 0` are the correct forms and are not reported.
//
// CVE-2026-31969 (HTSlib cram_byte_array_stop_decode_char).
#include "Common.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <functional>
#include <vector>

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

// The value of E as an integer constant, if it is one.
bool constValue(const Expr *E, const ASTContext &Ctx, int64_t &V) {
  Expr::EvalResult R;
  if (!E->EvaluateAsInt(R, Ctx))
    return false;
  V = R.Val.getInt().getSExtValue();
  return true;
}

bool isPostDec(const Expr *E) {
  const auto *UO = dyn_cast<UnaryOperator>(E->IgnoreParenImpCasts());
  return UO && UO->getOpcode() == UO_PostDec;
}

// Does Cond test a post-decremented counter for being negative (Neg) or for
// being still non-negative (!Neg)?
bool postDecTest(const Expr *Cond, const ASTContext &Ctx, bool Neg) {
  const auto *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
  if (!BO || !BO->isRelationalOp())
    return false;
  BinaryOperatorKind Op = BO->getOpcode();
  const Expr *X = BO->getLHS(), *C = BO->getRHS();
  if (!isPostDec(X)) {
    std::swap(X, C);
    Op = BinaryOperator::reverseComparisonOp(Op);
  }
  int64_t V;
  if (!isPostDec(X) || !constValue(C, Ctx, V))
    return false;
  if (Neg)
    return (Op == BO_LT && V == 0) || (Op == BO_LE && V == -1);
  return (Op == BO_GE && V == 0) || (Op == BO_GT && V == -1);
}

bool leaves(const Stmt *S) {
  if (const auto *CS = dyn_cast_or_null<CompoundStmt>(S))
    S = CS->body_empty() ? nullptr : CS->body_back();
  return isa_and_nonnull<BreakStmt, ReturnStmt, GotoStmt>(S);
}

// The variables Loop (its condition, body and increment) changes.
llvm::SmallPtrSet<const ValueDecl *, 8> modified(const Stmt *Loop) {
  llvm::SmallPtrSet<const ValueDecl *, 8> Out;
  auto target = [&](const Expr *E) {
    if (const auto *DR = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts()))
      Out.insert(DR->getDecl());
  };
  walk(Loop, [&](const Stmt *X) {
    if (const auto *UO = dyn_cast<UnaryOperator>(X); UO && UO->isIncrementDecrementOp())
      target(UO->getSubExpr());
    if (const auto *BO = dyn_cast<BinaryOperator>(X); BO && BO->isAssignmentOp())
      target(BO->getLHS());
  });
  return Out;
}

bool mentions(const Stmt *S, const llvm::SmallPtrSet<const ValueDecl *, 8> &Vars) {
  bool Found = false;
  walk(S, [&](const Stmt *X) {
    if (const auto *DR = dyn_cast<DeclRefExpr>(X))
      Found |= Vars.count(DR->getDecl()) > 0;
  });
  return Found;
}

// Does the body of Loop walk memory: a subscript by a non-constant index, or
// a dereference of a pointer the loop moves? `*q = f(*q); q->v[0] += 1`
// touches the same slots every turn (FFmpeg av_mod_i).
bool accessesMemory(const Stmt *Loop, const Stmt *S, const ASTContext &Ctx) {
  auto Mod = modified(Loop);
  bool Found = false;
  walk(S, [&](const Stmt *X) {
    if (const auto *UO = dyn_cast<UnaryOperator>(X); UO && UO->getOpcode() == UO_Deref)
      Found |= mentions(UO->getSubExpr(), Mod);
    if (const auto *AS = dyn_cast<ArraySubscriptExpr>(X)) {
      int64_t V;
      Found |= !constValue(AS->getIdx(), Ctx, V) || mentions(AS->getBase(), Mod);
    }
  });
  return Found;
}

const Stmt *loopBody(const Stmt *L) {
  if (const auto *W = dyn_cast<WhileStmt>(L))
    return W->getBody();
  if (const auto *F = dyn_cast<ForStmt>(L))
    return F->getBody();
  if (const auto *D = dyn_cast<DoStmt>(L))
    return D->getBody();
  return nullptr;
}

const Expr *loopCond(const Stmt *L) {
  if (const auto *W = dyn_cast<WhileStmt>(L))
    return W->getCond();
  if (const auto *F = dyn_cast<ForStmt>(L))
    return F->getCond();
  if (const auto *D = dyn_cast<DoStmt>(L))
    return D->getCond();
  return nullptr;
}

class PostDecrementOffByOneChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    const ASTContext &Ctx = Mgr.getASTContext();
    ParentMap PM(const_cast<Stmt *>(Body));
    auto report = [&](const Expr *At) {
      raptor::reportAt(BR, this, "Post-decrement off by one",
                       "the counter is tested before it is decremented, so the loop runs "
                       "one time more than it counts: one element past the end "
                       "(CWE-193, CWE-787)",
                       At, Mgr.getAnalysisDeclContext(D));
    };
    walk(Body, [&](const Stmt *S) {
      if (const Expr *Cond = loopCond(S)) {
        const Stmt *LB = loopBody(S);
        // the loop goes on while X-- >= 0, or (all of a && chain) ...
        const Expr *C = Cond->IgnoreParenImpCasts();
        std::vector<const Expr *> Parts;
        std::function<void(const Expr *)> split = [&](const Expr *E) {
          E = E->IgnoreParenImpCasts();
          if (const auto *BO = dyn_cast<BinaryOperator>(E); BO && BO->getOpcode() == BO_LAnd) {
            split(BO->getLHS());
            split(BO->getRHS());
          } else
            Parts.push_back(E);
        };
        split(C);
        for (const Expr *P : Parts)
          if (postDecTest(P, Ctx, /*Neg=*/false) && accessesMemory(S, LB, Ctx))
            report(P);
        return;
      }
      const auto *If = dyn_cast<IfStmt>(S);
      if (!If || !leaves(If->getThen()) || !postDecTest(If->getCond(), Ctx, /*Neg=*/true))
        return;
      // the nearest enclosing loop, whose body accesses memory
      for (const Stmt *P = PM.getParent(If); P; P = PM.getParent(P)) {
        if (isa<SwitchStmt>(P) && isa<BreakStmt>(If->getThen()))
          return; // that break leaves the switch
        if (const Stmt *LB = loopBody(P)) {
          if (accessesMemory(P, LB, Ctx))
            report(If->getCond());
          return;
        }
      }
    });
  }
};
} // namespace

RAPTOR_CHECKER(PostDecrementOffByOneChecker, "PostDecrementOffByOne",
               "Loop bounded by a post-decremented counter tested for < 0")
