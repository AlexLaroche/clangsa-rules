// raptor.LoopGuardOutpacedByWrites: a loop condition checks a write cursor
// for room for N elements, and one pass of the body can write more than N
// through it before anything checks the cursor again (CWE-787, CWE-193):
//
//   while (*pp < end && to < to_end) {     // room for one
//     if (code == SHARP_s) *to++ = 'S';    // first
//     *to++ = code;                        // second: one past to_end
//   }
//
// Guards (a conjunct of a for/while condition; do-while runs the body first
// and is left out). C is a local or parameter, pointer or integer:
//   C < E, E > C, C != E          room 1
//   C < E - m, C + k < E          room 1 + m, 1 + k
// and m more when E is a local set to `X - m` or `&X[Y - m]` (a pointer to
// the last element: `end = &buf[n - 1]; while (p != end)` has room for two).
// A constant bound (`i < 10`) into a fixed array that holds every index the
// pass writes is not a capacity check and is not reported.
//   E - C > k, E - C >= k         room k + 1, k
// `C <= E` is a different bug (OffByOne territory) and is not considered.
// A for loop whose increment moves C by a constant of two or more
// (`for (; p < end; p += 2) { p[0] = a; p[1] = b; }`) declares what a pass
// uses, and is left out.
//
// Writes, followed along every path of one pass in source order:
//   `*C++ = v`, `B[C++] = v`       write at the position, then move by one
//   `*C = v`, `B[C] = v`, `C[k] = v`   write at the position (+ k)
//   `C++`, `C += k` (constant)     move
// What resets what the pass knows (no report after it): a comparison or a
// subtraction `E - C` that mentions C (`if (oend - o < 2) break;`), a call
// that is passed C (the callee may check it), an assignment to C, and an
// inner loop that mentions C (it has its own guard). A switch is followed
// case by case, with fall-through and break.
//
// Ruby GHSA-34m4-m9fh-gqp5 (enc/iso_8859_*.c and windows_125*.c case_map,
// fixed in 3.4.13 with `to_end - to > 1`), nDPI CVE-2026-86098
// (ndpi_json_string_escape: `j < dst_max_len`, then `dst[j++] = '\\';
// dst[j++] = c;`).
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <cstdint>
#include <functional>
#include <optional>
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

std::optional<int64_t> constOf(const Expr *E, const ASTContext &Ctx) {
  Expr::EvalResult R;
  if (!E || E->isValueDependent() || !E->EvaluateAsInt(R, Ctx))
    return std::nullopt;
  return R.Val.getInt().getSExtValue();
}

const VarDecl *varOf(const Expr *E) {
  const auto *DR = dyn_cast_or_null<DeclRefExpr>(E ? E->IgnoreParenImpCasts() : nullptr);
  if (!DR)
    return nullptr;
  const auto *VD = dyn_cast<VarDecl>(DR->getDecl());
  if (!VD || !VD->hasLocalStorage())
    return nullptr;
  QualType T = VD->getType();
  return (T->isPointerType() || T->isIntegerType()) ? VD : nullptr;
}

bool mentions(const Stmt *S, const VarDecl *V) {
  bool Found = false;
  walk(S, [&](const Stmt *X) {
    if (const auto *DR = dyn_cast<DeclRefExpr>(X))
      Found |= DR->getDecl() == V;
  });
  return Found;
}

struct Guard {
  const VarDecl *Cursor;
  int64_t Room;
  const Expr *At;
  std::optional<int64_t> Bound = std::nullopt; // `i < 10`: the constant
};

// How far short of the real end the bound E stops: k for `X - k`,
// `&X[Y - k]`, and for a local set to one of them (`end = &buf[n - 1]`
// is the last element, so `p != end` leaves room for two).
int64_t slack(const Expr *E, const ASTContext &Ctx, int Depth = 0) {
  E = E->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(E); UO && UO->getOpcode() == UO_AddrOf)
    if (const auto *AS = dyn_cast<ArraySubscriptExpr>(UO->getSubExpr()->IgnoreParens()))
      return slack(AS->getIdx(), Ctx, Depth);
  if (const auto *BO = dyn_cast<BinaryOperator>(E); BO && BO->getOpcode() == BO_Sub)
    if (auto K = constOf(BO->getRHS(), Ctx); K && *K > 0)
      return *K;
  if (Depth == 0)
    if (const auto *DR = dyn_cast<DeclRefExpr>(E))
      if (const auto *VD = dyn_cast<VarDecl>(DR->getDecl()); VD && VD->hasLocalStorage() && VD->getInit())
        return slack(VD->getInit(), Ctx, 1);
  return 0;
}

// The room a conjunct E of a loop condition proves for its cursor.
std::optional<Guard> guardOf(const Expr *E, const ASTContext &Ctx) {
  const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts());
  if (!BO || BO->getBeginLoc().isMacroID())
    return std::nullopt;
  BinaryOperatorKind Op = BO->getOpcode();
  const Expr *L = BO->getLHS()->IgnoreParenImpCasts(), *R = BO->getRHS()->IgnoreParenImpCasts();
  if (Op == BO_GT || Op == BO_GE) {
    std::swap(L, R);
    Op = Op == BO_GT ? BO_LT : BO_LE;
  }
  if (Op == BO_NE) {
    for (int I = 0; I < 2; ++I, std::swap(L, R))
      if (const VarDecl *C = varOf(L); C && !mentions(R, C))
        return Guard{C, 1 + slack(R, Ctx), BO, constOf(R, Ctx)};
    return std::nullopt;
  }
  if (Op != BO_LT && Op != BO_LE)
    return std::nullopt;
  // k < E - C, k <= E - C
  if (const auto *Sub = dyn_cast<BinaryOperator>(R); Sub && Sub->getOpcode() == BO_Sub) {
    const VarDecl *C = varOf(Sub->getRHS());
    auto K = constOf(L, Ctx);
    if (C && K && !mentions(Sub->getLHS(), C)) {
      int64_t Room = (Op == BO_LT ? *K + 1 : *K) + slack(Sub->getLHS(), Ctx);
      return Room >= 1 ? std::optional<Guard>(Guard{C, Room, BO}) : std::nullopt;
    }
    if (C)
      return std::nullopt;
  }
  if (Op != BO_LT)
    return std::nullopt;
  // C < E, C + k < E, C < E - m
  int64_t Room = 1;
  const VarDecl *C = varOf(L);
  if (!C) {
    const auto *Add = dyn_cast<BinaryOperator>(L);
    if (!Add || Add->getOpcode() != BO_Add)
      return std::nullopt;
    C = varOf(Add->getLHS());
    auto K = constOf(Add->getRHS(), Ctx);
    if (!C || !K || *K < 0)
      return std::nullopt;
    Room += *K;
  }
  if (mentions(R, C))
    return std::nullopt;
  Room += slack(R, Ctx);
  return Guard{C, Room, BO, constOf(R, Ctx)};
}

// Offsets: Unreached when no path gets here; Checked (and anything near it)
// when the path has checked the cursor since the loop condition, so later
// writes on it are not counted against the guard.
constexpr int64_t Unreached = INT64_MIN;
constexpr int64_t Checked = INT64_MIN / 2;

// Does Inc move V by a constant of two or more (`p += 2`, `i = i + 4`)?
bool steps(const Expr *Inc, const VarDecl *V, const ASTContext &Ctx) {
  bool Found = false;
  walk(Inc, [&](const Stmt *X) {
    const auto *BO = dyn_cast<BinaryOperator>(X);
    if (!BO || varOf(BO->getLHS()) != V)
      return;
    const Expr *K = nullptr;
    if (BO->getOpcode() == BO_AddAssign)
      K = BO->getRHS();
    else if (const auto *Add = dyn_cast<BinaryOperator>(BO->getRHS()->IgnoreParenImpCasts());
             BO->getOpcode() == BO_Assign && Add && Add->getOpcode() == BO_Add &&
             varOf(Add->getLHS()) == V)
      K = Add->getRHS();
    if (auto C = K ? constOf(K, Ctx) : std::nullopt; C && *C >= 2)
      Found = true;
  });
  return Found;
}

bool isLoop(const Stmt *S) { return isa<ForStmt, WhileStmt, DoStmt, CXXForRangeStmt>(S); }

// Follows one pass of a loop body for one cursor.
class Pass {
public:
  Pass(const Guard &G, const ASTContext &Ctx) : G(G), Ctx(Ctx) {}

  const Expr *Overflow = nullptr; // the first write past the room
  int64_t Needed = 0;

  // The cursor's offset after S (Unreached when no path goes on past S).
  int64_t stmt(const Stmt *S, int64_t N) {
    if (!S || N == Unreached)
      return N;
    if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
      for (const Stmt *B : CS->body())
        N = stmt(B, N);
      return N;
    }
    if (const auto *If = dyn_cast<IfStmt>(S)) {
      if (If->getInit())
        N = stmt(If->getInit(), N);
      if (If->getConditionVariableDeclStmt())
        N = stmt(If->getConditionVariableDeclStmt(), N);
      N = expr(If->getCond(), N);
      int64_t T = stmt(If->getThen(), N);
      int64_t E = If->getElse() ? stmt(If->getElse(), N) : N;
      return std::max(T, E);
    }
    if (const auto *Sw = dyn_cast<SwitchStmt>(S))
      return switchStmt(Sw, N);
    if (isLoop(S))
      return mentions(S, G.Cursor) ? Checked : N;
    if (isa<BreakStmt>(S)) {
      if (!Breaks.empty())
        Breaks.back() = std::max(Breaks.back(), N);
      return Unreached;
    }
    if (const auto *R = dyn_cast<ReturnStmt>(S)) {
      expr(R->getRetValue(), N);
      return Unreached;
    }
    if (isa<ContinueStmt, GotoStmt, IndirectGotoStmt>(S))
      return Unreached;
    if (const auto *L = dyn_cast<LabelStmt>(S))
      return stmt(L->getSubStmt(), N);
    if (const auto *SC = dyn_cast<SwitchCase>(S))
      return stmt(SC->getSubStmt(), N);
    if (const auto *DS = dyn_cast<DeclStmt>(S)) {
      for (const Decl *D : DS->decls())
        if (const auto *VD = dyn_cast<VarDecl>(D); VD && VD->getInit())
          N = expr(VD->getInit(), N);
      return N;
    }
    if (const auto *E = dyn_cast<Expr>(S))
      return expr(E, N);
    for (const Stmt *C : S->children())
      N = stmt(C, N);
    return N;
  }

private:
  const Guard &G;
  const ASTContext &Ctx;
  std::vector<int64_t> Breaks;

  bool isCursor(const Expr *E) const { return varOf(E) == G.Cursor; }

  bool isStep(const Expr *E) const {
    const auto *UO = dyn_cast<UnaryOperator>(E->IgnoreParenImpCasts());
    return UO && UO->isIncrementOp() && isCursor(UO->getSubExpr());
  }

  // Base is a fixed-size array that holds the furthest write a constant
  // bound allows (`char str[64]; while (len < 10) { str[len++] = ' '; str[len]
  // = 0; }` pads to a column).
  bool fits(const Expr *Base, int64_t Offset) const {
    if (!G.Bound || !Base)
      return false;
    const auto *CAT = Ctx.getAsConstantArrayType(Base->IgnoreParenImpCasts()->getType());
    return CAT && *G.Bound - 1 + Offset < (int64_t)CAT->getSize().getZExtValue();
  }

  void write(const Expr *At, int64_t Offset, const Expr *Base = nullptr) {
    if (!Overflow && Offset + 1 > G.Room && !fits(Base, Offset) && !At->getBeginLoc().isMacroID()) {
      Overflow = At;
      Needed = Offset + 1;
    }
  }

  // Handles an assignment target. Returns false when LHS is not a write
  // through the cursor.
  bool lhs(const Expr *LHS, int64_t &N) {
    LHS = LHS->IgnoreParenImpCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(LHS); UO && UO->getOpcode() == UO_Deref) {
      const Expr *P = UO->getSubExpr()->IgnoreParenImpCasts();
      if (isStep(P)) { // *C++ = v
        write(LHS, N);
        ++N;
        return true;
      }
      if (isCursor(P)) { // *C = v
        write(LHS, N);
        return true;
      }
      return false;
    }
    if (const auto *AS = dyn_cast<ArraySubscriptExpr>(LHS)) {
      const Expr *Idx = AS->getIdx()->IgnoreParenImpCasts();
      if (isStep(Idx)) { // B[C++] = v
        N = expr(AS->getBase(), N);
        write(LHS, N, AS->getBase());
        ++N;
        return true;
      }
      if (isCursor(Idx)) { // B[C] = v
        N = expr(AS->getBase(), N);
        write(LHS, N, AS->getBase());
        return true;
      }
      if (isCursor(AS->getBase())) { // C[k] = v
        if (auto K = constOf(Idx, Ctx); K && *K >= 0) {
          write(LHS, N + *K);
          return true;
        }
        N = Checked; // C[i]: an offset the pass does not know
        return true;
      }
    }
    return false;
  }

  int64_t switchStmt(const SwitchStmt *Sw, int64_t N) {
    N = expr(Sw->getCond(), N);
    const auto *Body = dyn_cast_or_null<CompoundStmt>(Sw->getBody());
    if (!Body)
      return stmt(Sw->getBody(), N);
    Breaks.push_back(Unreached);
    int64_t Cur = Unreached;
    bool Default = false;
    for (const Stmt *S : Body->body()) {
      while (const auto *SC = dyn_cast<SwitchCase>(S)) {
        Default |= isa<DefaultStmt>(SC);
        Cur = std::max(Cur, N);
        S = SC->getSubStmt();
      }
      Cur = stmt(S, Cur);
    }
    int64_t Out = std::max(Breaks.back(), Cur);
    Breaks.pop_back();
    return Default ? Out : std::max(Out, N);
  }

  int64_t expr(const Expr *E, int64_t N) {
    if (!E || N == Unreached)
      return N;
    E = E->IgnoreParens();
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->isAssignmentOp()) {
        N = expr(BO->getRHS(), N);
        if (lhs(BO->getLHS(), N))
          return N;
        if (isCursor(BO->getLHS())) {
          // C += k moves by k; anything else puts C somewhere the pass
          // does not know
          auto K = constOf(BO->getRHS(), Ctx);
          if (BO->getOpcode() == BO_AddAssign && K && *K >= 0)
            return N + *K;
          return Checked;
        }
        return expr(BO->getLHS(), N);
      }
      if (BO->getOpcode() == BO_LAnd || BO->getOpcode() == BO_LOr) {
        int64_t A = expr(BO->getLHS(), N);
        return std::max(A, expr(BO->getRHS(), A));
      }
      N = expr(BO->getLHS(), N);
      N = expr(BO->getRHS(), N);
      if ((BO->isComparisonOp() && mentions(BO, G.Cursor)) ||
          (BO->getOpcode() == BO_Sub && mentions(BO->getRHS(), G.Cursor)))
        return Checked; // the code checks the cursor here
      return N;
    }
    if (const auto *CO = dyn_cast<AbstractConditionalOperator>(E)) {
      N = expr(CO->getCond(), N);
      return std::max(expr(CO->getTrueExpr(), N), expr(CO->getFalseExpr(), N));
    }
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->isIncrementDecrementOp() && isCursor(UO->getSubExpr()))
        return UO->isIncrementOp() ? N + 1 : (N > 0 ? N - 1 : N);
      return expr(UO->getSubExpr(), N);
    }
    if (const auto *CE = dyn_cast<CallExpr>(E)) {
      for (const Expr *A : CE->arguments())
        N = expr(A, N);
      for (const Expr *A : CE->arguments())
        if (mentions(A, G.Cursor))
          return Checked; // the callee may check or move the cursor
      return N;
    }
    for (const Stmt *C : E->children())
      if (const auto *CE = dyn_cast_or_null<Expr>(C))
        N = expr(CE, N);
    return N;
  }
};

class LoopGuardOutpacedByWritesChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    const ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();
    walk(Body, [&](const Stmt *S) {
      const Expr *Cond = nullptr;
      const Stmt *LB = nullptr;
      if (const auto *W = dyn_cast<WhileStmt>(S))
        Cond = W->getCond(), LB = W->getBody();
      else if (const auto *F = dyn_cast<ForStmt>(S))
        Cond = F->getCond(), LB = F->getBody();
      if (!Cond || !LB)
        return;
      std::vector<const Expr *> Parts;
      std::function<void(const Expr *)> split = [&](const Expr *E) {
        E = E->IgnoreParenImpCasts();
        if (const auto *BO = dyn_cast<BinaryOperator>(E); BO && BO->getOpcode() == BO_LAnd) {
          split(BO->getLHS());
          split(BO->getRHS());
        } else
          Parts.push_back(E);
      };
      split(Cond);
      for (const Expr *P : Parts) {
        auto G = guardOf(P, Ctx);
        if (!G)
          continue;
        // `for (; p < end; p += 2)`: the step says how much a pass uses
        if (const auto *F = dyn_cast<ForStmt>(S); F && F->getInc() && steps(F->getInc(), G->Cursor, Ctx))
          continue;
        Pass Walk(*G, Ctx);
        Walk.stmt(LB, 0);
        if (!Walk.Overflow)
          continue;
        std::string Name = G->Cursor->getNameAsString();
        std::string Msg;
        llvm::raw_string_ostream OS(Msg);
        OS << "the loop condition (line " << SM.getExpansionLineNumber(P->getBeginLoc())
           << ") checks '" << Name << "' for room for " << G->Room
           << (G->Room == 1 ? " element" : " elements") << ", but one pass can write "
           << Walk.Needed << " through it before checking again: a write past the end "
           << "(CWE-787, CWE-193)";
        raptor::reportAt(BR, this, "Loop guard outpaced by writes", Msg, Walk.Overflow,
                         Mgr.getAnalysisDeclContext(D));
      }
    });
  }
};
} // namespace

RAPTOR_CHECKER(LoopGuardOutpacedByWritesChecker, "LoopGuardOutpacedByWrites",
               "Loop condition checks a write cursor for less room than one pass writes")
