// raptor.UncappedCreditReplenish: a credit or flow-control window counter is
// spent in one place and topped up in another by a variable amount, and the
// function that tops it up never bounds the result. The rest of the code
// relies on the counter staying below a maximum: an overflow guard written as
// `if (n > MAX - c->window)` and a room computation such as
// `c->credits - fifo->count` both wrap once the counter has gone past it
// (CWE-190 leading to CWE-787/CWE-125).
//
//   void send_chain(h2c_t *h2c, size_t n) { ... h2c->send_window -= n; }
//   void filter_cleanup(h2c_t *h2c, size_t window) {
//     ...
//     h2c->send_window += window;            // refund, no bound
//   }
//
// Credit field: a struct field F of integer type whose name says it is a
// credit or a flow-control window (credit, window, wnd, quota, budget,
// allowance, token); lengths, sizes and totals are added to and trimmed all
// the time without being bounded credits. Spend site: `F -= e`, `F = F - e`
// or `F--`, anywhere in the file. Top-up site: `F += e` or `F = F + e`, with e not
// a constant, on a field that has a spend site in another function. Reported
// when the top-up's function has none of:
//   - a relational comparison (`<`, `>`, `<=`, `>=`) that mentions F: an
//     overflow guard before (`if (n > MAX - F)`, `if (F + n > c->limit)`) or a
//     clamp after (`if (F > max) F = max`), and `MIN(F + n, max)`;
//   - a subtraction of F (`size = MAX - F`): the amount is the room left;
//   - a spend of F: the function gives back what it took itself
//     (`F -= n; if (submit() < 0) F += n;`);
//   - a spend of another field by the same amount: credit moved from one
//     account to another (`send_window += w; send_queued -= w;`), which keeps
//     their sum, and so a bound the code checks on the sum.
//
// CVE-2026-123007 (nginx HTTP/2 send_window refund in
// ngx_http_v2_filter_cleanup, unsigned wrap in the WINDOW_UPDATE check, out of
// bounds copy in ngx_ssl_send_chain), CVE-2026-68365 (Linux io_edgeport
// txCredits topped up from the device without checking maxTxCredits, out of
// bounds write in the transmit FIFO).
#include "Common.h"
#include "Registry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Support/Regex.h"
#include <string>
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

// The integer field E names (`p->f`, `s.f`), or null.
bool isCreditName(StringRef N) {
  static const llvm::Regex R("credit|window|wnd|quota|budget|allowance|token",
                             llvm::Regex::IgnoreCase);
  return R.match(N);
}

const FieldDecl *fieldOf(const Expr *E) {
  if (!E)
    return nullptr;
  const auto *ME = dyn_cast<MemberExpr>(raptor::strip(E));
  if (!ME)
    return nullptr;
  const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD || !FD->getType()->isIntegerType())
    return nullptr;
  return FD;
}

bool mentions(const Stmt *S, const FieldDecl *F) {
  bool Found = false;
  walk(S, [&](const Stmt *N) {
    if (const auto *ME = dyn_cast<MemberExpr>(N))
      if (ME->getMemberDecl() == F)
        Found = true;
  });
  return Found;
}

struct Update {
  const FieldDecl *Field = nullptr;
  const Expr *Amount = nullptr; // null for `F--`
  const Stmt *At = nullptr;
  bool Spend = false;
};

// `F op= e`, `F = F op e` (op + or -), `F--`, `--F`.
bool update(const Stmt *N, Update &U) {
  if (const auto *UO = dyn_cast<UnaryOperator>(N)) {
    if (!UO->isDecrementOp())
      return false;
    U = {fieldOf(UO->getSubExpr()), nullptr, N, true};
    return U.Field != nullptr;
  }
  const auto *BO = dyn_cast<BinaryOperator>(N);
  if (!BO)
    return false;
  const FieldDecl *F = fieldOf(BO->getLHS());
  if (!F)
    return false;
  if (BO->getOpcode() == BO_AddAssign || BO->getOpcode() == BO_SubAssign) {
    U = {F, BO->getRHS(), N, BO->getOpcode() == BO_SubAssign};
    return true;
  }
  if (BO->getOpcode() != BO_Assign)
    return false;
  const auto *R = dyn_cast<BinaryOperator>(raptor::strip(BO->getRHS()));
  if (!R || (R->getOpcode() != BO_Add && R->getOpcode() != BO_Sub))
    return false;
  const Expr *Amount = nullptr;
  if (fieldOf(R->getLHS()) == F)
    Amount = R->getRHS();
  else if (R->getOpcode() == BO_Add && fieldOf(R->getRHS()) == F)
    Amount = R->getLHS();
  if (!Amount)
    return false;
  U = {F, Amount, N, R->getOpcode() == BO_Sub};
  return true;
}

bool sameAmount(const Expr *A, const Expr *B) {
  if (!A || !B)
    return false;
  return Expr::isSameComparisonOperand(raptor::strip(A), raptor::strip(B));
}

struct FunctionCollector : RecursiveASTVisitor<FunctionCollector> {
  std::vector<const FunctionDecl *> Defs;
  bool VisitFunctionDecl(FunctionDecl *FD) {
    if (FD->doesThisDeclarationHaveABody())
      Defs.push_back(FD);
    return true;
  }
};

struct FunctionFacts {
  const FunctionDecl *FD;
  std::vector<Update> Updates;
  std::vector<const BinaryOperator *> Relational; // and subtractions
};

class UncappedCreditReplenishChecker : public Checker<check::EndOfTranslationUnit> {
public:
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                                 BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();
    FunctionCollector Col;
    Col.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));

    std::vector<FunctionFacts> Fns;
    // field -> functions that spend it
    llvm::DenseMap<const FieldDecl *, llvm::SmallPtrSet<const FunctionDecl *, 4>> Spenders;
    llvm::DenseMap<const FieldDecl *, const Stmt *> FirstSpend;
    for (const FunctionDecl *FD : Col.Defs) {
      FunctionFacts Facts{FD, {}, {}};
      walk(FD->getBody(), [&](const Stmt *N) {
        Update U;
        if (update(N, U)) {
          Facts.Updates.push_back(U);
          if (U.Spend) {
            Spenders[U.Field].insert(FD);
            FirstSpend.try_emplace(U.Field, U.At);
          }
        }
        if (const auto *BO = dyn_cast<BinaryOperator>(N))
          if (BO->isRelationalOp())
            Facts.Relational.push_back(BO);
          else if (BO->getOpcode() == BO_Sub)
            Facts.Relational.push_back(BO);
      });
      Fns.push_back(std::move(Facts));
    }

    for (const FunctionFacts &Fn : Fns) {
      for (const Update &U : Fn.Updates) {
        if (U.Spend || !U.Amount)
          continue;
        if (U.Amount->isIntegerConstantExpr(Ctx) || !isCreditName(U.Field->getName()))
          continue;
        auto It = Spenders.find(U.Field);
        if (It == Spenders.end() || It->second.contains(Fn.FD))
          continue; // never spent, or spent and given back here
        if (U.At->getBeginLoc().isMacroID())
          continue;
        bool Bounded = false;
        for (const BinaryOperator *BO : Fn.Relational)
          if (mentions(BO->isRelationalOp() ? BO : BO->getRHS(), U.Field)) {
            Bounded = true;
            break;
          }
        if (Bounded)
          continue;
        bool Transfer = false;
        for (const Update &O : Fn.Updates)
          if (O.Spend && O.Field != U.Field && sameAmount(O.Amount, U.Amount)) {
            Transfer = true;
            break;
          }
        if (Transfer)
          continue;

        std::string Name = U.Field->getNameAsString();
        unsigned SpendLine = SM.getExpansionLineNumber(FirstSpend[U.Field]->getBeginLoc());
        std::string Msg =
            "'" + Name + "' is spent elsewhere (line " + std::to_string(SpendLine) +
            ") and topped up here by a variable amount, and nothing in this function "
            "bounds the result; once it exceeds the maximum the code assumes, guards "
            "such as 'MAX - " + Name + "' and room computations based on it wrap";
        raptor::reportAt(BR, this, "Uncapped credit replenish", Msg, U.At,
                         Mgr.getAnalysisDeclContext(Fn.FD));
      }
    }
  }
};
} // namespace

RAPTOR_CHECKER(UncappedCreditReplenishChecker, "UncappedCreditReplenish",
               "A credit or window counter spent elsewhere is topped up by a variable "
               "amount without a bound check (wraps checks that assume a maximum)")
