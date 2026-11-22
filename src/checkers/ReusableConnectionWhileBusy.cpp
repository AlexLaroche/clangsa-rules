// raptor.ReusableConnectionWhileBusy: nginx marks an idle connection
// reusable (`ngx_reusable_connection(c, 1)`), and ngx_get_connection() may
// then close it through ngx_drain_connections() when free slots run low.
// Work running on a connection that is still marked reusable is freed under
// it (CWE-416). Two shapes:
//
//   1. Work started without clearing the mark. A busy field B is tested by
//      the idle check that guards the mark (`if (h2c->last_out ||
//      h2c->processing) return; ... ngx_reusable_connection(c, 1);`), and
//      another function starts work by incrementing B (`h2c->processing++`,
//      `B += n`) without calling ngx_reusable_connection(..., 0):
//      nginx CVE-2026-123633 (ngx_http_v2_create_stream).
//
//   2. Work registered after a call that can drain. A function clears the
//      mark, then calls ngx_get_connection() before inserting the new work
//      into the structure the idle check inspects (`ngx_rbtree_insert(&qc->
//      streams.tree, ...)` after the call): the drain can close another idle
//      stream of the same connection, whose close handler sees no streams
//      and marks the connection reusable again: nginx CVE-2026-121810
//      (ngx_quic_create_stream). Inserts on an error path (in an if branch
//      that returns) do not count.
//
// The mark: a call named like *reusable_connection / *_reusable / mark_idle
// with a constant 0 or 1 last argument. The draining call:
// ngx_get_connection / *get_connection. Both lists are nginx's API; the
// rule applies to code built on it (nginx modules, forks such as Angie,
// freenginx, Tengine, OpenResty).
#include "BufHelpers.h"
#include "Common.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/Support/Regex.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {

struct Collector : RecursiveASTVisitor<Collector> {
  std::vector<const FunctionDecl *> Defs;
  bool VisitFunctionDecl(FunctionDecl *FD) {
    if (FD->doesThisDeclarationHaveABody())
      Defs.push_back(FD);
    return true;
  }
};

// ngx_reusable_connection(c, K): K, or -1 for other calls.
int markValue(const CallExpr *CE, ASTContext &Ctx) {
  static const llvm::Regex R("reusable_connection$|_reusable$|mark_idle$|set_idle$");
  StringRef N = raptor::calleeName(CE);
  if (N.empty() || !R.match(N) || CE->getNumArgs() < 2)
    return -1;
  if (auto V = intValue(CE->getArg(CE->getNumArgs() - 1), Ctx))
    return V->getExtValue() == 0 ? 0 : 1;
  return 2; // a saved value: a restore
}

bool drains(const CallExpr *CE) {
  StringRef N = raptor::calleeName(CE);
  return N == "ngx_get_connection" || N.ends_with("get_connection");
}

const FieldDecl *fieldOf(const Expr *E) {
  const auto *ME = dyn_cast<MemberExpr>(E->IgnoreParenImpCasts());
  if (!ME)
    return nullptr;
  const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  return FD && FD->getType()->isIntegerType() ? FD : nullptr;
}

bool returns(const Stmt *S) {
  bool R = false;
  forEach<Stmt>(S, [&](const Stmt *X) { R |= isa<ReturnStmt>(X); });
  return R;
}

class ReusableConnectionWhileBusyChecker : public Checker<check::EndOfTranslationUnit> {
public:
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                                 BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();
    auto before = [&](const Stmt *A, const Stmt *B) {
      return SM.isBeforeInTranslationUnit(SM.getExpansionLoc(A->getBeginLoc()),
                                          SM.getExpansionLoc(B->getBeginLoc()));
    };
    Collector Col;
    Col.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));

    // Busy fields: tested by an `if (...) return;` before a mark(c, 1).
    std::set<const FieldDecl *> Busy;
    for (const FunctionDecl *FD : Col.Defs) {
      std::vector<const CallExpr *> Marks;
      forEach<CallExpr>(FD->getBody(), [&](const CallExpr *CE) {
        if (markValue(CE, Ctx) == 1)
          Marks.push_back(CE);
      });
      if (Marks.empty())
        continue;
      forEach<IfStmt>(FD->getBody(), [&](const IfStmt *I) {
        if (!before(I, Marks.back()) || I->getElse() || !returns(I->getThen()))
          return;
        forEach<MemberExpr>(I->getCond(), [&](const MemberExpr *ME) {
          if (const FieldDecl *F = fieldOf(ME))
            Busy.insert(F);
        });
      });
    }

    for (const FunctionDecl *FD : Col.Defs) {
      const Stmt *Body = FD->getBody();
      ParentMap PM(const_cast<Stmt *>(Body));
      std::vector<const CallExpr *> Clears, Drains, Inserts;
      forEach<CallExpr>(Body, [&](const CallExpr *CE) {
        int M = markValue(CE, Ctx);
        if (M == 0)
          Clears.push_back(CE);
        if (drains(CE))
          Drains.push_back(CE);
        if (raptor::calleeName(CE).contains("insert")) {
          // not on an error path: an if branch that returns
          for (const Stmt *P = PM.getParent(CE); P; P = PM.getParent(P))
            if (const auto *I = dyn_cast<IfStmt>(P); I && returns(I->getThen()) &&
                                                     inside(PM, I->getThen(), CE))
              return;
          Inserts.push_back(CE);
        }
      });

      // 1. work started on a busy field without clearing the mark
      if (Clears.empty() && !Busy.empty()) {
        const Expr *Start = nullptr;
        forEach<Expr>(Body, [&](const Expr *E) {
          if (Start)
            return;
          const FieldDecl *F = nullptr;
          if (const auto *U = dyn_cast<UnaryOperator>(E); U && U->isIncrementOp())
            F = fieldOf(U->getSubExpr());
          else if (const auto *B = dyn_cast<CompoundAssignOperator>(E);
                   B && B->getOpcode() == BO_AddAssign)
            F = fieldOf(B->getLHS());
          if (F && Busy.count(F))
            Start = E;
        });
        if (Start) {
          const FieldDecl *F = isa<UnaryOperator>(Start)
                                   ? fieldOf(cast<UnaryOperator>(Start)->getSubExpr())
                                   : fieldOf(cast<CompoundAssignOperator>(Start)->getLHS());
          raptor::reportAt(
              BR, this, "Reusable connection while busy",
              "'" + F->getNameAsString() +
                  "' is tested before the connection is marked reusable, and this "
                  "function starts work by incrementing it without clearing the mark "
                  "(ngx_reusable_connection(c, 0)): ngx_drain_connections() can still close "
                  "the connection and free it under the new work (CWE-416)",
              Start, Mgr.getAnalysisDeclContext(FD));
        }
      }

      // 2. the mark cleared, then a draining call before the new work is inserted
      for (const CallExpr *Dr : Drains) {
        bool Cleared = false;
        for (const CallExpr *C : Clears)
          Cleared |= before(C, Dr);
        bool LateInsert = false;
        for (const CallExpr *In : Inserts)
          LateInsert |= before(Dr, In);
        if (!Cleared || !LateInsert)
          continue;
        raptor::reportAt(BR, this, "Reusable connection while busy",
                         "'" + raptor::calleeName(Dr).str() +
                             "' can drain connections, and the new work is inserted only "
                             "after it: a drained sibling's close handler finds nothing "
                             "active and marks the connection reusable again, so a later "
                             "drain frees it under the new work (CWE-416). Insert the work "
                             "before this call",
                         Dr, Mgr.getAnalysisDeclContext(FD));
        break;
      }
    }
  }

  static bool inside(const ParentMap &PM, const Stmt *Hay, const Stmt *S) {
    for (const Stmt *P = S; P; P = PM.getParent(P))
      if (P == Hay)
        return true;
    return false;
  }
};
} // namespace

RAPTOR_CHECKER(ReusableConnectionWhileBusyChecker, "ReusableConnectionWhileBusy",
               "nginx connection left reusable (drainable) while a stream is starting on it")
