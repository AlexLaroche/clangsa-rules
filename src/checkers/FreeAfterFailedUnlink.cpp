// raptor.FreeAfterFailedUnlink: a function searches a list for an object X
// to unlink it, and frees X on the path where the search failed too
// (CWE-416):
//
//   while (w) {
//       if (w == ctx) { *p = w->next; goto done; }   // found: unlinked
//       p = &w->next; w = w->next;
//   }
//   ngx_log_error(..., "could not cancel %V resolving", ...);   // not found
// done:
//   ngx_resolver_free_locked(r, ctx);                 // freed either way
//
// X was not in the list because something else holds it: in nginx the
// resolver had detached the waiting list and was calling each context's
// handler, and the next iteration used the freed context.
//
// The search: a loop with `if (A == X)` (either order), X a variable, whose
// then-branch unlinks (assigns a `->next`/`->prev`/`->link` member) and
// leaves by `goto L` or `return`. The not-found path is the code after the
// loop; it reaches the free unless a `return` (or a `goto` to another label)
// comes first at some level before the found branch's label. The free: a
// call named like free/release/destroy/delete/unref with X as an argument,
// after the loop, not under a condition that mentions X (the fix frees only
// `if (ctx->handler != ngx_resolver_free_handler)`), with X not reassigned
// in between. A found branch that `break`s is not considered (the paths
// merge).
//
// nginx CVE-2026-123634 (ngx_resolve_name_done, ngx_resolve_addr_done).
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/Support/Regex.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {

const VarDecl *varOf(const Expr *E) {
  const auto *DR = dyn_cast<DeclRefExpr>(E->IgnoreParenCasts());
  return DR ? dyn_cast<VarDecl>(DR->getDecl()) : nullptr;
}

bool mentionsVar(const Stmt *S, const VarDecl *V) {
  bool R = false;
  forEach<DeclRefExpr>(S, [&](const DeclRefExpr *D) { R |= D->getDecl() == V; });
  return R;
}

bool isFreeName(StringRef N) {
  static const llvm::Regex R("free|release|destroy|dealloc|delete|unref|_put$",
                             llvm::Regex::IgnoreCase);
  return R.match(N);
}

bool isLinkMember(const Expr *E) {
  const auto *ME = dyn_cast<MemberExpr>(E->IgnoreParenCasts());
  if (!ME)
    return false;
  std::string N = ME->getMemberDecl()->getName().lower();
  return StringRef(N).contains("next") || StringRef(N).contains("prev") ||
         StringRef(N).contains("link");
}

class FreeAfterFailedUnlinkChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    const SourceManager &SM = Mgr.getASTContext().getSourceManager();
    ParentMap PM(const_cast<Stmt *>(Body));
    // S is (by identity) inside Hay
    auto inside = [&](const Stmt *Hay, const Stmt *S) {
      for (const Stmt *P = S; P; P = PM.getParent(P))
        if (P == Hay)
          return true;
      return false;
    };
    auto before = [&](const Stmt *A, const Stmt *B) {
      return SM.isBeforeInTranslationUnit(SM.getExpansionLoc(A->getBeginLoc()),
                                          SM.getExpansionLoc(B->getBeginLoc()));
    };

    std::vector<const Stmt *> Loops;
    forEach<Stmt>(Body, [&](const Stmt *S) {
      if (isa<WhileStmt>(S) || isa<ForStmt>(S) || isa<DoStmt>(S))
        Loops.push_back(S);
    });
    std::set<const VarDecl *> Done;

    for (const Stmt *L : Loops) {
      // the found branch: `if (A == X) { ...unlink...; goto/return }`
      const VarDecl *X = nullptr;
      const LabelDecl *Found = nullptr;
      bool Returns = false;
      forEach<IfStmt>(L, [&](const IfStmt *I) {
        if (X)
          return;
        const auto *C = dyn_cast<BinaryOperator>(I->getCond()->IgnoreParenImpCasts());
        if (!C || C->getOpcode() != BO_EQ)
          return;
        const VarDecl *Cand = nullptr;
        for (const Expr *Side : {C->getLHS(), C->getRHS()}) {
          const Expr *Other = Side == C->getLHS() ? C->getRHS() : C->getLHS();
          if (const VarDecl *V = varOf(Side); V && !mentionsVar(Other, V))
            Cand = Cand ? Cand : V;
        }
        if (!Cand)
          return;
        // the candidate must not be the cursor: the cursor is assigned in the loop
        bool Cursor = false;
        forEach<BinaryOperator>(L, [&](const BinaryOperator *B) {
          if (B->isAssignmentOp() && varOf(B->getLHS()) == Cand)
            Cursor = true;
        });
        if (Cursor) {
          // try the other side
          const Expr *Other = varOf(C->getLHS()) == Cand ? C->getRHS() : C->getLHS();
          Cand = varOf(Other);
          if (!Cand)
            return;
          forEach<BinaryOperator>(L, [&](const BinaryOperator *B) {
            if (B->isAssignmentOp() && varOf(B->getLHS()) == Cand)
              Cand = nullptr;
          });
          if (!Cand)
            return;
        }
        bool Unlinks = false;
        forEach<BinaryOperator>(I->getThen(), [&](const BinaryOperator *B) {
          Unlinks |= B->getOpcode() == BO_Assign && (isLinkMember(B->getRHS()) || isLinkMember(B->getLHS()));
        });
        const LabelDecl *G = nullptr;
        bool R = false;
        forEach<Stmt>(I->getThen(), [&](const Stmt *S) {
          if (const auto *GS = dyn_cast<GotoStmt>(S))
            G = GS->getLabel();
          R |= isa<ReturnStmt>(S);
        });
        if (Unlinks && (G || R)) {
          X = Cand;
          Found = G;
          Returns = !G;
        }
      });
      if (!X || Done.count(X))
        continue;

      // Does the not-found path (after the loop) leave before the merge?
      bool Leaves = false;
      bool Merged = false;
      const Stmt *Cur = L;
      for (const Stmt *P = PM.getParent(Cur); P && !Leaves && !Merged; Cur = P, P = PM.getParent(P)) {
        const auto *CS = dyn_cast<CompoundStmt>(P);
        if (!CS)
          continue;
        bool After = false;
        for (const Stmt *S : CS->body()) {
          if (S == Cur) {
            After = true;
            continue;
          }
          if (!After)
            continue;
          if (const auto *LS = dyn_cast<LabelStmt>(S); LS && Found && LS->getDecl() == Found) {
            Merged = true;
            break;
          }
          if (isa<ReturnStmt>(S) || isa<ContinueStmt>(S) || isa<BreakStmt>(S)) {
            Leaves = true;
            break;
          }
          if (const auto *GS = dyn_cast<GotoStmt>(S); GS && GS->getLabel() != Found) {
            Leaves = true;
            break;
          }
        }
        if (P == Body)
          break;
      }
      if (Leaves)
        continue;
      (void)Returns;

      // the free of X after the loop
      const CallExpr *Free = nullptr;
      forEach<CallExpr>(Body, [&](const CallExpr *CE) {
        if (Free || !before(L, CE) || inside(L, CE))
          return;
        if (!isFreeName(raptor::calleeName(CE)))
          return;
        bool Arg = false;
        for (const Expr *A : CE->arguments())
          Arg |= varOf(A) == X;
        if (!Arg)
          return;
        for (const Stmt *P = PM.getParent(CE); P; P = PM.getParent(P))
          if (const auto *I = dyn_cast<IfStmt>(P); I && mentionsVar(I->getCond(), X))
            return;
        bool Reassigned = false;
        forEach<BinaryOperator>(Body, [&](const BinaryOperator *B) {
          Reassigned |= B->getOpcode() == BO_Assign && varOf(B->getLHS()) == X &&
                        before(L, B) && before(B, CE);
        });
        if (!Reassigned)
          Free = CE;
      });
      if (!Free)
        continue;
      Done.insert(X);
      raptor::reportAt(BR, this, "Free after failed unlink",
                       "'" + X->getNameAsString() +
                           "' is freed here even when the search of the list above did not "
                           "find it to unlink it: then something else holds it (a loop "
                           "that detached the list and is calling each entry) and uses it "
                           "after this free (CWE-416). Free it only once it has been "
                           "unlinked, or hand it to its holder",
                       Free, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(FreeAfterFailedUnlinkChecker, "FreeAfterFailedUnlink",
               "object freed even when the search to unlink it from a list failed")
