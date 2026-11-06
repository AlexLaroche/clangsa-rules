// raptor.DoubleFree: free($PTR); ... free($PTR); with no
// `$PTR = ...;` in between. The releasers are raptor_mem::releasedArg's:
// free() and friends, library destructors (`OCSP_REQUEST_free(req)`,
// mongo-c-driver CVE-2026-84964) and allocator hooks (libssh2
// `SSH2_FREE(session, data)` -> `session->free(data, ...)`, CVE-2026-66032).
// A plain free() after destructors known only by name (`x_free(p); free(p);`)
// is the release of the block whose contents they cleared: not reported.
// A release under `if (A || B)` whose every case is later the test of an
// `if (A) return ...;` before the next release (libuv uv__getpwuid_r) cannot
// reach it: not reported.
// Flow-sensitive walk of the CFG (may-analysis, so a free on any incoming path
// counts). Path-sensitive tracking of the freed symbol is not used because
// unix.Malloc (enabled by default) sinks the path at the first double free.
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <set>

using namespace clang;
using namespace ento;

namespace {
std::string condText(const Expr *E, ASTContext &Ctx) {
  const SourceManager &SM = Ctx.getSourceManager();
  CharSourceRange R = SM.getExpansionRange(E->getSourceRange());
  std::string T;
  for (char Ch : Lexer::getSourceText(R, SM, Ctx.getLangOpts()))
    if (!isspace(static_cast<unsigned char>(Ch)))
      T += Ch;
  return T;
}

void disjuncts(const Expr *E, ASTContext &Ctx, std::vector<std::string> &Out) {
  E = E->IgnoreParenImpCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(E);
      BO && BO->getOpcode() == BO_LOr) {
    disjuncts(BO->getLHS(), Ctx, Out);
    disjuncts(BO->getRHS(), Ctx, Out);
    return;
  }
  Out.push_back(condText(E, Ctx));
}

// The `if (C) return ...;` statements (no else) of the body: test text and
// location.
void exits(const Stmt *S, ASTContext &Ctx,
           std::vector<std::pair<std::string, SourceLocation>> &Out) {
  if (!S)
    return;
  if (const auto *If = dyn_cast<IfStmt>(S); If && !If->getElse()) {
    const Stmt *T = If->getThen();
    if (const auto *CS = dyn_cast<CompoundStmt>(T); CS && !CS->body_empty())
      T = CS->body_back();
    if (isa<ReturnStmt>(T))
      Out.push_back({condText(If->getCond(), Ctx), If->getBeginLoc()});
  }
  for (const Stmt *C : S->children())
    exits(C, Ctx, Out);
}

// Is every recorded release of K the body of an `if` (no else) each of whose
// `||` cases is the test of an exit lying between that release and CE?
bool guardExited(const raptor_mem::KeySet &Freed, const std::string &K,
                 const CallExpr *CE, AnalysisDeclContext *AC) {
  ASTContext &Ctx = AC->getASTContext();
  const SourceManager &SM = Ctx.getSourceManager();
  ParentMap &PM = AC->getParentMap();
  std::vector<std::pair<std::string, SourceLocation>> Ex;
  exits(AC->getBody(), Ctx, Ex);
  std::string Pre = "@" + K + "#";
  bool Any = false;
  for (auto It = Freed.lower_bound(Pre);
       It != Freed.end() && llvm::StringRef(*It).starts_with(Pre); ++It) {
    const auto *R = reinterpret_cast<const CallExpr *>(
        static_cast<uintptr_t>(std::stoull(It->substr(Pre.size()))));
    const Stmt *Child = R, *P = PM.getParentIgnoreParenCasts(R);
    while (const auto *CS = dyn_cast_or_null<CompoundStmt>(P)) {
      if (CS->size() != 1)
        return false;
      Child = CS;
      P = PM.getParentIgnoreParenCasts(CS);
    }
    const auto *If = dyn_cast_or_null<IfStmt>(P);
    if (!If || If->getElse() || If->getThen() != Child)
      return false;
    std::vector<std::string> Cases;
    disjuncts(If->getCond(), Ctx, Cases);
    for (const std::string &C : Cases) {
      bool Exited = false;
      for (const auto &[T, L] : Ex)
        Exited |= T == C && SM.isBeforeInTranslationUnit(R->getEndLoc(), L) &&
                  SM.isBeforeInTranslationUnit(L, CE->getBeginLoc());
      if (!Exited)
        return false;
    }
    Any = true;
  }
  return Any;
}

class DoubleFreeChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const CFG *G = Mgr.getCFG(D);
    if (!G)
      return;
    auto In = raptor_mem::solveForward(*G, raptor_mem::trackFrees);
    for (const CFGBlock *B : *G) {
      raptor_mem::KeySet Freed = In[B];
      for (const CFGElement &E : *B) {
        auto CS = E.getAs<CFGStmt>();
        if (!CS)
          continue;
        const Stmt *S = CS->getStmt();
        if (const auto *CE = dyn_cast<CallExpr>(S))
          if (const Expr *P = raptor_mem::releasedArg(CE);
              P &&
              (Freed.count(raptor_mem::keyOf(P)) ||
               Freed.count("?" + raptor_mem::keyOf(P))) &&
              !raptor_mem::onlyRetry(Freed, raptor_mem::keyOf(P), CE) &&
              !(raptor_mem::isPlainFreeName(raptor::calleeName(CE)) &&
                raptor_mem::onlyNamedDestructors(Freed, raptor_mem::keyOf(P))) &&
              !guardExited(Freed, raptor_mem::keyOf(P), CE,
                           Mgr.getAnalysisDeclContext(D)))
            raptor::reportAt(
                BR, this, "Double free",
                "The software releases the same memory address twice (free(), "
                "a library destructor or an allocator hook), potentially "
                "leading to memory corruption",
                CE, Mgr.getAnalysisDeclContext(D));
        raptor_mem::trackFrees(S, Freed);
      }
    }
  }
};
} // namespace

RAPTOR_CHECKER(DoubleFreeChecker, "DoubleFree",
               "free() called twice on the same memory address")
