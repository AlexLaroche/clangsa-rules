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
// Also not reported (FFmpeg): the first element of an array freed in a loop
// that counts that array (the destructor removes it: `while (g->nb_filters)
// avfilter_free(g->filters[0]);`); a release by a destructor of another
// name than every earlier one (`ff_frame_thread_encoder_free(avctx);
// ff_thread_free(avctx);`: parts of one object); a pointer filled by
// `ret = fill(&p)` whose failure `if (ret < 0) return ret;` exits before the
// release; a release under `if (ret < 0)` when every earlier release sits in
// a block that sets ret to a value failing that test (`ret = 0;
// av_free(p); goto fail;`).
// Flow-sensitive walk of the CFG (may-analysis, so a free on any incoming path
// counts). Path-sensitive tracking of the freed symbol is not used because
// unix.Malloc (enabled by default) sinks the path at the first double free.
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <functional>
#include <optional>
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

const CallExpr *siteCall(const std::string &Marker, size_t PreLen) {
  return reinterpret_cast<const CallExpr *>(
      static_cast<uintptr_t>(std::stoull(Marker.substr(PreLen))));
}

template <typename F>
void forEachSite(const raptor_mem::KeySet &Freed, const std::string &K, F Fn) {
  std::string Pre = "@" + K + "#";
  for (auto It = Freed.lower_bound(Pre);
       It != Freed.end() && llvm::StringRef(*It).starts_with(Pre); ++It)
    Fn(siteCall(*It, Pre.size()));
}

bool memberBaseText(const Expr *E, ASTContext &Ctx, std::string &Base,
                    const ValueDecl *&Field) {
  const auto *ME = dyn_cast<MemberExpr>(E->IgnoreParenImpCasts());
  if (!ME)
    return false;
  Base = condText(ME->getBase(), Ctx) + (ME->isArrow() ? "->" : ".");
  Field = ME->getMemberDecl();
  return true;
}

// `f(b->arr[0])` in a loop whose test reads another field of b.
bool containerShrinks(const CallExpr *CE, const Expr *P,
                      AnalysisDeclContext *AC) {
  ASTContext &Ctx = AC->getASTContext();
  const auto *AS = dyn_cast<ArraySubscriptExpr>(P->IgnoreParenImpCasts());
  if (!AS || !AS->getIdx()->isIntegerConstantExpr(Ctx))
    return false;
  std::string Base;
  const ValueDecl *Arr = nullptr;
  if (!memberBaseText(AS->getBase(), Ctx, Base, Arr))
    return false;
  ParentMap &PM = AC->getParentMap();
  for (const Stmt *X = PM.getParent(CE); X; X = PM.getParent(X)) {
    const Expr *Cond = nullptr;
    if (const auto *W = dyn_cast<WhileStmt>(X))
      Cond = W->getCond();
    else if (const auto *F = dyn_cast<ForStmt>(X))
      Cond = F->getCond();
    else if (const auto *D = dyn_cast<DoStmt>(X))
      Cond = D->getCond();
    else
      continue;
    if (!Cond)
      return false;
    bool Counts = false;
    std::function<void(const Stmt *)> Walk = [&](const Stmt *S) {
      if (!S)
        return;
      std::string B;
      const ValueDecl *F = nullptr;
      if (const auto *E = dyn_cast<Expr>(S);
          E && memberBaseText(E, Ctx, B, F) && B == Base && F != Arr)
        Counts = true;
      for (const Stmt *C : S->children())
        Walk(C);
    };
    Walk(Cond);
    return Counts;
  }
  return false;
}

// Is CE a destructor by name whose name differs from every earlier release
// of K, all of them destructors by name too?
bool otherDestructors(const raptor_mem::KeySet &Freed, const std::string &K,
                      const CallExpr *CE) {
  llvm::StringRef N = raptor::calleeName(CE);
  if (N.empty() || raptor_mem::isPlainFreeName(N))
    return false;
  bool Any = false, Other = true;
  forEachSite(Freed, K, [&](const CallExpr *R) {
    llvm::StringRef RN = raptor::calleeName(R);
    Any = true;
    Other &= !RN.empty() && RN != N && !raptor_mem::isPlainFreeName(RN);
  });
  return Any && Other;
}

// The enclosing `if` of CE (through single-statement blocks), else null.
const IfStmt *guardOf(const Stmt *CE, ParentMap &PM) {
  const Stmt *Child = CE, *P = PM.getParentIgnoreParenCasts(CE);
  while (const auto *CS = dyn_cast_or_null<CompoundStmt>(P)) {
    if (CS->size() != 1)
      return nullptr;
    Child = CS;
    P = PM.getParentIgnoreParenCasts(CS);
  }
  const auto *If = dyn_cast_or_null<IfStmt>(P);
  return If && If->getThen() == Child && !If->getElse() ? If : nullptr;
}

bool isExit(const Stmt *S) {
  if (const auto *CS = dyn_cast<CompoundStmt>(S))
    return CS->size() == 1 && isExit(CS->body_front());
  return isa<ReturnStmt, GotoStmt>(S);
}

const VarDecl *localOf(const Expr *E) {
  const auto *R = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
  const auto *V = R ? dyn_cast<VarDecl>(R->getDecl()) : nullptr;
  return V && V->hasLocalStorage() ? V : nullptr;
}

bool reads(const Stmt *S, const VarDecl *V) {
  if (!S)
    return false;
  if (const auto *E = dyn_cast<Expr>(S); E && localOf(E) == V)
    return true;
  for (const Stmt *C : S->children())
    if (reads(C, V))
      return true;
  return false;
}

// `ret = fill(..., &k, ...)` then `if (<reads ret>) return/goto;` before CE.
bool filledPastFailure(const std::string &K, const CallExpr *CE,
                       AnalysisDeclContext *AC) {
  ASTContext &Ctx = AC->getASTContext();
  const SourceManager &SM = Ctx.getSourceManager();
  ParentMap &PM = AC->getParentMap();
  bool Found = false;
  std::function<void(const Stmt *)> Walk = [&](const Stmt *S) {
    if (!S || Found)
      return;
    if (const auto *If = dyn_cast<IfStmt>(S);
        If && !If->getElse() && isExit(If->getThen()) &&
        SM.isBeforeInTranslationUnit(If->getEndLoc(), CE->getBeginLoc())) {
      // The statement before the if: `ret = fill(&k)`.
      if (const auto *Blk = dyn_cast_or_null<CompoundStmt>(PM.getParent(If))) {
        const Stmt *Prev = nullptr;
        for (const Stmt *X : Blk->body()) {
          if (X == If)
            break;
          Prev = X;
        }
        const auto *A = dyn_cast_or_null<BinaryOperator>(Prev);
        const auto *Call =
            A && A->getOpcode() == BO_Assign
                ? dyn_cast<CallExpr>(A->getRHS()->IgnoreParenCasts())
                : nullptr;
        const VarDecl *R = A ? localOf(A->getLHS()) : nullptr;
        if (Call && R && reads(If->getCond(), R))
          for (const Expr *Arg : Call->arguments())
            if (const auto *U =
                    dyn_cast<UnaryOperator>(Arg->IgnoreParenImpCasts());
                U && U->getOpcode() == UO_AddrOf &&
                raptor_mem::keyOf(U->getSubExpr()) == K)
              Found = true;
      }
    }
    for (const Stmt *C : S->children())
      Walk(C);
  };
  Walk(AC->getBody());
  return Found;
}

// Does `V op C` (C a constant, either side) hold for V == Val?
std::optional<bool> evalTest(const Expr *Cond, const VarDecl *V,
                             const llvm::APSInt &Val, ASTContext &Ctx) {
  const auto *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
  if (!BO || !(BO->isRelationalOp() || BO->isEqualityOp()))
    return std::nullopt;
  BinaryOperatorKind Op = BO->getOpcode();
  const Expr *L = BO->getLHS(), *R = BO->getRHS();
  if (localOf(R) == V) {
    std::swap(L, R);
    Op = BinaryOperator::reverseComparisonOp(Op);
  }
  Expr::EvalResult E;
  if (localOf(L) != V || !R->EvaluateAsInt(E, Ctx))
    return std::nullopt;
  llvm::APSInt A = Val, B = E.Val.getInt();
  A = A.extend(64);
  B = B.extend(64);
  A.setIsSigned(true);
  B.setIsSigned(true);
  switch (Op) {
  case BO_LT: return A < B;
  case BO_LE: return A <= B;
  case BO_GT: return A > B;
  case BO_GE: return A >= B;
  case BO_EQ: return A == B;
  case BO_NE: return A != B;
  default: return std::nullopt;
  }
}

// CE under `if (ret op C)`; every earlier release of K in a block that sets
// ret to a constant failing the test.
bool statusExcludes(const raptor_mem::KeySet &Freed, const std::string &K,
                    const CallExpr *CE, AnalysisDeclContext *AC) {
  ASTContext &Ctx = AC->getASTContext();
  ParentMap &PM = AC->getParentMap();
  const IfStmt *If = guardOf(CE, PM);
  if (!If)
    return false;
  const auto *BO = dyn_cast<BinaryOperator>(If->getCond()->IgnoreParenImpCasts());
  const VarDecl *V = nullptr;
  if (BO)
    V = localOf(BO->getLHS()) ? localOf(BO->getLHS()) : localOf(BO->getRHS());
  if (!V)
    return false;
  bool Any = false, All = true;
  forEachSite(Freed, K, [&](const CallExpr *R) {
    Any = true;
    const Stmt *X = R;
    while (X && !isa<CompoundStmt>(PM.getParent(X)))
      X = PM.getParent(X);
    const auto *Blk = X ? dyn_cast<CompoundStmt>(PM.getParent(X)) : nullptr;
    std::optional<bool> T;
    if (!Blk) {
      All = false;
      return;
    }
    for (const Stmt *Y : Blk->body())
      if (const auto *A = dyn_cast<BinaryOperator>(Y);
          A && A->getOpcode() == BO_Assign && localOf(A->getLHS()) == V) {
        Expr::EvalResult E;
        if (A->getRHS()->EvaluateAsInt(E, Ctx))
          T = evalTest(If->getCond(), V, E.Val.getInt(), Ctx);
        else
          T = std::nullopt;
      }
    All &= T.has_value() && !*T;
  });
  return Any && All;
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
                           Mgr.getAnalysisDeclContext(D)) &&
              !containerShrinks(CE, P, Mgr.getAnalysisDeclContext(D)) &&
              !otherDestructors(Freed, raptor_mem::keyOf(P), CE) &&
              !(!Freed.count(raptor_mem::keyOf(P)) &&
                filledPastFailure(raptor_mem::keyOf(P), CE,
                                  Mgr.getAnalysisDeclContext(D))) &&
              !statusExcludes(Freed, raptor_mem::keyOf(P), CE,
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
