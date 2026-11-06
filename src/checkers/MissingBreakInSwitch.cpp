// raptor.MissingBreakInSwitch: a case whose statements fall
// through into the next case/default label because they do not end with
// break, return, goto or a call that does not return (exit(), abort(),
// __builtin_unreachable(), a noreturn function), also behind a label
// (llhttp's generated `case s_x: s_x: { ... UNREACHABLE; }`).
// A fall-through into a case that only breaks, or one marked as intended (`/* FALLTHROUGH */`, `// fall through`,
// `__attribute__((fallthrough))`, `[[fallthrough]]`) is not reported.
#include "Common.h"
#include "Registry.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <regex>

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {

bool allCasesLeave(const SwitchStmt *SW);
bool breaksOut(const Stmt *S);

// Does S end the case, i.e. is it break/continue/return/goto/exit(...), or an
// inner switch with a default whose every case leaves the function?
bool isTerminator(const Stmt *S) {
  if (!S)
    return false;
  // case X: { ...; break; }
  if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
    for (auto I = CS->body_rbegin(); I != CS->body_rend(); ++I)
      if (!isa<NullStmt>(*I))
        return isTerminator(*I);
    return false;
  }
  // if (c) return a; else return b;
  if (const auto *If = dyn_cast<IfStmt>(S))
    return If->getElse() && isTerminator(If->getThen()) &&
           isTerminator(If->getElse());
  if (const auto *LS = dyn_cast<LabelStmt>(S))
    return isTerminator(LS->getSubStmt());
  if (const auto *AS = dyn_cast<AttributedStmt>(S)) {
    for (const Attr *A : AS->getAttrs())
      if (isa<FallThroughAttr>(A))
        return true;
    return isTerminator(AS->getSubStmt());
  }
  if (isa<BreakStmt, ContinueStmt, ReturnStmt, GotoStmt, IndirectGotoStmt>(S))
    return true;
  if (const auto *SW = dyn_cast<SwitchStmt>(S))
    return allCasesLeave(SW);
  // do { ...; return 0; } while (0): a statement macro that leaves, unless a
  // break inside it only leaves the do.
  if (const auto *Do = dyn_cast<DoStmt>(S)) {
    const auto *C = dyn_cast<IntegerLiteral>(Do->getCond()->IgnoreParenCasts());
    return C && C->getValue() == 0 && !breaksOut(Do->getBody()) &&
           isTerminator(Do->getBody());
  }
  if (const auto *E = dyn_cast<Expr>(S))
    if (const auto *CE = dyn_cast<CallExpr>(E->IgnoreParenCasts()))
    {
      if (const FunctionDecl *FD = CE->getDirectCallee())
        if (FD->isNoReturn())
          return true;
      return raptor::isOneOf(raptor::calleeName(CE),
                             {"exit", "_exit", "_Exit", "abort",
                              "__builtin_unreachable", "__builtin_trap"});
    }
  return false;
}

// Does S hold a break that leaves the statement it is in (not one of a
// nested loop or switch)?
bool breaksOut(const Stmt *S) {
  if (!S)
    return false;
  if (isa<BreakStmt>(S))
    return true;
  if (isa<ForStmt, WhileStmt, DoStmt, SwitchStmt>(S))
    return false;
  for (const Stmt *C : S->children())
    if (breaksOut(C))
      return true;
  return false;
}

// Does SW (which has a default) never reach the code after it: no break out
// of it, and its last case group ends in a terminator? Its other groups end
// in one or fall into the next (nghttp2 session_after_frame_sent1's
// `/* Fall through */` cases); this rule reports those on SW itself.
bool allCasesLeave(const SwitchStmt *SW) {
  const auto *Body = dyn_cast_or_null<CompoundStmt>(SW->getBody());
  if (!Body)
    return false;
  bool Default = false;
  for (const SwitchCase *C = SW->getSwitchCaseList(); C;
       C = C->getNextSwitchCase())
    Default |= isa<DefaultStmt>(C);
  if (!Default)
    return false;
  const Stmt *Last = nullptr;
  bool InGroup = false;
  for (const Stmt *S : Body->body()) {
    if (breaksOut(S) && !isa<SwitchCase>(S))
      return false;
    if (const auto *SC = dyn_cast<SwitchCase>(S)) {
      InGroup = true;
      const Stmt *Sub = SC->getSubStmt();
      while (const auto *Inner = dyn_cast<SwitchCase>(Sub))
        Sub = Inner->getSubStmt();
      if (breaksOut(Sub))
        return false;
      Last = isa<NullStmt>(Sub) ? nullptr : Sub;
      continue;
    }
    if (InGroup && !isa<NullStmt>(S))
      Last = S;
  }
  return Last && isTerminator(Last);
}

class MissingBreakInSwitchChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    auto M = switchStmt().bind("sw");
    for (const BoundNodes &N :
         match(findAll(M), *D->getBody(), Mgr.getASTContext())) {
      const auto *SW = N.getNodeAs<SwitchStmt>("sw");
      if (hasFallthrough(SW, Mgr.getASTContext()) && SW->getCond())
        // focus-metavariable: $VAR
        raptor::reportAt(BR, this, "Missing break in switch",
                         "The software omits a break statement within a "
                         "switch or similar construct, causing code "
                         "associated with multiple conditions to execute",
                         SW->getCond(), Mgr.getAnalysisDeclContext(D));
    }
  }

private:
  // Walk the top-level statements of the switch body. Consecutive labels
  // (case A: case B:) form one group; a non-empty group that is followed by
  // another label must end with a terminator.
  // Is the fall-through from Last into the label at Next marked as intended
  // by a comment between them?
  static bool markedIntended(const Stmt *Last, const Stmt *Next,
                             ASTContext &Ctx) {
    const SourceManager &SM = Ctx.getSourceManager();
    SourceLocation B = SM.getExpansionLoc(Last->getEndLoc());
    SourceLocation E = SM.getExpansionLoc(Next->getBeginLoc());
    if (B.isInvalid() || E.isInvalid() || !SM.isBeforeInTranslationUnit(B, E))
      return false;
    StringRef T = Lexer::getSourceText(CharSourceRange::getCharRange(B, E), SM,
                                       Ctx.getLangOpts());
    static const std::regex Re("fall[ -]?(s[ -]?)?thr(ough|u)",
                               std::regex::icase);
    return std::regex_search(T.begin(), T.end(), Re);
  }

  // Is the case group at SC just `break;` (`default: break;`)? Falling into
  // it runs nothing more.
  static bool onlyBreaks(const SwitchCase *SC) {
    const Stmt *Sub = SC->getSubStmt();
    while (const auto *Inner = dyn_cast<SwitchCase>(Sub))
      Sub = Inner->getSubStmt();
    if (const auto *CS = dyn_cast<CompoundStmt>(Sub))
      return CS->size() == 1 && isa<BreakStmt>(CS->body_front());
    return isa<BreakStmt>(Sub);
  }

  // Is S a call to a logging function (av_log, g_warning, ...)? A case
  // group that only logs a warning and falls into the next one warns before
  // shared handling. A printf is not one: printing a verdict and falling
  // into the opposite verdict is the CWE-484 example.
  static bool isLogCall(const Stmt *S) {
    const auto *E = dyn_cast<Expr>(S);
    const auto *CE = E ? dyn_cast<CallExpr>(E->IgnoreParenCasts()) : nullptr;
    if (!CE)
      return false;
    std::string N = StringRef(raptor::calleeName(CE)).lower();
    return StringRef(N).contains("log") || StringRef(N).contains("warn");
  }

  static bool hasFallthrough(const SwitchStmt *SW, ASTContext &Ctx) {
    const auto *Body = dyn_cast_or_null<CompoundStmt>(SW->getBody());
    if (!Body)
      return false;
    bool InGroup = false;
    const Stmt *Last = nullptr; // last statement of the current group
    bool OnlyLogs = false;      // every statement of the group logs
    for (const Stmt *S : Body->body()) {
      if (const auto *SC = dyn_cast<SwitchCase>(S)) {
        if (InGroup && Last && !isTerminator(Last) && !OnlyLogs &&
            !markedIntended(Last, SC, Ctx) && !onlyBreaks(SC))
          return true;
        InGroup = true;
        // case A: case B: stmt -> nested SwitchCases
        const Stmt *Sub = SC->getSubStmt();
        while (const auto *Inner = dyn_cast<SwitchCase>(Sub))
          Sub = Inner->getSubStmt();
        Last = isa<NullStmt>(Sub) ? nullptr : Sub;
        OnlyLogs = !Last || isLogCall(Last);
        continue;
      }
      // `X(a, b);` with a case macro ending in `break;`: the `;` is empty.
      if (InGroup && !isa<NullStmt>(S)) {
        Last = S;
        OnlyLogs = OnlyLogs && isLogCall(S);
      }
    }
    return false;
  }
};
} // namespace

RAPTOR_CHECKER(MissingBreakInSwitchChecker, "MissingBreakInSwitch",
               "Omitted break statement in switch (CWE-484)")
