// raptor.SuspiciousAssert: an assertion (macro or function whose
// name matches (?i)^\w*assert\w*\s*$) whose arguments contain a <, <=, > or
// >= comparison.
//
// The analyzer sees preprocessed code, so for macros we find every expansion
// of an assertion macro through the SourceManager's expansion chain and lex
// the arguments as written in the source. This also covers assertions
// compiled out with NDEBUG, whose arguments are gone from the AST.
#include "Common.h"
#include "Registry.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/Support/Regex.h"
#include <set>

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {

bool isAssertName(StringRef Name) {
  static const llvm::Regex RE("^[[:alnum:]_]*assert[[:alnum:]_]*[[:space:]]*$",
                              llvm::Regex::IgnoreCase);
  return RE.match(Name);
}

// Does the argument list of the macro invocation Call, as written in the
// source, contain a <, <=, > or >= token?
bool argsHaveRelationalOp(CharSourceRange Call, const SourceManager &SM,
                          const LangOptions &LO) {
  SourceLocation B = SM.getSpellingLoc(Call.getBegin()),
                 E = SM.getSpellingLoc(Call.getEnd());
  if (SM.getFileID(B) != SM.getFileID(E))
    return false;
  StringRef Text = Lexer::getSourceText(CharSourceRange::getTokenRange(B, E), SM, LO);
  Lexer L(B, LO, Text.begin(), Text.begin(), Text.end());
  Token Tok;
  bool InArgs = false;
  for (bool End = false; !End;) {
    End = L.LexFromRawLexer(Tok);
    InArgs |= Tok.is(tok::l_paren);
    if (InArgs && Tok.isOneOf(tok::less, tok::lessequal, tok::greater,
                              tok::greaterequal))
      return true;
  }
  return false;
}

class SuspiciousAssertChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = BR.getSourceManager();
    auto Rel = binaryOperator(hasAnyOperatorName("<", "<=", ">", ">="));
    std::set<unsigned> Seen; // one report per assertion invocation

    auto Report = [&](SourceLocation Loc, SourceRange R) {
      Loc = SM.getExpansionLoc(Loc);
      if (!Seen.insert(Loc.getRawEncoding()).second)
        return;
      PathDiagnosticLocation L(Loc, SM);
      BR.EmitBasicReport(D, this, "Suspicious assert", raptor::Category,
                         "Most codebases define assertion macros which "
                         "compile to a no-op on non-debug builds. If "
                         "assertions are the only line of defense against "
                         "untrusted input, the software may be exposed to "
                         "attacks that leverage the lack of proper input "
                         "checks",
                         L, SM.getExpansionRange(R).getAsRange());
    };

    // assertion macros: $ASSERT(..., <... $_ < $_ ...>, ...)
    std::set<unsigned> Lexed; // macro invocations already lexed
    for (const BoundNodes &N : match(findAll(stmt().bind("s")), *D->getBody(), Ctx)) {
      SourceLocation Loc = N.getNodeAs<Stmt>("s")->getBeginLoc();
      for (; Loc.isMacroID(); Loc = SM.getImmediateMacroCallerLoc(Loc)) {
        if (SM.isMacroArgExpansion(Loc))
          continue;
        StringRef Name = Lexer::getImmediateMacroName(Loc, SM, Ctx.getLangOpts());
        if (!isAssertName(Name))
          continue;
        CharSourceRange Call = SM.getImmediateExpansionRange(Loc);
        if (!Lexed.insert(Call.getBegin().getRawEncoding()).second)
          break;
        if (argsHaveRelationalOp(Call, SM, Ctx.getLangOpts()))
          Report(Call.getBegin(), Call.getAsRange());
        break;
      }
    }

    // assertion functions: $ASSERT(..., <... $_ < $_ ...>, ...)
    auto Call = callExpr(callee(functionDecl()),
                         hasAnyArgument(anyOf(Rel, hasDescendant(Rel))))
                    .bind("call");
    for (const BoundNodes &N : match(findAll(Call), *D->getBody(), Ctx)) {
      const auto *CE = N.getNodeAs<CallExpr>("call");
      SourceLocation B = CE->getBeginLoc();
      // a call spelled in a macro body is not visible to semgrep
      if (isAssertName(raptor::calleeName(CE)) &&
          (!B.isMacroID() || SM.isMacroArgExpansion(B)))
        Report(CE->getBeginLoc(), CE->getSourceRange());
    }
  }
};
} // namespace

RAPTOR_CHECKER(SuspiciousAssertChecker, "SuspiciousAssert",
               "Assertion used as the only check on untrusted input (CWE-754)")
