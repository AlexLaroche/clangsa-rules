// Port of raptor-suspicious-assert: an assertion (macro or function whose
// name matches (?i)^\w*assert\w*\s*$) whose arguments contain a <, <=, > or
// >= comparison.
//
// The analyzer sees preprocessed code, so for macros we look for relational
// operators written in a macro argument and recover the macro names from
// the SourceManager's expansion chain.
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
    for (const BoundNodes &N :
         match(findAll(Rel.bind("op")), *D->getBody(), Ctx)) {
      SourceLocation Loc = N.getNodeAs<BinaryOperator>("op")->getOperatorLoc();
      // walk up through every macro whose argument contains the operator
      while (Loc.isMacroID()) {
        if (SM.isMacroArgExpansion(Loc)) {
          StringRef Name = Lexer::getImmediateMacroName(Loc, SM,
                                                        Ctx.getLangOpts());
          if (isAssertName(Name)) {
            Report(Loc, SourceRange(Loc));
            break;
          }
        }
        Loc = SM.getImmediateMacroCallerLoc(Loc);
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
