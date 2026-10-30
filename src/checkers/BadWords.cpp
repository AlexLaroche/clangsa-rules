// raptor.BadWords: words that suggest bugs,
// security issues or secrets. Like semgrep's generic mode, the regexes run
// over the raw text of the main file (comments and code alike).
#include "Common.h"
#include "Registry.h"
#include "clang/AST/Decl.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/Support/Regex.h"

using namespace clang;
using namespace ento;

namespace {
class BadWordsChecker : public Checker<check::ASTDecl<TranslationUnitDecl>> {
public:
  void checkASTDecl(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                    BugReporter &BR) const {
    static llvm::Regex Res[] = {
        llvm::Regex("(TODO|XXX|FIXME|BUG|HACK|LATER|CVE-)"),
        llvm::Regex("(unsafe|insecure|dangerous|warning|overflow)",
                    llvm::Regex::IgnoreCase),
        llvm::Regex("(password|private|token|secret)", llvm::Regex::IgnoreCase)};
    const SourceManager &SM = BR.getSourceManager();
    FileID FID = SM.getMainFileID();
    StringRef Text = SM.getBufferData(FID);
    SourceLocation Start = SM.getLocForStartOfFile(FID);

    size_t Off = 0;
    while (Off <= Text.size()) {
      size_t End = Text.find('\n', Off);
      if (End == StringRef::npos)
        End = Text.size();
      StringRef Line = Text.slice(Off, End);
      for (llvm::Regex &Re : Res) {
        llvm::SmallVector<StringRef, 2> M;
        if (!Re.match(Line, &M))
          continue;
        SourceLocation L = Start.getLocWithOffset(Off + (M[0].data() - Line.data()));
        BR.EmitBasicReport(TU, this, "Suspicious word", raptor::Category,
                           "The code contains '" + M[0].str() +
                               "', which may indicate a bug, a security issue, "
                               "or a hard-coded secret",
                           PathDiagnosticLocation(L, SM));
      }
      Off = End + 1;
    }
  }
};
} // namespace

RAPTOR_CHECKER(BadWordsChecker, "BadWords",
               "Comments and code that suggest bugs, security issues or secrets")
