// raptor.BadWords: words that suggest bugs,
// security issues or secrets. Like semgrep's generic mode, the regexes run
// over the raw text of the main file (comments and code alike).
//
// Noise cuts (httpd h2_mplx.c triage, 2026-11-12):
//   - a marker word (TODO, XXX, FIXME, BUG, HACK, LATER) must stand alone, not
//     be part of an identifier: `BUG` in `APLOG_DEBUG` / `AP_DEBUG_ASSERT` is
//     not reported; `CVE-` is matched anywhere;
//   - a risk word (unsafe, warning, overflow...) inside an ALL_CAPS constant
//     with an underscore (`APLOG_WARNING`, `LOG_WARNING`) is skipped and the
//     rest of the line is searched;
//   - `#include` / `#import` lines are skipped: a header name
//     (`h2_private.h`) is neither a secret nor a code smell.
#include "Common.h"
#include "Registry.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/CharInfo.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/Regex.h"

using namespace clang;
using namespace ento;

namespace {
bool isIdent(char C) { return isAlphanumeric(C) || C == '_'; }

// The identifier around [B, E) in L is a macro or enum constant: all
// capitals, digits and underscores, with at least one underscore.
bool inMacroConstant(StringRef L, size_t B, size_t E) {
  while (B > 0 && isIdent(L[B - 1]))
    --B;
  while (E < L.size() && isIdent(L[E]))
    ++E;
  StringRef T = L.slice(B, E);
  return T.contains('_') &&
         llvm::all_of(T, [](char C) { return isUppercase(C) || isDigit(C) || C == '_'; });
}

class BadWordsChecker : public Checker<check::ASTDecl<TranslationUnitDecl>> {
public:
  void checkASTDecl(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                    BugReporter &BR) const {
    static llvm::Regex Markers(
        "(^|[^A-Za-z0-9_])(TODO|XXX|FIXME|BUG|HACK|LATER)([^A-Za-z0-9_]|$)|(CVE-)");
    static llvm::Regex Risky("(unsafe|insecure|dangerous|warning|overflow)",
                             llvm::Regex::IgnoreCase);
    static llvm::Regex Secrets("(password|private|token|secret)", llvm::Regex::IgnoreCase);
    static llvm::Regex Include("^[ \t]*#[ \t]*(include|import)[ \t]*[<\"]");
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
      auto Report = [&](StringRef W) {
        SourceLocation L = Start.getLocWithOffset(Off + (W.data() - Line.data()));
        BR.EmitBasicReport(TU, this, "Suspicious word", raptor::Category,
                           "The code contains '" + W.str() +
                               "', which may indicate a bug, a security issue, "
                               "or a hard-coded secret",
                           PathDiagnosticLocation(L, SM));
      };
      if (!Include.match(Line)) {
        llvm::SmallVector<StringRef, 5> M;
        if (Markers.match(Line, &M))
          Report(!M[2].empty() ? M[2] : M[4]);
        for (StringRef Rest = Line; Risky.match(Rest, &M);) {
          size_t B = M[0].data() - Line.data(), E = B + M[0].size();
          if (!inMacroConstant(Line, B, E)) {
            Report(M[0]);
            break;
          }
          Rest = Line.drop_front(E);
        }
        if (Secrets.match(Line, &M))
          Report(M[0]);
      }
      Off = End + 1;
    }
  }
};
} // namespace

RAPTOR_CHECKER(BadWordsChecker, "BadWords",
               "Comments and code that suggest bugs, security issues or secrets")
