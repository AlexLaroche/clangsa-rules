// Port of raptor-write-into-stack-buffer: a non-static local array passed
// as the destination of a copy/format/read function. Syntactic, like the
// semgrep rule ($BUF must be the array itself, declared with a size).
#include "Common.h"
#include "Registry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/Support/Regex.h"

using namespace clang;
using namespace ento;

namespace {
// Buffer to buffer copy functions (buffer in 1st arg; a string literal
// source is fine).
bool isCopyFn(StringRef N) {
  return raptor::isOneOf(
      N, {"strcpy",   "strncpy",  "stpcpy",   "stpncpy", "strlcpy",
          "strscpy",  "wcscpy",   "wcsncpy",  "wcpcpy",  "wcpncpy",
          "wcslcpy",  "_mbscpy",  "_mbsncpy", "_mbpcpy", "_mbpncpy",
          "_mbslcpy", "strccpy",  "strcadd",  "streadd", "strecpy",
          "strcat",   "strncat",  "strlcat",  "wcscat",  "wcsncat",
          "wcslcat",  "_mbscat",  "_mbsncat", "_mbslcat", "memcpy",
          "memccpy",  "mempcpy",  "memmove",  "memset",  "wmemcpy",
          "wmempcpy", "wmemmove", "wmemset"});
}

// `$_ $BUF[$_];` not `static`: a sized local array with automatic storage.
bool isStackArray(const Expr *E) {
  const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  if (!VD || !VD->hasLocalStorage() || !VD->getTypeSourceInfo())
    return false;
  auto AT = VD->getTypeSourceInfo()->getTypeLoc().getAs<ArrayTypeLoc>();
  return AT && AT.getSizeExpr();
}

bool isStringLit(const Expr *E) {
  return isa<StringLiteral>(E->IgnoreParenImpCasts());
}

class Visitor : public RecursiveASTVisitor<Visitor> {
public:
  Visitor(BugReporter &BR, const CheckerBase *C, AnalysisDeclContext *ADC)
      : BR(BR), C(C), ADC(ADC) {}

  bool VisitCallExpr(CallExpr *CE) {
    StringRef N = raptor::calleeName(CE);
    unsigned NA = CE->getNumArgs();
    if (N.empty() || NA == 0)
      return true;
    auto Arg = [&](unsigned I) { return CE->getArg(I); };
    bool Bad = false;
    if (isCopyFn(N))
      Bad = isStackArray(Arg(0)) && !(NA > 1 && isStringLit(Arg(1)));
    else if (raptor::isOneOf(N, {"sprintf", "vsprintf"}))
      Bad = NA > 1 && isStackArray(Arg(0)) && riskyFormat(Arg(1));
    else if (raptor::isOneOf(N, {"snprintf", "vsnprintf", "swprintf",
                                 "vswprintf"}))
      Bad = NA > 2 && isStackArray(Arg(0)) && riskyFormat(Arg(2));
    else if (raptor::isOneOf(N, {"gets", "fgets", "getwd", "getcwd", "fread"}))
      Bad = isStackArray(Arg(0));
    else if (N == "bcopy")
      Bad = NA > 1 && isStackArray(Arg(1)) && !isStringLit(Arg(0));
    else if (raptor::isOneOf(N, {"read", "pread", "recv", "recvfrom"}))
      Bad = NA > 1 && isStackArray(Arg(1));
    if (Bad)
      raptor::reportAt(BR, C, "Write into stack buffer",
                       "The software directly writes into a stack buffer. "
                       "This might lead to a stack-based buffer overflow",
                       CE, ADC);
    return true;
  }

private:
  // metavariable-regex on the source text of $FMT (anchored at the start,
  // like semgrep's re.match).
  bool riskyFormat(const Expr *E) const {
    const SourceManager &SM = BR.getSourceManager();
    CharSourceRange R = CharSourceRange::getTokenRange(
        SM.getExpansionRange(E->getSourceRange()).getAsRange());
    StringRef Text = Lexer::getSourceText(R, SM, ADC->getASTContext().getLangOpts());
    static const llvm::Regex Re(
        "^(\".*%l?s.*\"|\".*%S.*\"|[a-zA-Z_][a-zA-Z0-9_]*)");
    return Re.match(Text);
  }

  BugReporter &BR;
  const CheckerBase *C;
  AnalysisDeclContext *ADC;
};

class WriteIntoStackBufferChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    Visitor(BR, this, Mgr.getAnalysisDeclContext(D))
        .TraverseStmt(D->getBody());
  }
};
} // namespace

RAPTOR_CHECKER(WriteIntoStackBufferChecker, "WriteIntoStackBuffer",
               "Direct write into a stack buffer")
