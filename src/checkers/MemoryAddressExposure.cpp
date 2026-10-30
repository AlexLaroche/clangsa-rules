// raptor.MemoryAddressExposure: printf-like calls whose literal
// format string contains a %x, %X or %p conversion (semgrep regex
// `%\w*x`, `%\w*X`, `%\w*p`), which may leak memory addresses.
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/StringMap.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {
// Function name -> index of its format string argument.
const llvm::StringMap<unsigned> &formatFunctions() {
  static const llvm::StringMap<unsigned> M = [] {
    llvm::StringMap<unsigned> M;
    for (const char *F :
         {"printf", "vprintf", "wprintf", "vwprintf", "vcprintf", "vcwprintf",
          "vscprintf", "vscwprintf", "printk", "warn", "vwarn", "warnx",
          "vwarnx"})
      M[F] = 0;
    for (const char *F :
         {"fprintf", "vfprintf", "fwprintf", "vfwprintf", "sprintf",
          "vsprintf", "asprintf", "vasprintf", "dprintf", "vdprintf",
          "wsprintf", "syslog", "vsyslog", "err", "verr", "errx", "verrx",
          "warnc", "vwarnc"})
      M[F] = 1;
    for (const char *F :
         {"snprintf", "vsnprintf", "swprintf", "vswprintf", "errc", "verrc"})
      M[F] = 2;
    return M;
  }();
  return M;
}

bool isWordChar(uint32_t C) {
  return (C >= 'a' && C <= 'z') || (C >= 'A' && C <= 'Z') ||
         (C >= '0' && C <= '9') || C == '_';
}

// '%' followed by a run of word characters containing x, X or p.
bool exposesAddress(const StringLiteral *S) {
  unsigned N = S->getLength();
  for (unsigned I = 0; I < N; ++I) {
    if (S->getCodeUnit(I) != '%')
      continue;
    for (unsigned J = I + 1; J < N && isWordChar(S->getCodeUnit(J)); ++J) {
      uint32_t C = S->getCodeUnit(J);
      if (C == 'x' || C == 'X' || C == 'p')
        return true;
    }
  }
  return false;
}

class MemoryAddressExposureChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const auto &Funcs = formatFunctions();
    forEach<CallExpr>(D->getBody(), [&](const CallExpr *CE) {
      auto It = Funcs.find(raptor::calleeName(CE));
      if (It == Funcs.end() || CE->getNumArgs() <= It->second)
        return;
      const auto *S = dyn_cast<StringLiteral>(ign(CE->getArg(It->second)));
      if (!S || !exposesAddress(S))
        return;
      raptor::reportAt(
          BR, this, "Memory address exposure",
          "The software generates an error message that includes sensitive "
          "information about its environment, users, or associated data. In "
          "particular, exposure of memory addresses might defeat ASLR.",
          CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(MemoryAddressExposureChecker, "MemoryAddressExposure",
               "Format string that may expose memory addresses")
