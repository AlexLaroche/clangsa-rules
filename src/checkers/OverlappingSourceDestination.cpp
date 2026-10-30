// Port of raptor-overlapping-source-destination: copy/concatenation
// functions (and sprintf/snprintf) whose destination is also a source.
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {
bool isCopyFunction(StringRef N) {
  return raptor::isOneOf(
      N, {// strcpy
          "strcpy", "strncpy", "stpcpy", "stpncpy", "strlcpy", "strscpy",
          "wcscpy", "wcsncpy", "wcpcpy", "wcpncpy", "wcslcpy", "_mbscpy",
          "_mbsncpy", "_mbpcpy", "_mbpncpy", "_mbslcpy", "strccpy", "strcadd",
          "streadd", "strecpy",
          // strcat
          "strcat", "strncat", "strlcat", "wcscat", "wcsncat", "wcslcat",
          "_mbscat", "_mbsncat", "_mbslcat",
          // memcpy
          "memcpy", "memccpy", "wmemcpy", "mempcpy", "wmempcpy",
          // bcopy
          "bcopy"});
}

class OverlappingSourceDestinationChecker
    : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    forEach<CallExpr>(D->getBody(), [&](const CallExpr *CE) {
      StringRef N = raptor::calleeName(CE);
      unsigned NArgs = CE->getNumArgs();
      bool Overlap = false;
      if (isCopyFunction(N)) {
        // $FUN($DST, $DST, ...)
        Overlap = NArgs >= 2 && sameExpr(CE->getArg(0), CE->getArg(1));
      } else if (N == "sprintf" || N == "snprintf") {
        // sprintf($DST, ..., $DST, ...) / snprintf($DST, $_, ..., $DST, ...)
        for (unsigned I = N == "sprintf" ? 1 : 2; I < NArgs && !Overlap; ++I)
          Overlap = sameExpr(CE->getArg(0), CE->getArg(I));
      }
      if (Overlap)
        raptor::reportAt(
            BR, this, "Overlapping source and destination",
            "C standards specify that the results are undefined if a call to "
            "copy functions, with the exception of memmove(), would cause "
            "copying to take place between objects that overlap (e.g., if "
            "the target string array and one of the supplied input arguments "
            "refer to the same buffer).",
            CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(OverlappingSourceDestinationChecker,
               "OverlappingSourceDestination",
               "Copy with overlapping source and destination")
