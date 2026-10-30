// raptor.FormatStringBugs: printf/scanf/syslog/err-like calls
// whose format argument is not a string literal (nor a gettext() family
// call returning a translated literal).
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
          "vscprintf", "vscwprintf", "printk", "scanf", "__isoc99_scanf",
          "vscanf", "__isoc99_vscanf", "wscanf", "vwscanf", "warn", "vwarn",
          "warnx", "vwarnx"})
      M[F] = 0;
    for (const char *F :
         {"fprintf", "vfprintf", "fwprintf", "vfwprintf", "sprintf",
          "vsprintf", "asprintf", "vasprintf", "dprintf", "vdprintf",
          "wsprintf", "fscanf", "__isoc99_fscanf", "vfscanf",
          "__isoc99_vfscanf", "fwscanf", "vfwscanf", "sscanf",
          "__isoc99_sscanf", "vsscanf", "__isoc99_vsscanf", "swscanf",
          "vswscanf", "syslog", "vsyslog", "err", "verr", "errx", "verrx",
          "warnc", "vwarnc"})
      M[F] = 1;
    for (const char *F :
         {"snprintf", "vsnprintf", "swprintf", "vswprintf", "errc", "verrc"})
      M[F] = 2;
    return M;
  }();
  return M;
}

// A local variable (static or not) initialized with a string literal and never
// assigned in the function body: semgrep's constant propagation treats it as
// the literal itself.
bool isConstantStringVar(const Expr *E, const Stmt *Body) {
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  if (!VD || !VD->isLocalVarDecl() || !VD->getInit() ||
      !isa<StringLiteral>(ign(VD->getInit())))
    return false;
  bool Assigned = false;
  forEach<BinaryOperator>(Body, [&](const BinaryOperator *BO) {
    if (BO->isAssignmentOp())
      if (const auto *L = dyn_cast<DeclRefExpr>(ign(BO->getLHS())))
        Assigned |= L->getDecl() == VD;
  });
  return !Assigned;
}

// "...", c ? "..." : "...", a gettext() call, or a constant string variable.
bool isSafeFormat(const Expr *E, const Stmt *Body) {
  E = ign(E);
  if (isa<StringLiteral>(E))
    return true;
  if (const auto *CO = dyn_cast<ConditionalOperator>(E))
    return isSafeFormat(CO->getTrueExpr(), Body) &&
           isSafeFormat(CO->getFalseExpr(), Body);
  if (const auto *CE = dyn_cast<CallExpr>(E))
    return raptor::isOneOf(raptor::calleeName(CE),
                           {"gettext", "dgettext", "dcgettext"});
  return isConstantStringVar(E, Body);
}

class FormatStringBugsChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const auto &Funcs = formatFunctions();
    forEach<CallExpr>(D->getBody(), [&](const CallExpr *CE) {
      auto It = Funcs.find(raptor::calleeName(CE));
      if (It == Funcs.end() || CE->getNumArgs() <= It->second ||
          isSafeFormat(CE->getArg(It->second), D->getBody()))
        return;
      raptor::reportAt(
          BR, this, "Format string bug",
          "The software uses a function that accepts a format string as an "
          "argument, but the format string originates from an external "
          "source. This can lead to buffer overflows, denial of service, or "
          "data representation problems.",
          CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(FormatStringBugsChecker, "FormatStringBugs",
               "Format string not a string literal")
