// Port of raptor-insecure-api-scanf: scanf() family calls whose format, as
// written, contains %s/%ls/%S or is not a string literal, excluding the
// sscanf() variants that read from a constant string.
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
class InsecureApiScanfChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    raptor::api::forEachCall(D, Mgr, [&](const CallExpr *CE) {
      std::string Name = raptor::api::calleeAsWritten(CE, Ctx);
      unsigned FmtIdx;
      if (raptor::isOneOf(Name, {"scanf", "__isoc99_scanf", "vscanf",
                                 "__isoc99_vscanf", "wscanf", "vwscanf"}))
        FmtIdx = 0;
      else if (raptor::isOneOf(Name, {"fscanf", "__isoc99_fscanf", "vfscanf",
                                      "__isoc99_vfscanf", "fwscanf",
                                      "vfwscanf"}))
        FmtIdx = 1;
      else if (raptor::isOneOf(Name, {"sscanf", "__isoc99_sscanf", "vsscanf",
                                      "__isoc99_vsscanf", "swscanf",
                                      "vswscanf"})) {
        FmtIdx = 1;
        // exclude string literals as source
        if (CE->getNumArgs() > FmtIdx &&
            raptor::api::isConstantString(CE->getArg(0), D->getBody(), Ctx))
          return;
      } else
        return;
      if (CE->getNumArgs() <= FmtIdx ||
          !raptor::api::regexMatchesAtStart(
              raptor::api::textAsWritten(CE->getArg(FmtIdx), Ctx),
              raptor::api::unsafeFormatRegex()))
        return;
      raptor::reportAt(BR, this, "Potential buffer overflow in scanf()",
                       "A buffer overflow condition exists when a program "
                       "attempts to put more data in a buffer than it can hold",
                       CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(InsecureApiScanfChecker, "InsecureApiScanf",
               "Use of scanf() family functions with unbounded %s")
