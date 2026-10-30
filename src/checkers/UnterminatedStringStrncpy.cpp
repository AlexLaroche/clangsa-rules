// Port of raptor-unterminated-string-strncpy: strncpy() and friends that are
// not followed by an explicit NUL termination of the destination
// ($DST[$_] = NULL, '\0' or 0) later in the same block.
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {
// NULL, '\0' or 0
bool isNul(const Expr *E) {
  E = raptor::strip(E);
  if (isa<GNUNullExpr, CXXNullPtrLiteralExpr>(E))
    return true;
  if (const auto *I = dyn_cast<IntegerLiteral>(E))
    return I->getValue() == 0;
  if (const auto *C = dyn_cast<CharacterLiteral>(E))
    return C->getValue() == 0;
  return false;
}

class UnterminatedStringStrncpyChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(D);
    const ParentMap &PM = ADC->getParentMap();
    const SourceManager &SM = BR.getSourceManager();
    forEach<CallExpr>(D->getBody(), [&](const CallExpr *CE) {
      if (!raptor::isOneOf(raptor::calleeName(CE),
                           {"strncpy", "stpncpy", "wcsncpy", "wcpncpy",
                            "_mbsncpy"}))
        return;
      // pattern-not-inside: $FUN($DST, $_, $_); ... $DST[$_] = <NUL>;
      if (CE->getNumArgs() == 3)
        if (const CompoundStmt *Block = enclosingBlock(CE, PM)) {
          bool Terminated = false;
          forEach<BinaryOperator>(Block, [&](const BinaryOperator *BO) {
            const auto *AS = dyn_cast<ArraySubscriptExpr>(ign(BO->getLHS()));
            if (!Terminated && BO->getOpcode() == BO_Assign && AS &&
                isAfter(BO, CE, SM) && isNul(BO->getRHS()) &&
                sameExpr(AS->getBase(), CE->getArg(0)))
              Terminated = true;
          });
          if (Terminated)
            return;
        }
      raptor::reportAt(
          BR, this, "Unterminated string after strncpy()",
          "If there is no NUL character byte in the first n bytes of the "
          "source string, strncpy() and stpncpy() do not NUL-terminate the "
          "destination buffer. If the program does not explicitly terminate "
          "the destination buffer, this will almost certainly result in "
          "information disclosure, and possibly a buffer overflow condition.",
          CE, ADC);
    });
  }
};
} // namespace

RAPTOR_CHECKER(UnterminatedStringStrncpyChecker, "UnterminatedStringStrncpy",
               "strncpy() destination not NUL-terminated")
