// raptor.IncorrectUseOfMemset: memset()/memset_explicit() whose
// size is 0 (or '\0'), or whose fill byte is a sizeof(...) expression, i.e.
// the second and third arguments are likely swapped.
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {
bool isZeroLiteral(const Expr *E) {
  E = raptor::strip(E);
  if (const auto *I = dyn_cast_or_null<IntegerLiteral>(E))
    return I->getValue() == 0;
  if (const auto *C = dyn_cast_or_null<CharacterLiteral>(E))
    return C->getValue() == 0;
  return false;
}

bool isSizeof(const Expr *E) {
  const auto *U = dyn_cast_or_null<UnaryExprOrTypeTraitExpr>(raptor::strip(E));
  return U && U->getKind() == UETT_SizeOf;
}

class IncorrectUseOfMemsetChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    forEach<CallExpr>(D->getBody(), [&](const CallExpr *CE) {
      if (!raptor::isOneOf(raptor::calleeName(CE), {"memset", "memset_explicit"}) ||
          CE->getNumArgs() != 3)
        return;
      if (isZeroLiteral(CE->getArg(2)) || isSizeof(CE->getArg(1)))
        raptor::reportAt(
            BR, this, "Incorrect use of memset()",
            "The invocation of memset() is easy to get wrong. The second "
            "argument is the character and the third argument is the size, "
            "but sometimes these arguments are in the wrong order. This "
            "results in a no-op.",
            CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(IncorrectUseOfMemsetChecker, "IncorrectUseOfMemset",
               "memset() with swapped size and fill arguments")
