// raptor.IncorrectUnsignedComparison: an unsigned variable compared
// with `< 0`, `<= 0` or `>= 0` (always false, `== 0`, always true).
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
// unsigned short/int/long (and size_t, long long): not unsigned char or bool
bool isUnsignedShortOrWider(ASTContext &C, QualType T) {
  T = T.getCanonicalType();
  const auto *BT = T->getAs<BuiltinType>();
  return BT && BT->isUnsignedInteger() && BT->getKind() != BuiltinType::Bool &&
         C.getIntWidth(T) >= C.getIntWidth(C.ShortTy);
}

class IncorrectUnsignedComparisonChecker
    : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &C = Mgr.getASTContext();
    auto M = binaryOperator(hasAnyOperatorName("<", "<=", ">="),
                            hasRHS(ignoringParenImpCasts(integerLiteral(equals(0)))))
                 .bind("cmp");
    for (const BoundNodes &N : match(findAll(M), *D->getBody(), C)) {
      const auto *BO = N.getNodeAs<BinaryOperator>("cmp");
      if (!isUnsignedShortOrWider(C, BO->getLHS()->IgnoreParenImpCasts()->getType()))
        continue;
      raptor::reportAt(BR, this, "Incorrect unsigned comparison",
                       "Checking if an unsigned variable is negative makes no "
                       "sense and is usually a good indication that something "
                       "is probably wrong with the code",
                       BO, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(IncorrectUnsignedComparisonChecker,
               "IncorrectUnsignedComparison",
               "Unsigned value compared with 0 as if it could be negative")
