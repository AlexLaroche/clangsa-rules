// raptor.PointerSubtraction: a pointer subtracted from another
// pointer (the semgrep rule matches subtractions of two variables declared as
// pointers, which is every pointer difference once real types are known).
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
class PointerSubtractionChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    auto M = binaryOperator(hasOperatorName("-"),
                            hasLHS(hasType(pointerType())),
                            hasRHS(hasType(pointerType())))
                 .bind("sub");
    for (const BoundNodes &N : match(findAll(M), *D->getBody(), Mgr.getASTContext()))
      raptor::reportAt(BR, this, "Pointer subtraction",
                       "The software subtracts one pointer from another in "
                       "order to determine size, but this calculation can be "
                       "incorrect if the pointers do not exist in the same "
                       "memory chunk",
                       N.getNodeAs<BinaryOperator>("sub"),
                       Mgr.getAnalysisDeclContext(D));
  }
};
} // namespace

RAPTOR_CHECKER(PointerSubtractionChecker, "PointerSubtraction",
               "Pointer subtraction used to determine a size")
