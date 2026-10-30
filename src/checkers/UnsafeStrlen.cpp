// raptor.UnsafeStrlen: the result of strlen() and friends stored in
// a (signed or unsigned) short, which is easy to overflow.
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {
bool isShort(QualType T) {
  T = T.getCanonicalType();
  return T->isSpecificBuiltinType(BuiltinType::Short) ||
         T->isSpecificBuiltinType(BuiltinType::UShort);
}

bool isStrlenCall(const Expr *E) {
  const auto *CE = dyn_cast_or_null<CallExpr>(raptor::strip(E));
  return CE && raptor::isOneOf(raptor::calleeName(CE),
                               {"strlen", "lstrlen", "strnlen", "wcslen",
                                "wcsnlen"});
}

class UnsafeStrlenChecker : public Checker<check::ASTCodeBody> {
  void report(const Stmt *S, AnalysisManager &Mgr, BugReporter &BR,
              const Decl *D) const {
    raptor::reportAt(
        BR, this, "Unsafe strlen() result in a short",
        "The software performs a calculation that can produce an integer "
        "overflow or wraparound, when the logic assumes that the resulting "
        "value will always be larger than the original value. When "
        "influenced by the size of an input it is often easier to overflow "
        "a short than an int.",
        S, Mgr.getAnalysisDeclContext(D));
  }

public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    // (short $_) = $FUN(...)
    forEach<BinaryOperator>(D->getBody(), [&](const BinaryOperator *BO) {
      if (BO->getOpcode() == BO_Assign && isShort(BO->getLHS()->getType()) &&
          isStrlenCall(BO->getRHS()))
        report(BO, Mgr, BR, D);
    });
    // short $_ = $FUN(...);
    forEach<DeclStmt>(D->getBody(), [&](const DeclStmt *DS) {
      for (const Decl *X : DS->decls())
        if (const auto *VD = dyn_cast<VarDecl>(X))
          if (isShort(VD->getType()) && isStrlenCall(VD->getInit()))
            report(DS, Mgr, BR, D);
    });
  }
};
} // namespace

RAPTOR_CHECKER(UnsafeStrlenChecker, "UnsafeStrlen",
               "strlen() result stored in a short")
