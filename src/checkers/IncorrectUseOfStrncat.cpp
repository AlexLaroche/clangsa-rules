// raptor.IncorrectUseOfStrncat: strncat() whose size is the size
// of the whole destination buffer (array size, sizeof, strlen) or the space
// left without room for the NUL terminator.
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {
// sizeof($DST)
bool isSizeofOf(const Expr *E, const Expr *Dst) {
  const auto *U = dyn_cast_or_null<UnaryExprOrTypeTraitExpr>(ign(E));
  return U && U->getKind() == UETT_SizeOf && !U->isArgumentType() &&
         sameExpr(U->getArgumentExpr(), Dst);
}

// strlen($DST)
bool isStrlenOf(const Expr *E, const Expr *Dst) {
  const auto *CE = dyn_cast_or_null<CallExpr>(ign(E));
  return CE && raptor::calleeName(CE) == "strlen" && CE->getNumArgs() == 1 &&
         sameExpr(CE->getArg(0), Dst);
}

class IncorrectUseOfStrncatChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    forEach<CallExpr>(D->getBody(), [&](const CallExpr *CE) {
      if (raptor::calleeName(CE) != "strncat" || CE->getNumArgs() != 3)
        return;
      const Expr *Dst = CE->getArg(0), *Len = CE->getArg(2);
      const auto *Sub = dyn_cast<BinaryOperator>(ign(Len));
      bool Bad =
          declaredWithSize(Dst, Len, Ctx) || // $_ $DST[$LEN]; strncat($DST, $_, $LEN)
          isSizeofOf(Len, Dst) || isStrlenOf(Len, Dst) ||
          (Sub && Sub->getOpcode() == BO_Sub && isSizeofOf(Sub->getLHS(), Dst) &&
           isStrlenOf(Sub->getRHS(), Dst));
      if (Bad)
        raptor::reportAt(
            BR, this, "Incorrect use of strncat()",
            "The strncat() function is nearly as dangerous as strcat(), in "
            "that it's quite easy to misuse. The first common mistake is "
            "supplying the size of the entire buffer instead of the size "
            "remaining in the buffer. A more subtle mistake can be made: the "
            "size parameter needs to be the amount of space left in the "
            "buffer less one; otherwise, the NUL byte is written one byte "
            "past the end of the buffer.",
            CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(IncorrectUseOfStrncatChecker, "IncorrectUseOfStrncat",
               "strncat() with an incorrect size")
