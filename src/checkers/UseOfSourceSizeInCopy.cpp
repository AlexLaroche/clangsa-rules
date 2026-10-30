// Port of raptor-use-of-source-size-in-copy: copy functions whose size is
// derived from the source buffer instead of the destination:
//  - $FUN($DST, $SRC, $LEN) with $SRC declared as `$_ $SRC[$LEN]` and $DST
//    not declared as `$_ $DST[$LEN]`;
//  - $FUN($DST, $SRC, <... $SRC ...>);
//  - snprintf-like $FUN($DST, <... $SRC ...>, ..., $SRC, ...).
// A string literal source is excluded, including (like semgrep's constant
// propagation) a variable initialized with a literal and never assigned.
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {
bool isCopyFunction(StringRef N) {
  return raptor::isOneOf(N, {"strncpy", "stpncpy", "strlcpy", "strscpy",
                             "memcpy", "memmove", "wmemcpy", "wmemmove",
                             "mempcpy", "wmempcpy"});
}

bool isPrintfFunction(StringRef N) {
  return raptor::isOneOf(N, {"snprintf", "vsnprintf", "swprintf", "vswprintf"});
}

// "..." or a variable holding a constant string literal.
bool isConstantString(const Expr *E, const Stmt *Body) {
  if (isStringLit(E))
    return true;
  const auto *DRE = dyn_cast<DeclRefExpr>(ign(E));
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  if (!VD || !VD->hasLocalStorage() || !isStringLit(VD->getInit()))
    return false;
  bool Assigned = false;
  forEach<BinaryOperator>(Body, [&](const BinaryOperator *BO) {
    if (BO->isAssignmentOp() && refDecl(BO->getLHS()) == VD)
      Assigned = true;
  });
  return !Assigned;
}

bool isLiteral(const Expr *E) {
  return isa<IntegerLiteral, CharacterLiteral, StringLiteral,
             FloatingLiteral>(ign(E));
}

class UseOfSourceSizeInCopyChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    const Stmt *Body = D->getBody();
    forEach<CallExpr>(Body, [&](const CallExpr *CE) {
      StringRef N = raptor::calleeName(CE);
      bool Bad = false;
      if (isCopyFunction(N) && CE->getNumArgs() == 3) {
        const Expr *Dst = CE->getArg(0), *Src = CE->getArg(1),
                   *Len = CE->getArg(2);
        if (!isConstantString(Src, Body))
          Bad = (declaredWithSize(Src, Len, Ctx) &&
                 !declaredWithSize(Dst, Len, Ctx)) ||
                containsExpr(Len, Src);
      } else if (isPrintfFunction(N) && CE->getNumArgs() >= 3) {
        for (unsigned I = 2; I < CE->getNumArgs() && !Bad; ++I)
          Bad = !isLiteral(CE->getArg(I)) &&
                containsExpr(CE->getArg(1), CE->getArg(I));
      }
      if (Bad)
        raptor::reportAt(
            BR, this, "Use of source size in copy",
            "The software uses the size of a source buffer when reading from "
            "or writing to a destination buffer, which may cause it to "
            "access memory that is outside of the bounds of the buffer.",
            CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(UseOfSourceSizeInCopyChecker, "UseOfSourceSizeInCopy",
               "Copy size derived from the source buffer")
