// Port of raptor-signed-unsigned-conversion: a signed integer (int, off_t) is
// assigned/returned to an unsigned one (unsigned, size_t) or passed as the
// size argument of a memory/string API, or an unsigned integer is
// assigned/returned to a signed integer of the same or smaller width.
#include "IntegerConversion.h"
#include "Registry.h"

using namespace clang;
using namespace ento;
using namespace raptor_int;

namespace {
constexpr const char *BugName = "Signed/unsigned conversion";
constexpr const char *BugMsg =
    "The software uses a signed primitive and performs a cast to an unsigned "
    "primitive, or uses an unsigned primitive and performs a cast to a signed "
    "primitive, which can produce an unexpected value";

// The rule's types are int, unsigned, size_t and off_t: no char or short.
bool isIntOrWider(ASTContext &C, QualType T) {
  return isPlainInt(T) && C.getIntWidth(T) >= C.getIntWidth(C.IntTy);
}

bool signedToUnsigned(ASTContext &C, QualType Dest, QualType Src) {
  return !Src.isNull() && isIntOrWider(C, Dest) && isIntOrWider(C, Src) &&
         Dest->isUnsignedIntegerType() && Src->isSignedIntegerType();
}

bool unsignedToSigned(ASTContext &C, QualType Dest, QualType Src) {
  return !Src.isNull() && isIntOrWider(C, Dest) && isIntOrWider(C, Src) &&
         Dest->isSignedIntegerType() && Src->isUnsignedIntegerType() &&
         C.getIntWidth(Dest) <= C.getIntWidth(Src);
}

bool converts(ASTContext &C, QualType Dest, QualType Src) {
  return signedToUnsigned(C, Dest, Src) || unsignedToSigned(C, Dest, Src);
}

// Size arguments: function, argument index, number of arguments (negative:
// at least -N, for variadic patterns like `snprintf($_, (int $_), ...)`).
struct SizeArg {
  StringRef Fun;
  unsigned Idx;
  int NArgs;
};
const SizeArg SizeArgs[] = {
    {"strncpy", 2, 3},   {"stpncpy", 2, 3},   {"strncat", 2, 3},
    {"strlcpy", 2, 3},   {"strscpy", 2, 3},   {"strlcat", 2, 3},
    {"snprintf", 1, -2}, {"vsnprintf", 1, -2}, {"swprintf", 1, -2},
    {"vswprintf", 1, -2}, {"getcwd", 1, 2},   {"memcpy", 2, 3},
    {"mempcpy", 2, 3},   {"memccpy", 3, 4},   {"memmove", 2, 3},
    {"memset", 2, 3},    {"bcopy", 2, 3},     {"alloca", 0, 1},
    {"__builtin_alloca", 0, 1}, // glibc's alloca() macro
    {"malloc", 0, 1},    {"calloc", 1, 2},    {"calloc", 0, 2},
    {"realloc", 1, 2},   {"read", 2, 3},      {"recv", 2, 4},
    {"recvfrom", 2, -5}, {"fread", 1, 4},
};

class SignedUnsignedConversionChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &C = Mgr.getASTContext();
    AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(D);

    // (unsigned $_) = <... (int $_) ...> and the opposite direction
    AssignmentVisitor V;
    V.OnAssign = [&](QualType Dest, const Expr *RHS, const Stmt *S) {
      if (converts(C, Dest, effectiveType(C, RHS, true)))
        raptor::reportAt(BR, this, BugName, BugMsg, S, ADC);
    };
    V.OnInit = [&](QualType Dest, const Expr *Init, const VarDecl *,
                   const DeclStmt *DS) {
      if (converts(C, Dest, effectiveType(C, Init, true)))
        raptor::reportAt(BR, this, BugName, BugMsg, DS, ADC);
    };
    V.TraverseStmt(D->getBody());

    // memcpy($_, $_, (int $_)) and friends
    using namespace ast_matchers;
    for (const BoundNodes &N :
         match(findAll(callExpr().bind("call")), *D->getBody(), C)) {
      const auto *CE = N.getNodeAs<CallExpr>("call");
      StringRef Fun = raptor::calleeName(CE);
      int NArgs = CE->getNumArgs();
      for (const SizeArg &A : SizeArgs) {
        if (A.Fun != Fun ||
            (A.NArgs >= 0 ? NArgs != A.NArgs : NArgs < -A.NArgs))
          continue;
        QualType Src = effectiveType(C, CE->getArg(A.Idx), false);
        if (!Src.isNull() && isIntOrWider(C, Src) &&
            Src->isSignedIntegerType()) {
          raptor::reportAt(BR, this, BugName, BugMsg, CE, ADC);
          break;
        }
      }
    }

    // unsigned $FUN(...) { ... return (int $_); } and the opposite direction
    const auto *FD = dyn_cast<FunctionDecl>(D);
    if (!FD)
      return;
    QualType Ret = FD->getReturnType();
    bool Found = false;
    forEachReturn(D->getBody(), [&](const ReturnStmt *RS) {
      if (RS->getRetValue() &&
          converts(C, Ret, effectiveType(C, RS->getRetValue(), false)))
        Found = true;
    });
    if (Found)
      reportAtFunctionName(BR, this, BugName, BugMsg, FD);
  }
};
} // namespace

RAPTOR_CHECKER(SignedUnsignedConversionChecker, "SignedUnsignedConversion",
               "Signed to unsigned (or unsigned to signed) integer conversion")
