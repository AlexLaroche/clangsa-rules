// raptor.IncorrectOrderSetuidSetgid: privileges are dropped in the
// wrong order within a function, so group privileges (or saved root) may be
// regained afterwards:
//   setuid(x)  ... setgid()     (x != 0)
//   seteuid(x) ... setegid()    (x != 0, no seteuid(0) in between)
//   seteuid(x) ... setuid()     (x != 0, no seteuid(0) in between)
//   seteuid(x) ... seteuid(y)   (x, y != 0, no seteuid(0) in between)
// Like semgrep's `A; ... B;`, "later" means later in the function body.
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
bool isZeroArg(const CallExpr *CE) {
  if (CE->getNumArgs() != 1)
    return false;
  const auto *IL = dyn_cast<IntegerLiteral>(raptor::strip(CE->getArg(0)));
  return IL && IL->getValue() == 0;
}

class IncorrectOrderSetuidSetgidChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();
    auto M = callExpr(callee(functionDecl(
                          hasAnyName("setuid", "setgid", "seteuid", "setegid"))))
                 .bind("call");
    std::vector<const CallExpr *> Calls;
    for (const BoundNodes &N : match(findAll(M), *D->getBody(), Ctx))
      Calls.push_back(N.getNodeAs<CallExpr>("call"));
    llvm::sort(Calls, [&](const CallExpr *A, const CallExpr *B) {
      return SM.isBeforeInTranslationUnit(A->getBeginLoc(), B->getBeginLoc());
    });

    for (size_t I = 0; I < Calls.size(); ++I) {
      const CallExpr *A = Calls[I];
      StringRef AN = raptor::calleeName(A);
      if ((AN != "setuid" && AN != "seteuid") || isZeroArg(A))
        continue;
      for (size_t J = I + 1; J < Calls.size(); ++J) {
        const CallExpr *B = Calls[J];
        StringRef BN = raptor::calleeName(B);
        if (AN == "seteuid" && BN == "seteuid" && isZeroArg(B))
          break; // seteuid(0) in between: privileges are regained first
        bool Bad = (AN == "setuid" && BN == "setgid") ||
                   (AN == "seteuid" &&
                    (BN == "setegid" || BN == "setuid" || BN == "seteuid"));
        if (!Bad)
          continue;
        raptor::reportAt(BR, this, "Incorrect order of setuid() and setgid()",
                         AN.str() + "() is called before " + BN.str() +
                             "(): once the user ID is dropped the process may "
                             "no longer be able to drop its group privileges, "
                             "or may regain them",
                         A, Mgr.getAnalysisDeclContext(D));
        break;
      }
    }
  }
};
} // namespace

RAPTOR_CHECKER(IncorrectOrderSetuidSetgidChecker, "IncorrectOrderSetuidSetgid",
               "Privileges dropped in the wrong order")
