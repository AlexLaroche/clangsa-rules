// raptor.IncorrectOrderSetuidSetgid: privileges are dropped in the
// wrong order within a function, so group privileges (or saved root) may be
// regained afterwards:
//   setuid(x)  ... setgid()     (x != 0)
//   seteuid(x) ... setegid()    (x != 0, no seteuid(0) in between)
//   seteuid(x) ... setuid()     (x != 0, no seteuid(0) in between)
//   seteuid(x) ... seteuid(y)   (x, y != 0, no seteuid(0) in between)
// Like semgrep's `A; ... B;`, "later" means later in the function body.
// A variable saved from geteuid()/getuid() counts as 0 (the end of a
// temporary switch), and a call in the failure branch of A (`if (seteuid(u)
// < 0) setegid(egid);`) runs with the ID unchanged.
#include "Common.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
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

// The argument restores privileges: 0, or a variable saved from
// geteuid()/getuid() in the function (`uid_t euid = geteuid(); ...
// seteuid(euid);` ends a temporary switch).
bool isRegainArg(const CallExpr *CE, const Stmt *Body) {
  if (isZeroArg(CE))
    return true;
  if (CE->getNumArgs() != 1)
    return false;
  const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(CE->getArg(0)));
  const auto *V = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  if (!V)
    return false;
  auto saved = [](const Expr *E) {
    const auto *C = dyn_cast_or_null<CallExpr>(raptor::strip(E));
    return C && raptor::isOneOf(raptor::calleeName(C), {"geteuid", "getuid"});
  };
  if (saved(V->getInit()))
    return true;
  bool Yes = false;
  std::function<void(const Stmt *)> Walk = [&](const Stmt *S) {
    if (!S)
      return;
    if (const auto *BO = dyn_cast<BinaryOperator>(S); BO && BO->getOpcode() == BO_Assign)
      if (const auto *L = dyn_cast<DeclRefExpr>(raptor::strip(BO->getLHS()));
          L && L->getDecl() == V && saved(BO->getRHS()))
        Yes = true;
    for (const Stmt *C : S->children())
      Walk(C);
  };
  Walk(Body);
  return Yes;
}

// Is B in the branch taken when A fails (`if (seteuid(u) < 0) { B; }`)?
// The ID did not change there.
bool inFailureBranch(const CallExpr *A, const CallExpr *B, ParentMap &PM) {
  for (const Stmt *P = PM.getParent(A); P; P = PM.getParent(P)) {
    const auto *If = dyn_cast<IfStmt>(P);
    if (!If)
      continue;
    bool InCond = false;
    for (const Stmt *Q = A; Q && Q != If; Q = PM.getParent(Q))
      InCond |= Q == If->getCond();
    if (!InCond)
      return false;
    for (const Stmt *Q = B; Q; Q = PM.getParent(Q))
      if (Q == If->getThen())
        return true;
    return false;
  }
  return false;
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
    ParentMap PM(D->getBody());
    llvm::sort(Calls, [&](const CallExpr *A, const CallExpr *B) {
      return SM.isBeforeInTranslationUnit(A->getBeginLoc(), B->getBeginLoc());
    });

    for (size_t I = 0; I < Calls.size(); ++I) {
      const CallExpr *A = Calls[I];
      StringRef AN = raptor::calleeName(A);
      if ((AN != "setuid" && AN != "seteuid") || isRegainArg(A, D->getBody()))
        continue;
      for (size_t J = I + 1; J < Calls.size(); ++J) {
        const CallExpr *B = Calls[J];
        StringRef BN = raptor::calleeName(B);
        if (AN == "seteuid" && BN == "seteuid" && isRegainArg(B, D->getBody()))
          break; // seteuid(0) in between: privileges are regained first
        if (inFailureBranch(A, B, PM))
          continue;
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
