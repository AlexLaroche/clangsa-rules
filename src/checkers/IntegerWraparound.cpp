// Port of raptor-integer-wraparound:
//  1. an allocation size computed with * or + (directly in the argument, or
//     assigned to the size variable earlier in the function), which can wrap
//     around and allocate a buffer smaller than intended;
//  2. bounds checks like `x > MAX || (x + n) > MAX` (and the && / * forms),
//     where the second comparison is defeated by the very wraparound it is
//     meant to catch.
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
bool isOneOfOp(BinaryOperatorKind K);
bool isMulOrAdd(const Expr *E) {
  E = E->IgnoreParenImpCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) // includes `*=` and `+=`
    return isOneOfOp(BO->getOpcode()) || BO->getOpcode() == BO_MulAssign ||
           BO->getOpcode() == BO_AddAssign;
  return false;
}

bool isOneOfOp(BinaryOperatorKind K) { return K == BO_Mul || K == BO_Add; }

// The allocator called by CE, also through casts like `(*(code *)malloc)(n)`
// as found in decompiled code.
StringRef allocatorName(const CallExpr *CE) {
  if (StringRef N = raptor::calleeName(CE); !N.empty())
    return N;
  const Expr *E = CE->getCallee();
  while (true) {
    E = E->IgnoreParenCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(E); UO && UO->getOpcode() == UO_Deref)
      E = UO->getSubExpr();
    else
      break;
  }
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    if (const IdentifierInfo *II = DRE->getDecl()->getIdentifier())
      return II->getName();
  return "";
}

bool sameExpr(const Expr *A, const Expr *B, const ASTContext &Ctx) {
  llvm::FoldingSetNodeID IA, IB;
  A->IgnoreParenImpCasts()->Profile(IA, Ctx, /*Canonical=*/true);
  B->IgnoreParenImpCasts()->Profile(IB, Ctx, /*Canonical=*/true);
  return IA == IB;
}

// Size argument positions per allocator, as in the semgrep rule
std::vector<unsigned> sizeArgs(StringRef Name) {
  if (raptor::isOneOf(Name, {"malloc", "valloc"}))
    return {0};
  if (Name == "calloc")
    return {0, 1};
  if (raptor::isOneOf(Name, {"realloc", "reallocf", "aligned_alloc", "VirtualAlloc"}))
    return {1};
  return {};
}

class IntegerWraparoundChecker : public Checker<check::ASTCodeBody> {
  void checkAllocations(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();

    // `n = a * b;`, `n += b;`, `size_t n = a + b;` ... -> where n was computed
    llvm::DenseMap<const VarDecl *, llvm::SmallVector<SourceLocation, 2>> Computed;
    auto Assign = binaryOperator(isAssignmentOperator(),
                                 hasLHS(ignoringParenImpCasts(
                                     declRefExpr(to(varDecl().bind("v"))))))
                      .bind("assign");
    for (const BoundNodes &N : match(findAll(Assign), *D->getBody(), Ctx)) {
      const auto *BO = N.getNodeAs<BinaryOperator>("assign");
      if ((BO->getOpcode() == BO_Assign && isMulOrAdd(BO->getRHS())) ||
          BO->getOpcode() == BO_MulAssign || BO->getOpcode() == BO_AddAssign)
        Computed[N.getNodeAs<VarDecl>("v")].push_back(BO->getBeginLoc());
    }
    for (const BoundNodes &N : match(stmt(forEachDescendant(varDecl(hasInitializer(expr())).bind("v"))),
                                     *D->getBody(), Ctx)) {
      const auto *VD = N.getNodeAs<VarDecl>("v");
      if (isMulOrAdd(VD->getInit()))
        Computed[VD].push_back(VD->getBeginLoc());
    }

    auto Call = callExpr().bind("call");
    for (const BoundNodes &N : match(findAll(Call), *D->getBody(), Ctx)) {
      const auto *CE = N.getNodeAs<CallExpr>("call");
      bool Bad = false;
      for (unsigned I : sizeArgs(allocatorName(CE))) {
        if (I >= CE->getNumArgs())
          continue;
        const Expr *A = CE->getArg(I);
        if (isMulOrAdd(A)) {
          Bad = true;
          break;
        }
        if (const auto *DRE = dyn_cast<DeclRefExpr>(A->IgnoreParenCasts()))
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
            for (SourceLocation L : Computed.lookup(VD))
              if (SM.isBeforeInTranslationUnit(L, CE->getBeginLoc()))
                Bad = true;
        if (Bad)
          break;
      }
      if (Bad)
        raptor::reportAt(BR, this, "Integer wraparound in allocation size",
                         "The allocation size is computed with an arithmetic "
                         "operation that can wrap around, which may allocate "
                         "a buffer smaller than intended",
                         CE, Mgr.getAnalysisDeclContext(D));
    }
  }

  void checkBoundsChecks(const Decl *D, AnalysisManager &Mgr,
                         BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    auto M = binaryOperator(hasAnyOperatorName("||", "&&")).bind("logic");
    for (const BoundNodes &N : match(findAll(M), *D->getBody(), Ctx)) {
      const auto *L = N.getNodeAs<BinaryOperator>("logic");
      const auto *C1 = dyn_cast<BinaryOperator>(L->getLHS()->IgnoreParens());
      const auto *C2 = dyn_cast<BinaryOperator>(L->getRHS()->IgnoreParens());
      if (!C1 || !C2)
        continue;
      auto okOp = [&](BinaryOperatorKind K) {
        return L->getOpcode() == BO_LOr ? (K == BO_GT || K == BO_GE)
                                        : (K == BO_LT || K == BO_LE);
      };
      if (!okOp(C1->getOpcode()) || !okOp(C2->getOpcode()))
        continue;
      const auto *Arith = dyn_cast<BinaryOperator>(C2->getLHS()->IgnoreParenImpCasts());
      if (!Arith || !isOneOfOp(Arith->getOpcode()))
        continue;
      if (!sameExpr(C1->getLHS(), Arith->getLHS(), Ctx) ||
          !sameExpr(C1->getRHS(), C2->getRHS(), Ctx))
        continue;
      raptor::reportAt(BR, this, "Bounds check defeated by integer wraparound",
                       "The second comparison can be bypassed when the "
                       "arithmetic operation wraps around",
                       L, Mgr.getAnalysisDeclContext(D));
    }
  }

public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    checkAllocations(D, Mgr, BR);
    checkBoundsChecks(D, Mgr, BR);
  }
};
} // namespace

RAPTOR_CHECKER(IntegerWraparoundChecker, "IntegerWraparound",
               "Integer wraparound in allocation sizes and bounds checks")
