// Port of raptor-off-by-one: off-by-one array writes, strlen()/sizeof()
// comparisons, strncat() sizes not ending in "- 1", indexing with
// strlen() - 1 and allocations with no room for the NUL terminator.
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {
// strlen($STR); sets Str to the argument.
bool isStrlen(const Expr *E, const Expr **Str = nullptr) {
  const auto *CE = dyn_cast_or_null<CallExpr>(ign(E));
  if (!CE || raptor::calleeName(CE) != "strlen" || CE->getNumArgs() != 1)
    return false;
  if (Str)
    *Str = CE->getArg(0);
  return true;
}

bool isSizeof(const Expr *E, const Expr **Arg = nullptr) {
  const auto *U = dyn_cast_or_null<UnaryExprOrTypeTraitExpr>(ign(E));
  if (!U || U->getKind() != UETT_SizeOf)
    return false;
  if (Arg)
    *Arg = U->isArgumentType() ? nullptr : U->getArgumentExpr();
  return true;
}

// $X - 1; sets X to the left operand.
bool isMinusOne(const Expr *E, const ASTContext &Ctx,
                const Expr **X = nullptr) {
  const auto *BO = dyn_cast_or_null<BinaryOperator>(ign(E));
  if (!BO || BO->getOpcode() != BO_Sub ||
      !isa<IntegerLiteral>(ign(BO->getRHS())))
    return false;
  auto V = intValue(BO->getRHS(), Ctx);
  if (!V || *V != 1)
    return false;
  if (X)
    *X = BO->getLHS();
  return true;
}

// `$LEN = strlen($STR)` or `$LEN = strlen($STR) - 1` (assignment or
// declaration with initializer).
struct LenDef {
  const Stmt *At;        // the assignment / declaration statement
  const Expr *LHS;       // assigned expression (null for declarations)
  const VarDecl *Var;    // declared variable (null for assignments)
  const Expr *Str;       // $STR
  bool MinusOne;         // strlen($STR) - 1
  const CompoundStmt *Block;

  bool isLen(const Expr *E) const {
    if (Var) {
      const auto *DRE = dyn_cast<DeclRefExpr>(ign(E));
      return DRE && DRE->getDecl() == Var;
    }
    return sameExpr(E, LHS);
  }
};

class OffByOneChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(D);
    const ParentMap &PM = ADC->getParentMap();
    const SourceManager &SM = BR.getSourceManager();
    const Stmt *Body = D->getBody();
    llvm::SmallPtrSet<const Stmt *, 16> Reported;
    auto Report = [&](const Stmt *S) {
      if (Reported.insert(S).second)
        raptor::reportAt(BR, this, "Off-by-one error",
                         "The software calculates or uses an incorrect "
                         "maximum or minimum value that is 1 more, or 1 "
                         "less, than the correct value.",
                         S, ADC);
    };

    // Array writes: $BUF[sizeof($BUF)] = ..., $BUF[$LEN] = ... and
    // *($BUF + $LEN) = ... with `$_ $BUF[$LEN]`, and $BUF[$X][$Y] = ...
    // with `$_ $BUF[$_][$Y]` or `$_ $BUF[$X][$_]`.
    forEach<BinaryOperator>(Body, [&](const BinaryOperator *BO) {
      if (BO->getOpcode() != BO_Assign)
        return;
      const Expr *LHS = ign(BO->getLHS());
      if (const auto *AS = dyn_cast<ArraySubscriptExpr>(LHS)) {
        const Expr *Buf = AS->getBase(), *Idx = AS->getIdx(), *SizeofArg;
        if ((isSizeof(Idx, &SizeofArg) && SizeofArg && sameExpr(SizeofArg, Buf)) ||
            declaredWithSize(Buf, Idx, Ctx))
          return Report(BO);
        if (const auto *Inner = dyn_cast<ArraySubscriptExpr>(ign(Buf)))
          if (const ValueDecl *VD = refDecl(Inner->getBase()))
            if (const auto *Outer = Ctx.getAsConstantArrayType(VD->getType()))
              if (const auto *In =
                      Ctx.getAsConstantArrayType(Outer->getElementType()))
                if (equalsInt(Inner->getIdx(), Outer->getSize(), Ctx) ||
                    equalsInt(Idx, In->getSize(), Ctx))
                  return Report(BO);
        return;
      }
      if (const auto *UO = dyn_cast<UnaryOperator>(LHS))
        if (UO->getOpcode() == UO_Deref)
          if (const auto *Add = dyn_cast<BinaryOperator>(ign(UO->getSubExpr())))
            if (Add->getOpcode() == BO_Add &&
                declaredWithSize(Add->getLHS(), Add->getRHS(), Ctx))
              return Report(BO);
    });

    // strlen($SRC) > sizeof($DST), strlen($SRC) <= sizeof($DST),
    // sizeof($DST) < strlen($SRC), sizeof($DST) >= strlen($SRC)
    forEach<BinaryOperator>(Body, [&](const BinaryOperator *BO) {
      const Expr *L = BO->getLHS(), *R = BO->getRHS();
      switch (BO->getOpcode()) {
      case BO_GT:
      case BO_LE:
        if (isStrlen(L) && isSizeof(R))
          Report(BO);
        break;
      case BO_LT:
      case BO_GE:
        if (isSizeof(L) && isStrlen(R))
          Report(BO);
        break;
      default:
        break;
      }
    });

    // strncat($_, $_, $LEN) where $LEN is not `$_ - 1`, and
    // malloc(strlen($STR)).
    forEach<CallExpr>(Body, [&](const CallExpr *CE) {
      StringRef N = raptor::calleeName(CE);
      if (N == "strncat" && CE->getNumArgs() == 3 &&
          !isMinusOne(CE->getArg(2), Ctx))
        Report(CE);
      if (N == "malloc" && CE->getNumArgs() == 1 && isStrlen(CE->getArg(0)))
        Report(CE);
    });

    // $STR[strlen($STR) - 1]
    forEach<ArraySubscriptExpr>(Body, [&](const ArraySubscriptExpr *AS) {
      const Expr *X, *Str;
      if (isMinusOne(AS->getIdx(), Ctx, &X) && isStrlen(X, &Str) &&
          sameExpr(Str, AS->getBase()))
        Report(AS);
    });

    // $LEN = strlen($STR) [- 1]; ... followed by $STR[$LEN], $STR[$LEN - 1]
    // or malloc($LEN).
    std::vector<LenDef> Defs;
    auto AddDef = [&](const Stmt *At, const Expr *LHS, const VarDecl *Var,
                      const Expr *RHS) {
      const Expr *Str, *X;
      if (isStrlen(RHS, &Str))
        Defs.push_back({At, LHS, Var, Str, false, enclosingBlock(At, PM)});
      else if (isMinusOne(RHS, Ctx, &X) && isStrlen(X, &Str))
        Defs.push_back({At, LHS, Var, Str, true, enclosingBlock(At, PM)});
    };
    forEach<BinaryOperator>(Body, [&](const BinaryOperator *BO) {
      if (BO->getOpcode() == BO_Assign)
        AddDef(BO, BO->getLHS(), nullptr, BO->getRHS());
    });
    forEach<DeclStmt>(Body, [&](const DeclStmt *DS) {
      for (const Decl *X : DS->decls())
        if (const auto *VD = dyn_cast<VarDecl>(X))
          if (VD->getInit())
            AddDef(DS, nullptr, VD, VD->getInit());
    });
    for (const LenDef &Def : Defs) {
      if (!Def.Block)
        continue;
      forEach<ArraySubscriptExpr>(Def.Block, [&](const ArraySubscriptExpr *AS) {
        if (!isAfter(AS, Def.At, SM) || !sameExpr(AS->getBase(), Def.Str))
          return;
        const Expr *X;
        if (Def.MinusOne ? Def.isLen(AS->getIdx())
                         : isMinusOne(AS->getIdx(), Ctx, &X) && Def.isLen(X))
          Report(AS);
      });
      if (!Def.MinusOne)
        forEach<CallExpr>(Def.Block, [&](const CallExpr *CE) {
          if (raptor::calleeName(CE) == "malloc" && CE->getNumArgs() == 1 &&
              isAfter(CE, Def.At, SM) && Def.isLen(CE->getArg(0)))
            Report(CE);
        });
    }
  }
};
} // namespace

RAPTOR_CHECKER(OffByOneChecker, "OffByOne", "Off-by-one error")
