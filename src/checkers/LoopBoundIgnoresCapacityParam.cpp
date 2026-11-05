// raptor.LoopBoundIgnoresCapacityParam: a function takes an output buffer D
// and its capacity C (an integer parameter, or an in/out count `*C`, named
// like a size: *size*, *len*, *cnt*, *count*, *max*, *cap*, *num*), and fills
// D in a loop `for (i = 0; i < B; i++) D[i] = ...` (or `D[i].f = ...`) whose
// bound B is never bounded by C (CWE-787, CWE-120):
//
//   if (nVectorSize > m_nSize) return false;     // wrong direction
//   for (i = 0; i < m_nSize; i++) DstVector[i] = m_Num[i + nStart];
//
// Not reported: C in the loop condition; an in-loop exit on a test of C; a
// check before the loop that bounds B by C on the path that goes on
// (`if (B > C) return;`, `if (B <= C) { loop }`), or a clamp (`if (B > C) B =
// C;`, an assignment of B from an expression with C); read-only buffers; no
// capacity parameter.
//
// CVE-2026-25584 (iccDEV CIccTagFloatNum::GetValues), CVE-2026-30987 (iccDEV
// CIccTagNum::GetValues), CVE-2026-29068 (pjsip opus codec_parse).
#include "BufHelpers.h"
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {
bool sizeName(StringRef N) {
  std::string L = N.lower();
  for (const char *W : {"size", "len", "cnt", "count", "max", "cap", "num"})
    if (L.find(W) != std::string::npos)
      return true;
  return false;
}

bool mentions(const Stmt *S, const std::set<const ValueDecl *> &Ds) {
  bool M = false;
  forEach<DeclRefExpr>(
      S, [&](const DeclRefExpr *D) { M |= Ds.count(D->getDecl()) > 0; });
  return M;
}

bool exits(const Stmt *S) {
  bool X = false;
  forEach<Stmt>(S, [&](const Stmt *N) {
    if (isa<ReturnStmt>(N) || isa<GotoStmt>(N) || isa<BreakStmt>(N) ||
        isa<CXXThrowExpr>(N))
      X = true;
    else if (const auto *C = dyn_cast<CallExpr>(N);
             C && raptor_mem::neverReturns(C))
      X = true;
  });
  return X;
}

void tests(const Expr *Cond, bool True,
           std::vector<std::pair<const BinaryOperator *, bool>> &Out) {
  Cond = Cond->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(Cond);
      UO && UO->getOpcode() == UO_LNot)
    return tests(UO->getSubExpr(), !True, Out);
  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if ((BO->getOpcode() == BO_LAnd && True) ||
        (BO->getOpcode() == BO_LOr && !True)) {
      tests(BO->getLHS(), True, Out);
      tests(BO->getRHS(), True, Out);
    } else if (BO->isRelationalOp())
      Out.push_back({BO, True});
  }
}

// The array element written by S: `D[i] = ...`, `D[i].f = ...`.
const ArraySubscriptExpr *written(const Stmt *S) {
  const auto *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return nullptr;
  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  while (const auto *ME = dyn_cast<MemberExpr>(L)) {
    if (ME->isArrow())
      return nullptr;
    L = ME->getBase()->IgnoreParenImpCasts();
  }
  return dyn_cast<ArraySubscriptExpr>(L);
}

class LoopBoundIgnoresCapacityParamChecker
    : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const auto *FD = dyn_cast<FunctionDecl>(D);
    const Stmt *Body = D->getBody();
    if (!FD || !Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();
    std::set<const ValueDecl *> Out, Cap;
    for (const ParmVarDecl *P : FD->parameters()) {
      QualType T = P->getType();
      if (T->isPointerType() && !T->getPointeeType().isConstQualified() &&
          !T->getPointeeType()->isVoidType() &&
          !T->getPointeeType()->isFunctionType())
        Out.insert(P);
      if (!P->getIdentifier() || !sizeName(P->getName()))
        continue;
      if (T->isIntegerType() ||
          (T->isPointerType() && T->getPointeeType()->isIntegerType() &&
           !T->getPointeeType().isConstQualified()))
        Cap.insert(P);
    }
    for (const ValueDecl *C : Cap)
      Out.erase(C);
    if (Out.empty() || Cap.empty())
      return;

    std::vector<const IfStmt *> Ifs;
    forEach<IfStmt>(Body, [&](const IfStmt *If) { Ifs.push_back(If); });
    std::vector<const BinaryOperator *> Assigns;
    forEach<BinaryOperator>(Body, [&](const BinaryOperator *BO) {
      if (BO->isAssignmentOp())
        Assigns.push_back(BO);
    });

    auto check = [&](const Stmt *Loop, const Expr *Cond, const Stmt *LoopBody) {
      const auto *BO =
          Cond ? dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts())
               : nullptr;
      if (!BO || mentions(Cond, Cap))
        return;
      const Expr *I = BO->getLHS(), *B = BO->getRHS();
      BinaryOperatorKind Op = BO->getOpcode();
      if (Op == BO_GT || Op == BO_GE) {
        std::swap(I, B);
        Op = BinaryOperator::reverseComparisonOp(Op);
      }
      if (Op != BO_LT && Op != BO_LE && Op != BO_NE)
        return;
      const auto *IV = dyn_cast_or_null<VarDecl>(refDecl(I));
      if (!IV || ign(B)->isIntegerConstantExpr(Ctx))
        return;
      // The write.
      const ArraySubscriptExpr *W = nullptr;
      forEach<Stmt>(LoopBody, [&](const Stmt *S) {
        if (const ArraySubscriptExpr *A = written(S);
            A && !W && Out.count(refDecl(A->getBase())) &&
            refDecl(A->getIdx()) == IV)
          W = A;
      });
      if (!W)
        return;
      // An exit on the capacity inside the loop.
      bool Guard = false;
      forEach<IfStmt>(LoopBody, [&](const IfStmt *If) {
        Guard |= If->getCond() && mentions(If->getCond(), Cap) &&
                 exits(If->getThen());
      });
      if (Guard)
        return;
      SourceLocation At = SM.getExpansionLoc(Loop->getBeginLoc());
      auto before = [&](const Stmt *S) {
        return SM.isBeforeInTranslationUnit(SM.getExpansionLoc(S->getEndLoc()),
                                            At);
      };
      // B set from the capacity (`n = min(n, cap)`, `size_t max = n < *cap ? n
      // : *cap;`).
      if (const auto *BV = dyn_cast_or_null<VarDecl>(refDecl(B)))
        if (BV->getInit() && mentions(BV->getInit(), Cap))
          return;
      for (const BinaryOperator *A : Assigns)
        if (before(A) && sameExpr(A->getLHS(), B) && mentions(A->getRHS(), Cap))
          return;
      for (const IfStmt *If : Ifs) {
        if (!If->getCond())
          continue;
        bool Around = false;
        forEach<Stmt>(If->getThen(),
                      [&](const Stmt *S) { Around |= S == Loop; });
        std::vector<std::pair<const BinaryOperator *, bool>> Ts;
        if (Around)
          tests(If->getCond(), true, Ts);
        else if (before(If) && exits(If->getThen()))
          tests(If->getCond(), false, Ts);
        else if (before(If)) {
          // Clamp: if (B > C) B = C;
          bool Clamp = false;
          forEach<BinaryOperator>(If->getThen(), [&](const BinaryOperator *A) {
            Clamp |= A->isAssignmentOp() && sameExpr(A->getLHS(), B) &&
                     mentions(A->getRHS(), Cap);
          });
          if (Clamp)
            return;
        }
        for (auto [T, V] : Ts) {
          BinaryOperatorKind TOp = T->getOpcode();
          const Expr *L = T->getLHS(), *R = T->getRHS();
          if (containsExpr(R, B) && !containsExpr(L, B)) {
            std::swap(L, R);
            TOp = BinaryOperator::reverseComparisonOp(TOp);
          }
          if (!containsExpr(L, B) || !mentions(R, Cap))
            continue;
          if ((TOp == BO_LT || TOp == BO_LE) == V)
            return;
        }
      }
      raptor::reportAt(
          BR, this, "Loop bound ignores capacity parameter",
          "this loop fills the output buffer up to a bound that is never "
          "compared with the buffer's capacity parameter: the caller's buffer "
          "overflows when the bound is larger (CWE-787)",
          W, Mgr.getAnalysisDeclContext(D));
    };
    forEach<ForStmt>(
        Body, [&](const ForStmt *F) { check(F, F->getCond(), F->getBody()); });
    forEach<WhileStmt>(Body, [&](const WhileStmt *W) {
      check(W, W->getCond(), W->getBody());
    });
  }
};
} // namespace

RAPTOR_CHECKER(LoopBoundIgnoresCapacityParamChecker,
               "LoopBoundIgnoresCapacityParam",
               "Output loop bounded by something other than the buffer's "
               "capacity parameter")
