// raptor.UncheckedAllocProduct: an allocation sized by a 32-bit product of two
// run-time factors, filled in a loop bounded by one of them, with no overflow
// guard on the factors (CWE-190 -> CWE-787, heap overflow).
//
//   av_new_packet(new_pkt, expected_stride * par->height);   // int * int
//   for (y = 0; y < par->height; y++)
//     memcpy(new_pkt->data + y * expected_stride, src, n);   // writes h * stride
//
// When the product wraps, the buffer is small but the loop still writes
// rows * stride bytes.
// Sink: a call whose name contains "alloc" or "new" with an argument
// `a * b`, where the product is at most 32 bits wide and neither factor is
// a constant (a constant factor is raptor.IntegerWraparound's business).
// Loop: a for/while whose condition compares a counter with a factor and
// whose body writes memory (memcpy/memmove/memset, or an assignment through a
// subscript or a dereference).
// Sanitizer: a relational comparison with a division mentioning a factor
// (`a > INT_MAX / b`), or a call to an overflow helper (name containing
// "overflow", "mult" or "check_size") that takes a factor.
//
// This is CVE-2026-70628 / CVE-2026-70632 (FFmpeg < 9.0,
// libavformat/rawutils.c ff_reshuffle_raw_rgb).
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;

namespace {
using Keys = std::set<std::string>;

template <class F> void walk(const Stmt *S, F &&Fn) {
  if (!S)
    return;
  Fn(S);
  for (const Stmt *C : S->children())
    walk(C, Fn);
}

bool mentions(const Stmt *S, const Keys &K) { return raptor_mem::findKey(S, K) != nullptr; }

bool isAllocator(const CallExpr *CE) {
  std::string N = raptor::calleeName(CE).lower();
  return N.find("alloc") != std::string::npos || N.find("new") != std::string::npos;
}

bool writesMemory(const Stmt *Body) {
  bool W = false;
  walk(Body, [&](const Stmt *S) {
    if (W)
      return;
    if (const auto *CE = dyn_cast<CallExpr>(S)) {
      StringRef N = raptor::calleeName(CE);
      W = N.contains("memcpy") || N.contains("memmove") || N.contains("memset");
    } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->isAssignmentOp()) {
        const Expr *L = raptor::strip(BO->getLHS());
        const auto *UO = dyn_cast<UnaryOperator>(L);
        W = isa<ArraySubscriptExpr>(L) || (UO && UO->getOpcode() == UO_Deref);
      }
    }
  });
  return W;
}

const Expr *loopCond(const Stmt *S) {
  if (const auto *F = dyn_cast<ForStmt>(S))
    return F->getCond();
  if (const auto *W = dyn_cast<WhileStmt>(S))
    return W->getCond();
  if (const auto *D = dyn_cast<DoStmt>(S))
    return D->getCond();
  return nullptr;
}

const Stmt *loopBody(const Stmt *S) {
  if (const auto *F = dyn_cast<ForStmt>(S))
    return F->getBody();
  if (const auto *W = dyn_cast<WhileStmt>(S))
    return W->getBody();
  if (const auto *D = dyn_cast<DoStmt>(S))
    return D->getBody();
  return nullptr;
}

bool hasDivision(const Stmt *S, const Keys &K) {
  bool Found = false;
  walk(S, [&](const Stmt *X) {
    if (const auto *BO = dyn_cast<BinaryOperator>(X))
      if (BO->getOpcode() == BO_Div && mentions(BO, K))
        Found = true;
  });
  return Found;
}

class UncheckedAllocProductChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    walk(Body, [&](const Stmt *S) {
      const auto *CE = dyn_cast<CallExpr>(S);
      if (!CE || !isAllocator(CE))
        return;
      for (const Expr *A : CE->arguments()) {
        const auto *BO = dyn_cast_or_null<BinaryOperator>(raptor::strip(A));
        if (!BO || BO->getOpcode() != BO_Mul)
          continue;
        QualType T = BO->getType();
        if (!T->isIntegerType() || T->isDependentType() || Ctx.getTypeSize(T) > 32)
          continue;
        const Expr *L = raptor::strip(BO->getLHS()), *R = raptor::strip(BO->getRHS());
        if (L->isValueDependent() || R->isValueDependent() ||
            L->isIntegerConstantExpr(Ctx) || R->isIntegerConstantExpr(Ctx))
          continue;
        std::string KL = raptor_mem::keyOf(L), KR = raptor_mem::keyOf(R);
        if (KL.empty() || KR.empty())
          continue;
        Keys Factors{KL, KR};
        if (!filledByLoop(Body, Factors) || guarded(Body, Factors))
          continue;
        raptor::reportAt(BR, this, "Unchecked allocation product",
                         "Allocation size '" + KL + " * " + KR +
                             "' is a 32-bit product that can wrap, and a loop bounded "
                             "by a factor fills the buffer: check the product for "
                             "overflow (CWE-190, CWE-787)",
                         CE, Mgr.getAnalysisDeclContext(D));
        return;
      }
    });
  }

private:
  // A loop comparing with a factor that writes memory.
  static bool filledByLoop(const Stmt *Body, const Keys &F) {
    bool Found = false;
    walk(Body, [&](const Stmt *S) {
      if (Found)
        return;
      const auto *C = dyn_cast_or_null<BinaryOperator>(
          loopCond(S) ? raptor::strip(loopCond(S)) : nullptr);
      if (C && C->isRelationalOp() && mentions(C, F) && writesMemory(loopBody(S)))
        Found = true;
    });
    return Found;
  }

  static bool guarded(const Stmt *Body, const Keys &F) {
    llvm::SmallPtrSet<const Expr *, 8> LoopConds;
    walk(Body, [&](const Stmt *S) {
      if (const Expr *C = loopCond(S))
        LoopConds.insert(raptor::strip(C));
    });
    bool G = false;
    walk(Body, [&](const Stmt *S) {
      if (G)
        return;
      if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isRelationalOp() && !LoopConds.count(BO) && hasDivision(BO, F))
          G = true;
      } else if (const auto *CE = dyn_cast<CallExpr>(S)) {
        std::string N = raptor::calleeName(CE).lower();
        if (N.find("overflow") != std::string::npos || N.find("mult") != std::string::npos ||
            N.find("check_size") != std::string::npos)
          for (const Expr *A : CE->arguments())
            if (mentions(A, F))
              G = true;
      }
    });
    return G;
  }
};
} // namespace

RAPTOR_CHECKER(UncheckedAllocProductChecker, "UncheckedAllocProduct",
               "Allocation sized by an unchecked 32-bit product filled by a loop")
