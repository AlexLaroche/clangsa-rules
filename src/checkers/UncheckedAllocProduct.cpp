// raptor.UncheckedAllocProduct: an allocation sized by a 32-bit product of two
// run-time factors, with no overflow guard on the factors (CWE-190 -> CWE-787,
// heap overflow).
//
//   av_new_packet(new_pkt, expected_stride * par->height);   // int * int
//   comp->data = opj_calloc(comp->w * comp->h, sizeof(int)); // uint32 * uint32
//
// When the product wraps, the buffer is small, but the code that fills it (a
// loop over the rows, or the caller) still writes rows * stride elements.
// Sink: a call whose name contains "alloc" or "new" with a size argument
// containing `a * b` (directly, or in the initialiser or an assignment of the
// local variable passed as the size), where the product is at most 32 bits
// wide and neither factor is a constant (a constant factor is
// raptor.IntegerWraparound's business). A product computed in size_t on a
// 64-bit target does not match.
// Sanitizers, on the variables and fields used by the factors:
//   - a relational comparison containing a division (`a > INT_MAX / b`);
//   - a call to an overflow helper (name containing "overflow", "mult" or
//     "check_size", e.g. __builtin_mul_overflow, av_size_mult);
//   - both factors compared with a constant (`w > 4096 || h > 4096`).
//
// CVE-2026-70628 / CVE-2026-70632 (FFmpeg < 9.0, libavformat/rawutils.c),
// CVE-2016-9118 (OpenJPEG < 2.2.0, opj_image_create).
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Lex/Lexer.h"
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

// Variables and fields used by E (not under sizeof).
void keysIn(const Expr *E, Keys &Out) {
  walk(E, [&](const Stmt *S) {
    if (isa<DeclRefExpr>(S) || isa<MemberExpr>(S)) {
      std::string K = raptor_mem::keyOf(cast<Expr>(S));
      if (!K.empty())
        Out.insert(K);
    }
  });
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

class UncheckedAllocProductChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();

    // Initialisers and assignments of each local, for `n = a * b; alloc(n)`.
    llvm::DenseMap<const VarDecl *, std::vector<const Expr *>> Defs;
    walk(Body, [&](const Stmt *S) {
      if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *Dc : DS->decls())
          if (const auto *VD = dyn_cast<VarDecl>(Dc))
            if (VD->getInit())
              Defs[VD].push_back(VD->getInit());
      } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        // A compound assignment is recorded as an unknown (null) definition.
        if (BO->isAssignmentOp())
          if (const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(BO->getLHS())))
            if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
              Defs[VD].push_back(BO->getOpcode() == BO_Assign ? BO->getRHS() : nullptr);
      } else if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
        if (UO->isIncrementDecrementOp() || UO->getOpcode() == UO_AddrOf)
          if (const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(UO->getSubExpr())))
            if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
              Defs[VD].push_back(nullptr);
      }
    });

    // An operand built only from constants and locals that are only ever
    // assigned constants (`stride = 4 * MAXRLVLS;`).
    auto constant = [&](const Expr *E) {
      bool C = true;
      walk(E, [&](const Stmt *X) {
        if (isa<MemberExpr>(X) || isa<CallExpr>(X) || isa<ArraySubscriptExpr>(X))
          C = false;
        if (const auto *DRE = dyn_cast<DeclRefExpr>(X)) {
          const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
          if (!VD)
            return; // enumerator
          if (!VD->hasLocalStorage() || isa<ParmVarDecl>(VD)) {
            C = false;
            return;
          }
          auto It = Defs.find(VD);
          if (It == Defs.end() || It->second.empty())
            C = false;
          else
            for (const Expr *Dv : It->second)
              if (!Dv || Dv->isValueDependent() || !Dv->isIntegerConstantExpr(Ctx))
                C = false;
        }
      });
      return C;
    };

    walk(Body, [&](const Stmt *S) {
      const auto *CE = dyn_cast<CallExpr>(S);
      if (!CE || !isAllocator(CE))
        return;
      for (const Expr *A : CE->arguments()) {
        std::vector<const Expr *> Sizes{A};
        if (const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(A)))
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
            if (VD->hasLocalStorage() && !isa<ParmVarDecl>(VD))
              for (const Expr *E : Defs.lookup(VD))
                Sizes.push_back(E);
        for (const Expr *Size : Sizes)
          if (const BinaryOperator *Mul = narrowProduct(Size, Ctx)) {
            Keys L, R;
            keysIn(Mul->getLHS(), L);
            keysIn(Mul->getRHS(), R);
            if (L.empty() || R.empty() || constant(Mul->getLHS()) || constant(Mul->getRHS()) ||
                guarded(Body, L, R, Ctx))
              continue;
            raptor::reportAt(
                BR, this, "Unchecked allocation product",
                "Allocation size '" + exprText(Mul, Ctx) +
                    "' is a 32-bit product of run-time values that can wrap "
                    "around and allocate a buffer smaller than the data written "
                    "into it: check the factors for overflow or multiply in "
                    "size_t (CWE-190, CWE-787)",
                CE, Mgr.getAnalysisDeclContext(D));
            return;
          }
      }
    });
  }

private:
  static std::string exprText(const Expr *E, ASTContext &Ctx) {
    const SourceManager &SM = Ctx.getSourceManager();
    CharSourceRange R = CharSourceRange::getTokenRange(E->getSourceRange());
    return Lexer::getSourceText(R, SM, Ctx.getLangOpts()).str();
  }

  // A `*` of non-constant operands, at most 32 bits wide, inside E (not
  // under sizeof or a call).
  static const BinaryOperator *narrowProduct(const Expr *E, ASTContext &Ctx) {
    E = raptor::strip(E);
    if (!E || isa<UnaryExprOrTypeTraitExpr>(E) || isa<CallExpr>(E))
      return nullptr;
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_Mul) {
        QualType T = BO->getType();
        const Expr *L = raptor::strip(BO->getLHS()), *R = raptor::strip(BO->getRHS());
        if (T->isIntegerType() && !T->isDependentType() && Ctx.getTypeSize(T) <= 32 &&
            !L->isValueDependent() && !R->isValueDependent() &&
            !L->isIntegerConstantExpr(Ctx) && !R->isIntegerConstantExpr(Ctx))
          return BO;
      }
      if (BO->isAdditiveOp() || BO->isMultiplicativeOp() || BO->isShiftOp()) {
        if (const BinaryOperator *M = narrowProduct(BO->getLHS(), Ctx))
          return M;
        return narrowProduct(BO->getRHS(), Ctx);
      }
      return nullptr;
    }
    if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      if (const BinaryOperator *M = narrowProduct(CO->getTrueExpr(), Ctx))
        return M;
      return narrowProduct(CO->getFalseExpr(), Ctx);
    }
    return nullptr;
  }

  static bool guarded(const Stmt *Body, const Keys &L, const Keys &R, ASTContext &Ctx) {
    Keys F = L;
    F.insert(R.begin(), R.end());
    llvm::SmallPtrSet<const Expr *, 8> LoopConds;
    walk(Body, [&](const Stmt *S) {
      if (const Expr *C = loopCond(S))
        LoopConds.insert(raptor::strip(C));
    });
    bool G = false, BoundL = false, BoundR = false;
    walk(Body, [&](const Stmt *S) {
      if (G)
        return;
      if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (!BO->isRelationalOp() || LoopConds.count(BO))
          return;
        // a > MAX / b
        walk(BO, [&](const Stmt *X) {
          if (const auto *D = dyn_cast<BinaryOperator>(X))
            if (D->getOpcode() == BO_Div && mentions(D, F))
              G = true;
        });
        // w > 4096
        const Expr *A = raptor::strip(BO->getLHS()), *B = raptor::strip(BO->getRHS());
        if (A->isValueDependent() || B->isValueDependent())
          return;
        const Expr *V = nullptr;
        if (B->isIntegerConstantExpr(Ctx))
          V = A;
        else if (A->isIntegerConstantExpr(Ctx))
          V = B;
        if (V) {
          std::string K = raptor_mem::keyOf(V);
          BoundL |= L.count(K) > 0;
          BoundR |= R.count(K) > 0;
        }
      } else if (const auto *CE = dyn_cast<CallExpr>(S)) {
        std::string N = raptor::calleeName(CE).lower();
        if (N.find("overflow") != std::string::npos || N.find("mult") != std::string::npos ||
            N.find("check_size") != std::string::npos)
          for (const Expr *A : CE->arguments())
            if (mentions(A, F))
              G = true;
      }
    });
    return G || (BoundL && BoundR);
  }
};
} // namespace

RAPTOR_CHECKER(UncheckedAllocProductChecker, "UncheckedAllocProduct",
               "Allocation sized by an unchecked 32-bit product")
