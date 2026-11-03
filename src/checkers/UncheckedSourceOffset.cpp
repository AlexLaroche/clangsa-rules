// raptor.UncheckedSourceOffset: a memory copy reads from a buffer obtained
// from a call (so its length is not known here) at an offset scaled by a loop
// counter, and nothing compares the loop bound, or a size computed from it,
// to anything (CWE-125, heap over-read).
//
//   item.findAndGetUint8Array(DCM_PixelData, pixData8);   // no length
//   for (Uint32 f = 0; f < numFrames; f++) {              // numFrames from the file
//     const Uint8 *ptr = pixData8 + f * frameLen;
//     memcpy(frame, ptr, frameLen);                       // reads past the end
//   }
//
// Sink: the source argument of memcpy/memmove is `base + off` or
// `&base[off]` (directly or through a local initialised with it), where off
// mentions the counter i of an enclosing loop `i < N` / `i <= N` with a
// non-constant N.
// base: a local pointer whose value comes from a call (initialised or
// assigned from one, or passed to one as an out-argument). A buffer passed in
// by the caller is assumed to be sized by the caller.
// Sanitizer: a relational comparison, other than the loop condition, that
// mentions N or a value derived from it: a variable initialised or assigned
// from an expression using it, or an out-argument (`&v`, or `v` bound to a
// non-const reference) of a call that also takes it, e.g.
//   if (!safeMult(bytesPerFrame, numFrames, bytesRequired) || bytesRequired > count)
//
// This is CVE-2026-97059 (DCMTK <= 3.7.0, ConcatenationLoader::extractFrames).
#include "ApiUtil.h"
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;

namespace {
using VarSet = llvm::SmallPtrSet<const VarDecl *, 16>;

template <class F> void walk(const Stmt *S, F &&Fn) {
  if (!S)
    return;
  Fn(S);
  for (const Stmt *C : S->children())
    walk(C, Fn);
}

const VarDecl *refVar(const Expr *E) {
  const auto *DRE = dyn_cast_or_null<DeclRefExpr>(raptor::strip(E));
  return DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
}

void varsIn(const Stmt *S, VarSet &Out) {
  walk(S, [&](const Stmt *X) {
    if (const VarDecl *V = refVar(dyn_cast<Expr>(X)))
      Out.insert(V);
  });
}

bool mentions(const Stmt *S, const VarSet &Vars, const std::set<std::string> &Keys) {
  bool Found = false;
  walk(S, [&](const Stmt *X) {
    if (Found)
      return;
    if (const auto *E = dyn_cast<Expr>(X)) {
      if (const VarDecl *V = refVar(E))
        if (Vars.count(V))
          Found = true;
      if (!Keys.empty()) {
        std::string K = raptor_mem::keyOf(E);
        if (!K.empty() && Keys.count(K))
          Found = true;
      }
    }
  });
  return Found;
}

// A variable that a call may write: `&v`, or `v` passed to a non-const
// reference parameter.
const VarDecl *outArg(const CallExpr *CE, unsigned I) {
  const Expr *A = CE->getArg(I)->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(A))
    if (UO->getOpcode() == UO_AddrOf)
      return refVar(UO->getSubExpr());
  const FunctionDecl *FD = CE->getDirectCallee();
  if (FD && I < FD->getNumParams()) {
    QualType T = FD->getParamDecl(I)->getType();
    if (T->isLValueReferenceType() && !T.getNonReferenceType().isConstQualified())
      return refVar(A);
  }
  return nullptr;
}

bool isCopy(const CallExpr *CE) {
  return raptor::isOneOf(raptor::calleeName(CE),
                         {"memcpy", "memmove", "__builtin_memcpy", "__builtin_memmove",
                          "__builtin___memcpy_chk", "__builtin___memmove_chk"});
}

// Split a source pointer into base and offset.
bool splitSource(const Expr *E, const Expr *&Base, const Expr *&Off) {
  E = raptor::strip(E);
  if (const VarDecl *V = refVar(E))
    if (V->hasLocalStorage() && !isa<ParmVarDecl>(V) && V->getInit())
      E = raptor::strip(V->getInit());
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() != BO_Add)
      return false;
    bool LP = BO->getLHS()->getType()->isPointerType();
    Base = LP ? BO->getLHS() : BO->getRHS();
    Off = LP ? BO->getRHS() : BO->getLHS();
    return true;
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(E))
    if (UO->getOpcode() == UO_AddrOf)
      if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(raptor::strip(UO->getSubExpr()))) {
        Base = ASE->getBase();
        Off = ASE->getIdx();
        return true;
      }
  return false;
}

// Does B get its value from a call in Body?
bool fromCall(const VarDecl *B, const Stmt *Body) {
  if (B->getInit() && isa<CallExpr>(raptor::strip(B->getInit())))
    return true;
  bool Found = false;
  walk(Body, [&](const Stmt *S) {
    if (const auto *BO = dyn_cast<BinaryOperator>(S))
      if (BO->getOpcode() == BO_Assign && refVar(BO->getLHS()) == B &&
          isa<CallExpr>(raptor::strip(BO->getRHS())))
        Found = true;
    if (const auto *CE = dyn_cast<CallExpr>(S))
      for (unsigned I = 0; I < CE->getNumArgs(); ++I)
        if (outArg(CE, I) == B)
          Found = true;
  });
  return Found;
}

class UncheckedSourceOffsetChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(D);
    ParentMap &PM = ADC->getParentMap();
    walk(Body, [&](const Stmt *S) {
      const auto *CE = dyn_cast<CallExpr>(S);
      if (!CE || !isCopy(CE) || CE->getNumArgs() < 3)
        return;
      const Expr *Base = nullptr, *Off = nullptr;
      if (!splitSource(CE->getArg(1), Base, Off))
        return;
      const VarDecl *B = refVar(Base);
      if (!B || !B->hasLocalStorage() || isa<ParmVarDecl>(B) || !fromCall(B, Body))
        return;
      // An enclosing loop `i < N` whose counter scales the offset.
      for (const Stmt *Up = PM.getParent(S); Up; Up = PM.getParent(Up)) {
        const Expr *Cond = nullptr;
        if (const auto *F = dyn_cast<ForStmt>(Up))
          Cond = F->getCond();
        else if (const auto *W = dyn_cast<WhileStmt>(Up))
          Cond = W->getCond();
        const auto *LC = dyn_cast_or_null<BinaryOperator>(Cond ? raptor::strip(Cond) : nullptr);
        if (!LC || !LC->isRelationalOp())
          continue;
        const VarDecl *I = nullptr;
        const Expr *N = nullptr;
        if (LC->getOpcode() == BO_LT || LC->getOpcode() == BO_LE) {
          I = refVar(LC->getLHS());
          N = LC->getRHS();
        } else {
          I = refVar(LC->getRHS());
          N = LC->getLHS();
        }
        if (!I || !N || N->isValueDependent() || N->isIntegerConstantExpr(Ctx))
          continue;
        VarSet Counter;
        Counter.insert(I);
        if (!mentions(Off, Counter, {}))
          continue;
        if (boundChecked(Body, LC, N))
          return;
        raptor::reportAt(
            BR, this, "Unchecked source offset",
            ("Copy reads '" + B->getNameAsString() + "' at an offset scaled by '" +
             I->getNameAsString() + "' up to '" + raptor::api::textAsWritten(N, Ctx) +
             "', but nothing compares that bound, or a size computed from it, "
             "with the length of '" + B->getNameAsString() + "' (CWE-125)"),
            CE, ADC);
        return;
      }
    });
  }

private:
  // Is N, or a value derived from it, used in a relational comparison other
  // than the loop condition LC?
  static bool boundChecked(const Stmt *Body, const BinaryOperator *LC, const Expr *N) {
    VarSet Derived;
    varsIn(N, Derived);
    std::set<std::string> Keys;
    std::string K = raptor_mem::keyOf(N);
    if (!K.empty())
      Keys.insert(K);
    for (int Pass = 0; Pass < 4; ++Pass)
      walk(Body, [&](const Stmt *S) {
        if (const auto *DS = dyn_cast<DeclStmt>(S)) {
          for (const Decl *Dc : DS->decls())
            if (const auto *VD = dyn_cast<VarDecl>(Dc))
              if (VD->getInit() && mentions(VD->getInit(), Derived, Keys))
                Derived.insert(VD);
        } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
          if (BO->isAssignmentOp())
            if (const VarDecl *L = refVar(BO->getLHS()))
              if (mentions(BO->getRHS(), Derived, Keys))
                Derived.insert(L);
        } else if (const auto *CE = dyn_cast<CallExpr>(S)) {
          bool Takes = false;
          for (const Expr *A : CE->arguments())
            if (mentions(A, Derived, Keys))
              Takes = true;
          if (Takes)
            for (unsigned I = 0; I < CE->getNumArgs(); ++I)
              if (const VarDecl *V = outArg(CE, I))
                Derived.insert(V);
        }
      });
    bool Checked = false;
    walk(Body, [&](const Stmt *S) {
      if (const auto *BO = dyn_cast<BinaryOperator>(S))
        if (BO != LC && BO->isRelationalOp() && mentions(BO, Derived, Keys))
          Checked = true;
    });
    return Checked;
  }
};
} // namespace

RAPTOR_CHECKER(UncheckedSourceOffsetChecker, "UncheckedSourceOffset",
               "Copy source offset scaled by an unchecked loop bound")
