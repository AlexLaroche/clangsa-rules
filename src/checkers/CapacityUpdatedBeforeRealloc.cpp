// raptor.CapacityUpdatedBeforeRealloc: a size or dimension field of an object
// is set before the buffer it describes (another field of the same object) is
// reallocated, and the failure branch of the reallocation leaves without
// restoring the field (CWE-131, CWE-787):
//
//   vBarEntry->size = vBarEntry->count;
//   tmp = winpr_aligned_recalloc(vBarEntry->pixels, vBarEntry->count, bpp, 32);
//   if (!tmp) return FALSE;            // size now larger than pixels
//
// Field: an integer field F of B assigned before a call whose name contains
// "realloc" or "recalloc" with B->G (or B->G[i]) as first argument, F != G,
// F a size field of G (raptor_mem::isSizeField) or a dimension or count
// (width, height, size, len, count, capacity, stride, ...). Failure branch:
// an `if` after the call that tests its result for null and exits (return,
// goto, break, throw; not a call that ends the program) without assigning F,
// the assignment's block holding the call (same path, not another branch).
//
// CVE-2026-33984 (FreeRDP clear.c resize_vbar_entry), CVE-2026-33986
// (FreeRDP h264.c yuv_ensure_buffer: h264->width/height before the planes).
#include "BufHelpers.h"
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <set>

using namespace clang;
using namespace ento;

namespace {
template <class F> void walk(const Stmt *S, F &&Fn) {
  if (!S)
    return;
  Fn(S);
  for (const Stmt *C : S->children())
    walk(C, Fn);
}

bool exits(const Stmt *S) {
  bool X = false;
  walk(S, [&](const Stmt *N) {
    // Not a call that ends the program: then nobody uses the stale size.
    if (isa<ReturnStmt>(N) || isa<GotoStmt>(N) || isa<BreakStmt>(N) ||
        isa<CXXThrowExpr>(N))
      X = true;
  });
  return X;
}

bool dimension(StringRef Name) {
  std::string N = Name.lower();
  return raptor::isOneOf(N, {"width", "height", "w", "h", "size", "len",
                             "length", "count", "capacity", "cap", "stride",
                             "nelts", "nitems", "allocated", "alloc", "max",
                             "maxsize", "nsize", "num"});
}

// B->G or B->G[i]: the base key of B and the field G.
const FieldDecl *bufferField(const Expr *E, std::string &Base) {
  E = raptor::strip(E);
  if (const auto *ASE = dyn_cast_or_null<ArraySubscriptExpr>(E))
    E = raptor::strip(ASE->getBase());
  const auto *ME = dyn_cast_or_null<MemberExpr>(E);
  if (!ME)
    return nullptr;
  const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD || !(FD->getType()->isPointerType() || FD->getType()->isArrayType()))
    return nullptr;
  Base = raptor_mem::keyOf(ME->getBase());
  return Base.empty() ? nullptr : FD;
}

// Does Cond test V for null (`!v`, `v == NULL`)?
bool nullTest(const Expr *Cond, const std::string &V, ASTContext &Ctx) {
  bool T = false;
  walk(Cond, [&](const Stmt *S) {
    if (const auto *UO = dyn_cast<UnaryOperator>(S);
        UO && UO->getOpcode() == UO_LNot)
      T |= raptor_mem::keyOf(UO->getSubExpr()) == V;
    if (const auto *BO = dyn_cast<BinaryOperator>(S);
        BO && BO->getOpcode() == BO_EQ)
      for (auto [A, B] : {std::pair{BO->getLHS(), BO->getRHS()},
                          std::pair{BO->getRHS(), BO->getLHS()}})
        T |= raptor_mem::keyOf(A) == V &&
             B->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNotNull);
  });
  return T;
}

class CapacityUpdatedBeforeReallocChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();
    auto loc = [&](const Stmt *S, bool End = false) {
      return SM.getExpansionLoc(End ? S->getEndLoc() : S->getBeginLoc());
    };
    auto before = [&](SourceLocation A, SourceLocation B) {
      return SM.isBeforeInTranslationUnit(A, B);
    };

    struct Assign {
      const BinaryOperator *BO;
      std::string Base, Key;
      const FieldDecl *F;
    };
    std::vector<Assign> Assigns;
    struct Realloc {
      const CallExpr *CE;
      std::string Base, Result;
      const FieldDecl *G;
    };
    std::vector<Realloc> Reallocs;
    std::vector<const IfStmt *> Ifs;
    walk(Body, [&](const Stmt *S) {
      if (const auto *If = dyn_cast<IfStmt>(S))
        Ifs.push_back(If);
      const Expr *Init = nullptr;
      std::string Result;
      if (const auto *BO = dyn_cast<BinaryOperator>(S);
          BO && BO->getOpcode() == BO_Assign) {
        if (const auto *ME = dyn_cast<MemberExpr>(raptor::strip(BO->getLHS())))
          if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
              FD && FD->getType()->isIntegerType() && FD->getIdentifier())
            if (std::string B = raptor_mem::keyOf(ME->getBase()); !B.empty())
              Assigns.push_back({BO, B, raptor_mem::keyOf(ME), FD});
        Init = BO->getRHS();
        Result = raptor_mem::keyOf(BO->getLHS());
      }
      if (const auto *DS = dyn_cast<DeclStmt>(S))
        for (const Decl *Dc : DS->decls())
          if (const auto *VD = dyn_cast<VarDecl>(Dc); VD && VD->getInit()) {
            Init = VD->getInit();
            Result = VD->getNameAsString();
          }
      const auto *CE = Init ? dyn_cast<CallExpr>(raptor::strip(Init)) : nullptr;
      if (!CE || CE->getNumArgs() < 2 || Result.empty())
        return;
      std::string N = raptor::calleeName(CE).lower();
      if (N.find("realloc") == std::string::npos &&
          N.find("recalloc") == std::string::npos)
        return;
      std::string Base;
      if (const FieldDecl *G = bufferField(CE->getArg(0), Base))
        Reallocs.push_back({CE, Base, Result, G});
    });

    ParentMap PM(const_cast<Stmt *>(Body));
    std::set<const BinaryOperator *> Reported;
    for (const Realloc &R : Reallocs) {
      // The failure branch: exits without restoring.
      for (const IfStmt *If : Ifs) {
        if (!If->getCond() || !before(loc(R.CE), loc(If)) ||
            !nullTest(If->getCond(), R.Result, Ctx) || !exits(If->getThen()))
          continue;
        for (const Assign &A : Assigns) {
          if (A.Base != R.Base || A.F == R.G || Reported.count(A.BO) ||
              !before(loc(A.BO, true), loc(R.CE)))
            continue;
          if (!raptor_mem::isSizeField(A.F, R.G) && !dimension(A.F->getName()))
            continue;
          // Same path: the block holding the assignment holds the call.
          const CompoundStmt *Blk = raptor::buf::enclosingBlock(A.BO, PM);
          bool Holds = false;
          walk(Blk, [&](const Stmt *S) { Holds |= S == R.CE; });
          if (!Holds)
            continue;
          bool Restored = false;
          walk(If->getThen(), [&](const Stmt *S) {
            if (const auto *BO = dyn_cast<BinaryOperator>(S);
                BO && BO->isAssignmentOp())
              Restored |= raptor_mem::keyOf(BO->getLHS()) == A.Key;
          });
          if (Restored)
            continue;
          // A later assignment of the field before the call supersedes A.
          bool Superseded = false;
          for (const Assign &B : Assigns)
            Superseded |= B.Key == A.Key && B.BO != A.BO &&
                          before(loc(A.BO), loc(B.BO)) &&
                          before(loc(B.BO, true), loc(R.CE));
          if (Superseded)
            continue;
          Reported.insert(A.BO);
          raptor::reportAt(
              BR, this, "Capacity updated before realloc",
              "'" + A.Key + "' is set before the buffer '" +
                  R.G->getName().str() +
                  "' of the same object is reallocated, and the failure branch "
                  "leaves without "
                  "restoring it: the object then describes a buffer larger "
                  "than "
                  "the one it still holds; set it after the reallocation "
                  "succeeded (CWE-131, CWE-787)",
              A.BO, Mgr.getAnalysisDeclContext(D));
        }
      }
    }
  }
};
} // namespace

RAPTOR_CHECKER(
    CapacityUpdatedBeforeReallocChecker, "CapacityUpdatedBeforeRealloc",
    "Size field set before a reallocation whose failure leaves it set")
