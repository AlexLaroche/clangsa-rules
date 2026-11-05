// raptor.UncheckedAllocProduct: an allocation sized by a 32-bit product of two
// run-time factors, with no overflow guard on the factors (CWE-190 -> CWE-787,
// heap overflow).
//
//   av_new_packet(new_pkt, expected_stride * par->height);   // int * int
//   comp->data = opj_calloc(comp->w * comp->h, sizeof(int)); // uint32 * uint32
//
// When the product wraps, the buffer is small, but the code that fills it (a
// loop over the rows, or the caller) still writes rows * stride elements.
// Sink: a call whose name contains "alloc" or "new" with an integer argument
// containing `a * b`, directly or in a definition of a slot it reads (a
// local, a field, an array element `size[x]`), up to three assignments back,
// where the product is at most 32 bits wide, can wrap (the operands' value
// widths add up to more than the product's) and neither factor is a
// constant (a constant factor is raptor.IntegerWraparound's business). A
// product computed in size_t on a 64-bit target does not match.
// Sanitizers, on the variables and fields used by the factors:
//   - a relational comparison containing a division (`a > INT_MAX / b`);
//   - a call to an overflow helper (name containing "overflow", "mult" or
//     "check_size", e.g. __builtin_mul_overflow, av_size_mult);
//   - both factors bounded from above by constants whose product fits the
//     product's type, before the allocation: `if (w > 4096 || h > 4096)
//     return;`, `if (w > C) w = C;`, or `if (w < C && h < C)` around it. A
//     lower bound (`if (w <= 0 || h <= 0) return;`) does not count.
//
// CVE-2026-70628 / CVE-2026-70632 (FFmpeg < 9.0, libavformat/rawutils.c),
// CVE-2016-9118 (OpenJPEG < 2.2.0, opj_image_create), CVE-2026-18300 (GEGL
// rgbe_read_scanlines, g_new with a product of header dimensions),
// CVE-2026-55191 (FreeRDP avc444_ensure_buffer), CVE-2026-41445 (KissFFT
// kiss_fftndr_alloc).
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <map>
#include <optional>

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

bool mentions(const Stmt *S, const Keys &K) {
  return raptor_mem::findKey(S, K) != nullptr;
}

bool isAllocator(const CallExpr *CE) {
  std::string N = raptor::calleeName(CE).lower();
  return N.find("alloc") != std::string::npos ||
         N.find("new") != std::string::npos;
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

// Key of a variable, field or array element (`size[x]`: variable or
// literal index) that a size can be stored in.
std::string slotKey(const Expr *E) {
  E = raptor::strip(E);
  if (const auto *ASE = dyn_cast_or_null<ArraySubscriptExpr>(E)) {
    std::string B = raptor_mem::keyOf(ASE->getBase());
    const Expr *I = raptor::strip(ASE->getIdx());
    if (!B.empty())
      if (const auto *DRE = dyn_cast<DeclRefExpr>(I))
        return B + "[" + DRE->getDecl()->getNameAsString() + "]";
  }
  return E ? raptor_mem::keyOf(E) : "";
}

// Slots read by a size expression (not under sizeof or a call, nor the
// factors of a product computed wider than 32 bits: `(size_t)h * bpl` widens
// the total, a 32-bit `bpl` is only the size of a line).
void slotsIn(const Expr *E, Keys &Out, const ASTContext &Ctx) {
  E = raptor::strip(E);
  if (!E || isa<UnaryExprOrTypeTraitExpr>(E) || isa<CallExpr>(E))
    return;
  if (const auto *BO = dyn_cast<BinaryOperator>(E))
    if (BO->getOpcode() == BO_Mul && BO->getType()->isIntegerType() &&
        Ctx.getIntWidth(BO->getType()) > 32)
      return;
  if (isa<DeclRefExpr>(E) || isa<MemberExpr>(E) || isa<ArraySubscriptExpr>(E)) {
    std::string K = slotKey(E);
    if (!K.empty()) {
      Out.insert(K);
      return;
    }
  }
  for (const Stmt *C : E->children())
    if (const auto *CE = dyn_cast_or_null<Expr>(C))
      slotsIn(CE, Out, Ctx);
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

using FieldSet = std::set<const FieldDecl *>;

// The fields among the factors of a `*` chain (casts and parentheses aside);
// false when a non-constant factor is not a field.
bool factorFields(const Expr *E, const ASTContext &Ctx, FieldSet &Out) {
  E = E->IgnoreParenCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(E);
      BO && BO->getOpcode() == BO_Mul)
    return factorFields(BO->getLHS(), Ctx, Out) &&
           factorFields(BO->getRHS(), Ctx, Out);
  if (!E->isValueDependent() && E->isIntegerConstantExpr(Ctx))
    return true;
  if (const auto *ME = dyn_cast<MemberExpr>(E))
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      Out.insert(FD);
      return true;
    }
  return false;
}

// Where the file validates fields where it sets them: in a function that
// assigns the fields, a relational check with a division on them (OpenJPEG
// opj_j2k_read_siz `l_cp->tw = ...; if (l_cp->tw > 65535 / l_cp->th)`), or
// their product computed in 64 bits (libtiff LERC SetupBuffers
// `(uint64_t)sp->segment_width * sp->segment_height`, then checked). A check
// in a function that only reads the fields does not protect other paths.
struct FileGuards {
  std::vector<FieldSet> Sets;
  bool covers(const FieldSet &F) const {
    for (const FieldSet &S : Sets)
      if (std::includes(S.begin(), S.end(), F.begin(), F.end()))
        return true;
    return false;
  }
};
// A product computed in 64 bits from the start: no narrower `*` inside.
bool wideFromStart(const Expr *E, const ASTContext &Ctx) {
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Mul)
    return true;
  QualType T = BO->getType();
  return T->isIntegerType() && !T->isDependentType() &&
         Ctx.getIntWidth(T) >= 64 && wideFromStart(BO->getLHS(), Ctx) &&
         wideFromStart(BO->getRHS(), Ctx);
}
class GuardCollector : public RecursiveASTVisitor<GuardCollector> {
public:
  GuardCollector(const ASTContext &Ctx, FileGuards &G) : Ctx(Ctx), G(G) {}
  bool VisitFunctionDecl(FunctionDecl *FD) {
    const Stmt *Body = FD->doesThisDeclarationHaveABody() ? FD->getBody() : nullptr;
    if (!Body)
      return true;
    FieldSet Assigned;
    std::vector<FieldSet> Cands;
    walk(Body, [&](const Stmt *S) {
      const auto *BO = dyn_cast<BinaryOperator>(S);
      if (!BO)
        return;
      if (BO->isAssignmentOp())
        if (const auto *ME = dyn_cast<MemberExpr>(raptor::strip(BO->getLHS())))
          if (const auto *F = dyn_cast<FieldDecl>(ME->getMemberDecl()))
            Assigned.insert(F);
      if (BO->isRelationalOp()) {
        bool Div = false;
        FieldSet F;
        walk(BO, [&](const Stmt *X) {
          if (const auto *D = dyn_cast<BinaryOperator>(X);
              D && D->getOpcode() == BO_Div)
            Div = true;
          if (const auto *ME = dyn_cast<MemberExpr>(X))
            if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl()))
              F.insert(FD);
        });
        if (Div && F.size() >= 2)
          Cands.push_back(std::move(F));
      } else if (BO->getOpcode() == BO_Mul && !BO->isValueDependent() &&
                 wideFromStart(BO, Ctx)) {
        FieldSet F;
        if (factorFields(BO, Ctx, F) && F.size() >= 2)
          Cands.push_back(std::move(F));
      }
    });
    for (FieldSet &F : Cands)
      if (std::includes(Assigned.begin(), Assigned.end(), F.begin(), F.end()))
        G.Sets.push_back(std::move(F));
    return true;
  }

private:
  const ASTContext &Ctx;
  FileGuards &G;
};

class UncheckedAllocProductChecker : public Checker<check::ASTCodeBody> {
  mutable const TranslationUnitDecl *GuardsTU = nullptr;
  mutable FileGuards Guards;

  const FileGuards &fileGuards(ASTContext &Ctx) const {
    if (GuardsTU != Ctx.getTranslationUnitDecl()) {
      GuardsTU = Ctx.getTranslationUnitDecl();
      Guards = FileGuards();
      GuardCollector(Ctx, Guards).TraverseDecl(Ctx.getTranslationUnitDecl());
    }
    return Guards;
  }

public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();

    // Initialisers and assignments of each local, for `n = a * b; alloc(n)`.
    llvm::DenseMap<const VarDecl *, std::vector<const Expr *>> Defs;
    // Definitions of every slot (variable, field, array element), for
    // `size[x] = stride[x] * h; alloc(size[x])` and chains of locals.
    std::map<std::string, std::vector<const Expr *>> SlotDefs;
    walk(Body, [&](const Stmt *S) {
      if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *Dc : DS->decls())
          if (const auto *VD = dyn_cast<VarDecl>(Dc))
            if (VD->getInit()) {
              Defs[VD].push_back(VD->getInit());
              SlotDefs[VD->getNameAsString()].push_back(VD->getInit());
            }
      } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->getOpcode() == BO_Assign)
          if (std::string K = slotKey(BO->getLHS()); !K.empty())
            SlotDefs[K].push_back(BO->getRHS());
        // A compound assignment is recorded as an unknown (null) definition.
        if (BO->isAssignmentOp())
          if (const auto *DRE =
                  dyn_cast<DeclRefExpr>(raptor::strip(BO->getLHS())))
            if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
              Defs[VD].push_back(BO->getOpcode() == BO_Assign ? BO->getRHS()
                                                              : nullptr);
      } else if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
        if (UO->isIncrementDecrementOp() || UO->getOpcode() == UO_AddrOf)
          if (const auto *DRE =
                  dyn_cast<DeclRefExpr>(raptor::strip(UO->getSubExpr())))
            if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
              Defs[VD].push_back(nullptr);
      }
    });

    // An operand built only from constants and locals that are only ever
    // assigned constants (`stride = 4 * MAXRLVLS;`).
    auto constant = [&](const Expr *E) {
      bool C = true;
      walk(E, [&](const Stmt *X) {
        if (isa<MemberExpr>(X) || isa<CallExpr>(X) ||
            isa<ArraySubscriptExpr>(X))
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
              if (!Dv || Dv->isValueDependent() ||
                  !Dv->isIntegerConstantExpr(Ctx))
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
        if (!A->getType()->isIntegerType())
          continue;
        // The argument, then the definitions of the slots it reads, up to
        // three steps back.
        std::vector<const Expr *> Sizes{A};
        Keys Seen, Frontier;
        slotsIn(A, Frontier, Ctx);
        for (int Depth = 0; Depth < 3 && !Frontier.empty(); ++Depth) {
          Keys Next;
          for (const std::string &K : Frontier) {
            if (!Seen.insert(K).second)
              continue;
            auto It = SlotDefs.find(K);
            if (It == SlotDefs.end())
              continue;
            for (const Expr *E : It->second) {
              Sizes.push_back(E);
              slotsIn(E, Next, Ctx);
            }
          }
          Frontier = std::move(Next);
        }
        for (const Expr *Size : Sizes)
          if (const BinaryOperator *Mul = narrowProduct(Size, Ctx)) {
            Keys L, R;
            keysIn(Mul->getLHS(), L);
            keysIn(Mul->getRHS(), R);
            if (L.empty() || R.empty() || constant(Mul->getLHS()) ||
                constant(Mul->getRHS()) ||
                guarded(Body, CE, Mul, L, R, Seen, Ctx))
              continue;
            // Field factors validated elsewhere in the file.
            if (FieldSet F; factorFields(Mul, Ctx, F) && F.size() >= 2 &&
                            fileGuards(Ctx).covers(F))
              continue;
            raptor::reportAt(
                BR, this, "Unchecked allocation product",
                "Allocation size '" + exprText(Mul, Ctx) +
                    "' is a 32-bit product of run-time values that can wrap "
                    "around and allocate a buffer smaller than the data "
                    "written "
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
        const Expr *L = raptor::strip(BO->getLHS()),
                   *R = raptor::strip(BO->getRHS());
        if (T->isIntegerType() && !T->isDependentType() &&
            Ctx.getTypeSize(T) <= 32 && !L->isValueDependent() &&
            !R->isValueDependent() && !L->isIntegerConstantExpr(Ctx) &&
            !R->isIntegerConstantExpr(Ctx) &&
            raptor::valueBits(BO->getLHS(), Ctx) +
                    raptor::valueBits(BO->getRHS(), Ctx) >
                Ctx.getIntWidth(T) - (T->isSignedIntegerType() ? 1 : 0))
          return BO;
      }
      if (BO->isAdditiveOp() || BO->isMultiplicativeOp() || BO->isShiftOp() ||
          BO->isBitwiseOp()) {
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

  static bool exits(const Stmt *S) {
    bool E = false;
    walk(S, [&](const Stmt *X) {
      if (isa<ReturnStmt>(X) || isa<GotoStmt>(X) || isa<BreakStmt>(X) ||
          isa<ContinueStmt>(X) || isa<CXXThrowExpr>(X))
        E = true;
      else if (const auto *C = dyn_cast<CallExpr>(X);
               C && raptor_mem::neverReturns(C))
        E = true;
    });
    return E;
  }

  static void split(const Expr *E, BinaryOperatorKind Op,
                    std::vector<const Expr *> &Out) {
    E = E->IgnoreParenImpCasts();
    if (const auto *BO = dyn_cast<BinaryOperator>(E);
        BO && BO->getOpcode() == Op) {
      split(BO->getLHS(), Op, Out);
      split(BO->getRHS(), Op, Out);
    } else
      Out.push_back(E);
  }

  // `V op C` (either order) bounding V from above when it is true (WhenTrue)
  // or when it is false: sets K to V's key and C to the bound.
  static bool upper(const Expr *E, bool WhenTrue, std::string &K, uint64_t &C,
                    ASTContext &Ctx) {
    const auto *BO = dyn_cast<BinaryOperator>(E);
    if (!BO || !BO->isRelationalOp())
      return false;
    const Expr *A = raptor::strip(BO->getLHS()),
               *B = raptor::strip(BO->getRHS());
    if (A->isValueDependent() || B->isValueDependent())
      return false;
    BinaryOperatorKind Op = BO->getOpcode();
    std::optional<llvm::APSInt> V = B->getIntegerConstantExpr(Ctx);
    if (!V) {
      V = A->getIntegerConstantExpr(Ctx);
      if (!V)
        return false;
      std::swap(A, B);
      Op = BinaryOperator::reverseComparisonOp(Op);
    }
    bool Less = Op == BO_LT || Op == BO_LE;
    if (Less != WhenTrue)
      return false;
    K = raptor_mem::keyOf(A);
    C = V->isNegative() ? 0 : V->getLimitedValue();
    return !K.empty();
  }

  // Bounds that hold at Call: `if (v > C ...) exit;` or `if (v > C) v = C;`
  // before it, or `if (v < C && ...)` around it.
  static std::map<std::string, uint64_t>
  bounds(const Stmt *Body, const CallExpr *Call, ASTContext &Ctx) {
    const SourceManager &SM = Ctx.getSourceManager();
    SourceLocation At = SM.getExpansionLoc(Call->getBeginLoc());
    std::map<std::string, uint64_t> B;
    auto add = [&](const std::string &K, uint64_t C) {
      auto [It, New] = B.emplace(K, C);
      if (!New)
        It->second = std::min(It->second, C);
    };
    auto before = [&](const Stmt *S) {
      return SM.isBeforeInTranslationUnit(SM.getExpansionLoc(S->getEndLoc()),
                                          At);
    };
    walk(Body, [&](const Stmt *S) {
      // assert(): `c ? (void)0 : __assert_fail(..)`
      if (const auto *CO = dyn_cast<ConditionalOperator>(S)) {
        const auto *Fail =
            dyn_cast<CallExpr>(raptor::strip(CO->getFalseExpr()));
        if (!Fail || !raptor_mem::neverReturns(Fail) || !before(CO))
          return;
        std::vector<const Expr *> Parts;
        split(CO->getCond(), BO_LAnd, Parts);
        std::string K;
        uint64_t C;
        for (const Expr *P : Parts)
          if (upper(P, true, K, C, Ctx))
            add(K, C);
        return;
      }
      const auto *If = dyn_cast<IfStmt>(S);
      if (!If || !If->getCond())
        return;
      // `if (c) ; else exit;` (glibc's assert()), `if (c) {...} else return;`
      if (If->getElse() && exits(If->getElse()) && !exits(If->getThen()) &&
          before(If)) {
        std::vector<const Expr *> Parts;
        split(If->getCond(), BO_LAnd, Parts);
        std::string K;
        uint64_t C;
        for (const Expr *P : Parts)
          if (upper(P, true, K, C, Ctx))
            add(K, C);
        return;
      }
      bool Around = false;
      walk(If->getThen(), [&](const Stmt *X) { Around |= X == Call; });
      std::vector<const Expr *> Parts;
      std::string K;
      uint64_t C;
      if (Around) {
        split(If->getCond(), BO_LAnd, Parts);
        for (const Expr *P : Parts)
          if (upper(P, true, K, C, Ctx))
            add(K, C);
        return;
      }
      if (!before(If))
        return;
      split(If->getCond(), BO_LOr, Parts);
      if (exits(If->getThen())) {
        for (const Expr *P : Parts)
          if (upper(P, false, K, C, Ctx))
            add(K, C);
        return;
      }
      // Clamp: if (v > C) v = C2;
      if (Parts.size() != 1 || !upper(Parts[0], false, K, C, Ctx))
        return;
      const Stmt *T = If->getThen();
      if (const auto *CS = dyn_cast<CompoundStmt>(T); CS && CS->size() == 1)
        T = CS->body_front();
      const auto *As = dyn_cast<BinaryOperator>(T);
      if (!As || As->getOpcode() != BO_Assign ||
          raptor_mem::keyOf(As->getLHS()) != K)
        return;
      if (std::optional<llvm::APSInt> V =
              raptor::strip(As->getRHS())->getIntegerConstantExpr(Ctx))
        add(K,
            std::max<uint64_t>(C, V->isNegative() ? 0 : V->getLimitedValue()));
    });
    return B;
  }

  static bool guarded(const Stmt *Body, const CallExpr *Call,
                      const BinaryOperator *Mul, const Keys &L, const Keys &R,
                      const Keys &Slots, ASTContext &Ctx) {
    // The factors, and the slots the product flows through to the call
    // (`step = a * b; if (step <= UINT_MAX / n) calloc(n * step, ..)`).
    Keys F = L;
    F.insert(R.begin(), R.end());
    F.insert(Slots.begin(), Slots.end());
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
        // a > MAX / b, n <= MAX / c
        if (BO->isRelationalOp() && !LoopConds.count(BO) && mentions(BO, F))
          walk(BO, [&](const Stmt *X) {
            if (const auto *D = dyn_cast<BinaryOperator>(X))
              if (D->getOpcode() == BO_Div)
                G = true;
          });
      } else if (const auto *CE = dyn_cast<CallExpr>(S)) {
        std::string N = raptor::calleeName(CE).lower();
        if (N.find("overflow") != std::string::npos ||
            N.find("mult") != std::string::npos ||
            N.find("check_size") != std::string::npos)
          for (const Expr *A : CE->arguments())
            if (mentions(A, F))
              G = true;
      }
    });
    if (G)
      return true;
    // Both factors bounded by constants whose product fits.
    std::map<std::string, uint64_t> B = bounds(Body, Call, Ctx);
    auto bound = [&](const Keys &Ks) -> std::optional<uint64_t> {
      std::optional<uint64_t> Best;
      for (const std::string &K : Ks)
        if (auto It = B.find(K); It != B.end())
          Best = Best ? std::min(*Best, It->second) : It->second;
      return Best;
    };
    std::optional<uint64_t> BL = bound(L), BR = bound(R);
    if (!BL || !BR)
      return false;
    QualType T = Mul->getType();
    unsigned W = Ctx.getIntWidth(T) - (T->isSignedIntegerType() ? 1 : 0);
    unsigned __int128 P = (unsigned __int128)*BL * *BR;
    return P < ((unsigned __int128)1 << W);
  }
};
} // namespace

RAPTOR_CHECKER(UncheckedAllocProductChecker, "UncheckedAllocProduct",
               "Allocation sized by an unchecked 32-bit product")
