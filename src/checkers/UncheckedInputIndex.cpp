// raptor.UncheckedInputIndex: a local set from a value decoded from an input
// buffer indexes a fixed-size array smaller than the value's range, and
// nothing before the access checks it (CWE-129 -> CWE-125, CWE-787).
//
//   from = RFIFOW(fd, 2);                 // *(uint16 *)(rdata + pos + 2)
//   if (... sd->char_moves[from] <= 0)    // char_moves[MAX_CHARS]
//
// Sources (casts, `+ K` and parentheses aside): a load through a cast
// pointer, `*(uint16_t *)p` (plain `p[i]` reads are mostly the program's own
// tables), and byte-order or reader calls (ntohs, be32toh, get_u16, read32...). The
// value's range is that of the narrower of the loaded type and the local;
// `& K` and `% K` limit it to K. The latest assignment of the local before
// the access must be such a source.
// Sink: an index (the local itself, or the local +/- a constant) of an array
// declared with N elements (variable, global or field), N <= the largest
// value.
// Guards, before the access in source order: a comparison with the local on
// one side (outside an index) and anything but 0 or 1 on the other, a switch
// on it, or a call that takes it (a validating helper). Only the first
// unguarded access per local is reported.
//
// rAthena CVE-2025-58750 (chclif_parse_moveCharSlot).
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/Support/Regex.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {

const VarDecl *localOf(const Expr *E) {
  const auto *D = dyn_cast_or_null<DeclRefExpr>(E ? E->IgnoreParenImpCasts() : nullptr);
  const auto *V = D ? dyn_cast<VarDecl>(D->getDecl()) : nullptr;
  return V && V->hasLocalStorage() && !isa<ParmVarDecl>(V) ? V : nullptr;
}

bool readerCall(StringRef N) {
  static const llvm::Regex R("^(ntoh[sl]|ntohll|be(16|32|64)toh|le(16|32|64)toh|"
                             ".*(get|read|load|fetch|peek)_?u?(int)?(8|16|32|64).*|"
                             ".*u(8|16|32|64)_?(get|read|load).*)$",
                             llvm::Regex::IgnoreCase);
  return R.match(N);
}

// Largest value E can hold if it is a source; nullopt if it is not one.
std::optional<uint64_t> sourceMax(const Expr *E, const ASTContext &Ctx) {
  E = E->IgnoreParenCasts();
  if (const auto *B = dyn_cast<BinaryOperator>(E)) {
    if (B->getOpcode() == BO_And || B->getOpcode() == BO_Rem) {
      auto K = intValue(B->getRHS(), Ctx);
      auto S = sourceMax(B->getLHS(), Ctx);
      if (!S)
        return std::nullopt;
      if (K && !K->isNegative())
        return B->getOpcode() == BO_And ? std::min<uint64_t>(*S, K->getZExtValue())
                                        : std::min<uint64_t>(*S, K->getZExtValue() - 1);
      return S;
    }
    if (B->getOpcode() == BO_Add || B->getOpcode() == BO_Sub) {
      if (intValue(B->getRHS(), Ctx))
        return sourceMax(B->getLHS(), Ctx);
      return std::nullopt;
    }
    return std::nullopt;
  }
  auto range = [&](QualType T) -> std::optional<uint64_t> {
    if (!T->isIntegerType() || T->isBooleanType())
      return std::nullopt;
    unsigned W = Ctx.getTypeSize(T);
    if (W >= 64)
      return UINT64_MAX;
    return T->isSignedIntegerType() ? (uint64_t(1) << (W - 1)) - 1 : (uint64_t(1) << W) - 1;
  };
  // `*(uint16_t *)p`: a wire field loaded through a cast pointer (plain
  // `p[i]` / `*p` reads are mostly the program's own tables)
  if (const auto *U = dyn_cast<UnaryOperator>(E); U && U->getOpcode() == UO_Deref) {
    const auto *C = dyn_cast<CStyleCastExpr>(U->getSubExpr()->IgnoreParens());
    if (C && C->getType()->isPointerType())
      return range(U->getType());
    return std::nullopt;
  }
  if (const auto *CE = dyn_cast<CallExpr>(E))
    if (readerCall(raptor::calleeName(CE)))
      return range(CE->getType());
  return std::nullopt;
}

class UncheckedInputIndexChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();
    ParentMap PM(const_cast<Stmt *>(Body));
    auto loc = [&](const Stmt *S) { return SM.getExpansionLoc(S->getBeginLoc()); };
    auto before = [&](const Stmt *A, const Stmt *B) {
      return SM.isBeforeInTranslationUnit(loc(A), loc(B));
    };

    // Definitions of locals: (local, defining stmt, value expr)
    struct Def {
      const VarDecl *V;
      const Stmt *S;
      const Expr *E;
    };
    std::vector<Def> Defs;
    forEach<Stmt>(Body, [&](const Stmt *S) {
      if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (const VarDecl *V = localOf(BO->getLHS()); V && BO->isAssignmentOp())
          Defs.push_back({V, BO, BO->getOpcode() == BO_Assign ? BO->getRHS() : nullptr});
      } else if (const auto *U = dyn_cast<UnaryOperator>(S)) {
        if (const VarDecl *V = localOf(U->getSubExpr());
            V && (U->isIncrementDecrementOp() || U->getOpcode() == UO_AddrOf))
          Defs.push_back({V, U, nullptr});
      } else if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *Dc : DS->decls())
          if (const auto *V = dyn_cast<VarDecl>(Dc); V && V->getInit())
            Defs.push_back({V, V->getInit(), V->getInit()});
      }
    });

    // Is the use of V at Use guarded?
    auto inIndex = [&](const Stmt *S) {
      for (const Stmt *P = PM.getParent(S); P; P = PM.getParent(P))
        if (isa<ArraySubscriptExpr>(P))
          return true;
      return false;
    };
    auto guarded = [&](const VarDecl *V, const Stmt *Use) {
      bool G = false;
      forEach<Stmt>(Body, [&](const Stmt *S) {
        if (G || !before(S, Use))
          return;
        if (const auto *BO = dyn_cast<BinaryOperator>(S); BO && BO->isComparisonOp()) {
          for (int Side = 0; Side < 2 && !G; ++Side) {
            const Expr *Mine = Side ? BO->getRHS() : BO->getLHS();
            const Expr *Them = Side ? BO->getLHS() : BO->getRHS();
            bool Has = false;
            forEach<DeclRefExpr>(Mine, [&](const DeclRefExpr *R) {
              Has |= R->getDecl() == V && !inIndex(R);
            });
            if (!Has || inIndex(BO))
              continue;
            if (auto K = intValue(Them, Ctx); K && K->getExtValue() <= 1)
              continue;
            G = true;
          }
        } else if (const auto *Sw = dyn_cast<SwitchStmt>(S)) {
          forEach<DeclRefExpr>(Sw->getCond(), [&](const DeclRefExpr *R) { G |= R->getDecl() == V; });
        } else if (const auto *CE = dyn_cast<CallExpr>(S)) {
          if (sourceMax(CE, Ctx))
            return;
          for (const Expr *A : CE->arguments())
            if (localOf(A) == V)
              G = true;
        }
      });
      return G;
    };

    std::set<const VarDecl *> Done;
    std::vector<const ArraySubscriptExpr *> Uses;
    forEach<ArraySubscriptExpr>(Body, [&](const ArraySubscriptExpr *AS) { Uses.push_back(AS); });
    std::sort(Uses.begin(), Uses.end(),
              [&](const ArraySubscriptExpr *A, const ArraySubscriptExpr *B) { return before(A, B); });
    for (const ArraySubscriptExpr *AS : Uses) {
      const Expr *Base = AS->getBase()->IgnoreParenImpCasts();
      const auto *CAT = Ctx.getAsConstantArrayType(Base->getType());
      if (!CAT || !(isa<DeclRefExpr>(Base) || isa<MemberExpr>(Base)))
        continue;
      const Expr *Idx = AS->getIdx()->IgnoreParenImpCasts();
      if (const auto *B = dyn_cast<BinaryOperator>(Idx);
          B && B->isAdditiveOp() && intValue(B->getRHS(), Ctx))
        Idx = B->getLHS()->IgnoreParenImpCasts();
      const VarDecl *V = localOf(Idx);
      if (!V || Done.count(V))
        continue;
      const Def *Last = nullptr;
      for (const Def &Df : Defs)
        if (Df.V == V && before(Df.S, AS) && (!Last || before(Last->S, Df.S)))
          Last = &Df;
      if (!Last || !Last->E)
        continue;
      auto Max = sourceMax(Last->E, Ctx);
      if (!Max)
        continue;
      if (unsigned W = Ctx.getTypeSize(V->getType()); W < 64)
        Max = std::min<uint64_t>(*Max, (uint64_t(1) << W) - 1);
      uint64_t N = CAT->getSize().getZExtValue();
      if (*Max < N)
        continue;
      Done.insert(V);
      if (guarded(V, AS))
        continue;
      std::string Name = V->getNameAsString();
      raptor::reportAt(BR, this, "Index from input not checked",
                       "'" + Name + "' is read from an input buffer (up to " +
                           std::to_string(*Max) + ") and indexes an array of " +
                           std::to_string(N) + " elements with no check before: "
                           "out-of-bounds access (CWE-129). Check '" + Name + " < " +
                           std::to_string(N) + "' first",
                       AS, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(UncheckedInputIndexChecker, "UncheckedInputIndex",
               "Value decoded from input used as an index of a smaller fixed-size array unchecked")
