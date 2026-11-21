// raptor.SumBoundsCheckWraps: a bounds check `pos + n > LIMIT` (or `LIMIT <
// pos + n`, `>=`, `<=`) computed in 32-bit unsigned arithmetic, where neither
// pos nor n is bounded on its own, and pos or n is then used to reach memory.
// A huge n wraps the sum below LIMIT, the check passes, and the copy or index
// that follows goes out of bounds (CWE-190 -> CWE-787, CWE-125).
//
//   if (is_viewer->buffer_pos + word > IS_BUFFER_SIZE) { ...; return; }
//   memcpy(&is_viewer->output_buffer[is_viewer->buffer_pos], src, word);
//
// The sum: `A + B` with both terms not constant, each at least 32 bits wide,
// and the addition done in an unsigned type of at most 32 bits (64-bit sums would need a 2^64 length;
// 8/16-bit terms are promoted to int). LIMIT does not mention A or B.
// Bounded: a relational comparison with A or B alone on one side and, on the
// other, anything but 0 or 1 and the other term, before the check in source
// order or in the same condition (`pos > MAX || n > MAX || pos + n > MAX`).
// The check is reported when neither term is bounded, and A or B appears
// later in an index, in pointer arithmetic, or as an argument of
// mem*/str*n*/read/write.
//
// mupen64plus CVE-2025-9688 (write_is_viewer), Fast DDS CVE-2025-62601
// (CDRMessage::readData). Checks inside macro expansions (BUG_ON) are skipped.
// IntegerWraparound covers `x > MAX || x + n > MAX`.
#include "BufHelpers.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {

std::string key(const Expr *E) {
  E = E->IgnoreParenImpCasts();
  if (!isa<DeclRefExpr>(E) && !isa<MemberExpr>(E))
    return "";
  return raptor_mem::keyOf(E);
}

bool mentionsKey(const Stmt *S, const std::string &K) {
  bool R = false;
  forEach<Expr>(S, [&](const Expr *E) {
    if (!R && (isa<DeclRefExpr>(E) || isa<MemberExpr>(E)) && raptor_mem::keyOf(E) == K)
      R = true;
  });
  return R;
}

class SumBoundsCheckWrapsChecker : public Checker<check::ASTCodeBody> {
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

    std::vector<const BinaryOperator *> Rel;
    forEach<BinaryOperator>(Body, [&](const BinaryOperator *BO) {
      if (BO->isRelationalOp())
        Rel.push_back(BO);
    });
    // The condition (top of the && / || chain) a comparison belongs to.
    auto condOf = [&](const Stmt *S) {
      const Stmt *Cur = S;
      for (const Stmt *P = PM.getParent(S); P; Cur = P, P = PM.getParent(P)) {
        if (isa<ParenExpr>(P) || isa<ImplicitCastExpr>(P) ||
            (isa<BinaryOperator>(P) && cast<BinaryOperator>(P)->isLogicalOp()) ||
            (isa<UnaryOperator>(P) && cast<UnaryOperator>(P)->getOpcode() == UO_LNot))
          continue;
        break;
      }
      return Cur;
    };
    // Is K bounded by a comparison other than Check (not mentioning Other)?
    auto bounded = [&](const std::string &K, const std::string &Other,
                       const BinaryOperator *Check) {
      const Stmt *Cond = condOf(Check);
      for (const BinaryOperator *C : Rel) {
        if (C == Check || !(before(C, Check) || containsExpr(Cond, C)))
          continue;
        for (int Side = 0; Side < 2; ++Side) {
          const Expr *Mine = Side ? C->getRHS() : C->getLHS();
          const Expr *Them = Side ? C->getLHS() : C->getRHS();
          if (key(Mine) != K || mentionsKey(Them, Other))
            continue;
          if (auto V = intValue(Them, Ctx); V && V->getExtValue() <= 1)
            continue;
          return true;
        }
      }
      return false;
    };
    // Is K used after S to reach memory?
    auto usedForMemory = [&](const std::string &K, const Stmt *S) {
      bool R = false;
      forEach<Expr>(Body, [&](const Expr *E) {
        if (R || !before(S, E))
          return;
        if (const auto *AS = dyn_cast<ArraySubscriptExpr>(E))
          R = mentionsKey(AS->getIdx(), K);
        else if (const auto *B = dyn_cast<BinaryOperator>(E);
                 B && B->isAdditiveOp() && B->getType()->isPointerType())
          R = mentionsKey(B->getLHS(), K) || mentionsKey(B->getRHS(), K);
        else if (const auto *CE = dyn_cast<CallExpr>(E)) {
          StringRef N = raptor::calleeName(CE);
          N.consume_front("__builtin_");
          if (raptor::isOneOf(N, {"memcpy", "memmove", "memset", "memcmp", "mempcpy",
                                  "strncpy", "strncat", "strncmp", "read", "write", "fread",
                                  "fwrite", "recv", "send"}))
            for (const Expr *A : CE->arguments())
              R |= mentionsKey(A, K);
        }
      });
      return R;
    };

    for (const BinaryOperator *C : Rel) {
      const Expr *L = C->getLHS()->IgnoreParenImpCasts();
      const Expr *Rt = C->getRHS()->IgnoreParenImpCasts();
      const auto *Sum = dyn_cast<BinaryOperator>(
          (C->getOpcode() == BO_GT || C->getOpcode() == BO_GE) ? L : Rt);
      const Expr *Limit = (C->getOpcode() == BO_GT || C->getOpcode() == BO_GE) ? Rt : L;
      if (!Sum || Sum->getOpcode() != BO_Add)
        continue;
      QualType T = Sum->getType();
      if (!T->isUnsignedIntegerType() || Ctx.getTypeSize(T) > 32)
        continue;
      if (intValue(Sum->getLHS(), Ctx) || intValue(Sum->getRHS(), Ctx))
        continue;
      // a term narrower than 32 bits cannot wrap the sum
      if (Ctx.getTypeSize(Sum->getLHS()->IgnoreParenImpCasts()->getType()) < 32 ||
          Ctx.getTypeSize(Sum->getRHS()->IgnoreParenImpCasts()->getType()) < 32)
        continue;
      // assertions written as macros (BUG_ON(off + len > size))
      if (C->getBeginLoc().isMacroID())
        continue;
      std::string A = key(Sum->getLHS()), B = key(Sum->getRHS());
      if (A.empty() || B.empty() || A == B)
        continue;
      if (mentionsKey(Limit, A) || mentionsKey(Limit, B))
        continue;
      if (bounded(A, B, C) || bounded(B, A, C))
        continue;
      if (!usedForMemory(A, C) && !usedForMemory(B, C))
        continue;
      raptor::reportAt(BR, this, "Bounds check defeated by integer wraparound",
                       "'" + A + " + " + B + "' is computed in " + std::to_string(Ctx.getTypeSize(T)) +
                           "-bit unsigned arithmetic and neither term is bounded first: a "
                           "large '" + B + "' wraps the sum, the check passes and the access "
                           "that follows goes out of bounds (CWE-190). Check '" + B +
                           " > LIMIT - " + A + "' instead",
                       C, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(SumBoundsCheckWrapsChecker, "SumBoundsCheckWraps",
               "32-bit bounds check on a sum of two unbounded values, defeated by wraparound")
