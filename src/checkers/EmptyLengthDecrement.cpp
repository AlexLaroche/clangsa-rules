// raptor.EmptyLengthDecrement: an unsigned length parameter is decremented
// (`len - 1`, `len - K`) and nothing before it in the function looks at the
// length: no comparison, no `!len`, no `if (len)`. A length of 0 wraps to
// SIZE_MAX, so `buf[len - 1]` reads before the buffer and `(size - 1) / 2`
// or `i < count - 1` become huge (CWE-191 -> CWE-125, CWE-787).
//
//   /* input_len > 0 is guaranteed by mbedtls_pem_read_buffer(). */
//   size_t pad_len = input[input_len - 1];
//
// Only the first decrement of each parameter is reported. Any earlier test
// of the parameter (in source order) counts as a guard, whatever it
// compares with; a check after the use does not. Signed parameters (which
// go negative rather than wrap), locals, and parameters assigned before the
// use are left to other rules. UncheckedUnsignedSubtraction covers lengths
// that are checked, but by less than the subtraction needs.
//
// Mbed TLS CVE-2025-52497 (pem_check_pkcs_padding), Suricata CVE-2025-59149
// (ShortenString).
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include <algorithm>
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {

const ParmVarDecl *unsignedParam(const Expr *E) {
  const auto *DRE = dyn_cast_or_null<DeclRefExpr>(E ? E->IgnoreParenImpCasts() : nullptr);
  const auto *P = DRE ? dyn_cast<ParmVarDecl>(DRE->getDecl()) : nullptr;
  if (!P || !P->getType()->isUnsignedIntegerType() || P->getType()->isBooleanType())
    return nullptr;
  return P;
}

// Names of lengths and counts: `len`, `input_len`, `output_size`, `count`,
// `nbytes`, `n`. Other unsigned values (`a`, `x`, `index`, `L`) wrap on
// purpose in constant-time and modular code.
bool lengthName(StringRef N) {
  std::string L = N.lower();
  StringRef S(L);
  if (S == "n" || S == "sz")
    return true;
  for (StringRef W : {"len", "size", "count", "cnt", "num", "bytes", "nbyte"})
    if (S.contains(W))
      return true;
  return S.ends_with("sz") || S.ends_with("_n");
}

class EmptyLengthDecrementChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();

    // Earliest place each parameter is tested or written.
    std::map<const ParmVarDecl *, SourceLocation> Seen;
    auto see = [&](const ParmVarDecl *P, SourceLocation L) {
      if (!P || L.isInvalid())
        return;
      L = SM.getExpansionLoc(L);
      auto It = Seen.find(P);
      if (It == Seen.end() || SM.isBeforeInTranslationUnit(L, It->second))
        Seen[P] = L;
    };
    forEach<Stmt>(Body, [&](const Stmt *S) {
      if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isComparisonOp()) {
          see(unsignedParam(BO->getLHS()), BO->getBeginLoc());
          see(unsignedParam(BO->getRHS()), BO->getBeginLoc());
        } else if (BO->isLogicalOp()) {
          see(unsignedParam(BO->getLHS()), BO->getBeginLoc());
          see(unsignedParam(BO->getRHS()), BO->getBeginLoc());
        } else if (BO->isAssignmentOp()) {
          see(unsignedParam(BO->getLHS()), BO->getBeginLoc());
        }
      } else if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
        if (UO->getOpcode() == UO_LNot || UO->isIncrementDecrementOp())
          see(unsignedParam(UO->getSubExpr()), UO->getBeginLoc());
      } else if (const auto *If = dyn_cast<IfStmt>(S)) {
        see(unsignedParam(If->getCond()), If->getBeginLoc());
      } else if (const auto *W = dyn_cast<WhileStmt>(S)) {
        see(unsignedParam(W->getCond()), W->getBeginLoc());
      } else if (const auto *CO = dyn_cast<ConditionalOperator>(S)) {
        see(unsignedParam(CO->getCond()), CO->getBeginLoc());
      }
    });

    ParentMap PM(const_cast<Stmt *>(Body));
    auto parentOf = [&](const Stmt *S) {
      const Stmt *P = PM.getParent(S);
      while (P && (isa<ParenExpr>(P) || isa<ImplicitCastExpr>(P) || isa<CStyleCastExpr>(P)))
        P = PM.getParent(P);
      return P;
    };
    std::set<const ParmVarDecl *> Reported;
    std::vector<const BinaryOperator *> Subs;
    forEach<BinaryOperator>(Body, [&](const BinaryOperator *BO) {
      if (BO->getOpcode() == BO_Sub)
        Subs.push_back(BO);
    });
    std::sort(Subs.begin(), Subs.end(), [&](const BinaryOperator *A, const BinaryOperator *B) {
      return SM.isBeforeInTranslationUnit(SM.getExpansionLoc(A->getBeginLoc()),
                                          SM.getExpansionLoc(B->getBeginLoc()));
    });
    for (const BinaryOperator *BO : Subs) {
      const ParmVarDecl *P = unsignedParam(BO->getLHS());
      if (!P || Reported.count(P) || !lengthName(P->getName()))
        continue;
      // bit tricks: ~(size - 1), a & (a - 1)
      const Stmt *Par = parentOf(BO);
      if (const auto *U = dyn_cast_or_null<UnaryOperator>(Par); U && U->getOpcode() == UO_Not)
        continue;
      if (const auto *B = dyn_cast_or_null<BinaryOperator>(Par); B && B->getOpcode() == BO_And)
        continue;
      // `for (p += len - 1; len > 0; ...)`: the loop condition guards it
      bool LoopGuarded = false;
      for (const Stmt *A = Par; A; A = PM.getParent(A))
        if (const auto *F = dyn_cast<ForStmt>(A)) {
          if (F->getInit() && F->getCond() && containsExpr(F->getInit(), BO))
            forEach<DeclRefExpr>(F->getCond(), [&](const DeclRefExpr *R) {
              LoopGuarded |= R->getDecl() == P;
            });
          break;
        }
      if (LoopGuarded)
        continue;
      auto K = intValue(BO->getRHS(), Ctx);
      if (!K || K->isNegative() || K->isZero())
        continue;
      Reported.insert(P); // first decrement only, guarded or not
      SourceLocation Use = SM.getExpansionLoc(BO->getBeginLoc());
      auto It = Seen.find(P);
      if (It != Seen.end() && !SM.isBeforeInTranslationUnit(Use, It->second))
        continue;
      std::string Name = P->getNameAsString();
      raptor::reportAt(BR, this, "Length decremented without a non-zero check",
                       "'" + Name + "' is unsigned and nothing before this checks it, so '" +
                           Name + " - " + std::to_string(K->getZExtValue()) +
                           "' wraps to a huge value when it is smaller (an empty input): "
                           "out-of-bounds access or runaway count (CWE-191). Reject '" +
                           Name + " < " + std::to_string(K->getZExtValue()) + "' first",
                       BO, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(EmptyLengthDecrementChecker, "EmptyLengthDecrement",
               "Unsigned length parameter decremented with no check that it is non-zero")
