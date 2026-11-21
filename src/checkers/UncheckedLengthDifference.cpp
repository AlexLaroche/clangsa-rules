// raptor.UncheckedLengthDifference: an unsigned length A is reduced by a
// non-constant value B (`A - B`, `A -= B`, `A = A - B`) and nothing before
// the subtraction relates the two, so B > A wraps A - B to a huge value that
// then bounds a read, a copy or a loop (CWE-191 -> CWE-125, CWE-787,
// CWE-835).
//
//   auto opacityArraySize = size - colorPoints * 4;   // colorPoints from the file
//   getOpacityAtPosition(opacityPtr, opacityArraySize, colorStop);
//
// A: a variable or field of unsigned type (at least 32 bits, so it wraps
// rather than going negative) with a length-like name. B: not constant
// (`len - 1` is EmptyLengthDecrement's).
//
// Guards, before the subtraction in source order:
//   - a comparison whose operands mention both A and a value of B (`off >
//     len`, `off < len ? len - off : 0`, `for (i = 0; i < len; i++) ...
//     len - i`, `(length - consumed) > length`);
//   - a value of B initialised from an expression that mentions A, or
//     assigned from one outside any branch (`n = len < cap ? len : cap`), or
//     A from B.
// Only the first unguarded subtraction from each A is reported, and only
// when the difference reaches memory: an index, pointer arithmetic, the size
// of mem*/str*n*/alloc/read/write, an argument next to a pointer argument of
// another call, a loop condition (directly or through the local it
// initialises), or, for A -= B, when A is itself tested by a loop condition.
//
// rlottie CVE-2025-0634 (model::Gradient::populate), NetX Duo
// CVE-2025-0727/CVE-2025-2259 (_nx_http_server_put_process).
#include "BufHelpers.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <algorithm>
#include <functional>

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {

bool lengthName(StringRef N) {
  std::string L = N.lower();
  StringRef S(L);
  if (S == "n" || S == "sz")
    return true;
  for (StringRef W : {"len", "size", "count", "cnt", "bytes", "nbyte", "remain"})
    if (S.contains(W))
      return true;
  return S.ends_with("sz");
}

// Keys of the values E mentions (variables and member paths; a variable that
// is only the base of a member path is not a value of its own).
std::set<std::string> values(const Stmt *E, const ParentMap *PM = nullptr) {
  std::set<std::string> K;
  forEach<Expr>(E, [&](const Expr *X) {
    if (!isa<DeclRefExpr>(X) && !isa<MemberExpr>(X))
      return;
    if (PM) {
      const Stmt *P = PM->getParent(X);
      while (P && (isa<ParenExpr>(P) || isa<ImplicitCastExpr>(P)))
        P = PM->getParent(P);
      if (isa_and_nonnull<MemberExpr>(P))
        return;
    }
    if (const auto *D = dyn_cast<DeclRefExpr>(X); D && !isa<VarDecl>(D->getDecl()))
      return;
    std::string S = raptor_mem::keyOf(X);
    if (!S.empty())
      K.insert(S);
  });
  return K;
}

bool meets(const std::set<std::string> &A, const std::set<std::string> &B) {
  for (const auto &S : A)
    if (B.count(S))
      return true;
  return false;
}

class UncheckedLengthDifferenceChecker : public Checker<check::ASTCodeBody> {
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
    auto parentOf = [&](const Stmt *S) {
      const Stmt *P = PM.getParent(S);
      while (P && (isa<ParenExpr>(P) || isa<ImplicitCastExpr>(P) || isa<CStyleCastExpr>(P)))
        P = PM.getParent(P);
      return P;
    };

    // Comparisons and definitions (lhs keys, rhs) for the guards.
    std::vector<const BinaryOperator *> Cmps;
    std::vector<std::pair<std::string, const Stmt *>> Defs; // key, defining expr
    forEach<Stmt>(Body, [&](const Stmt *S) {
      if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isComparisonOp())
          Cmps.push_back(BO);
        else if (BO->getOpcode() == BO_Assign && parentOf(BO) &&
                 (isa<CompoundStmt>(parentOf(BO)) && parentOf(BO) == Body)) {
          std::string K = raptor_mem::keyOf(BO->getLHS());
          if (!K.empty())
            Defs.push_back({K, BO});
        }
      } else if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *Dc : DS->decls())
          if (const auto *V = dyn_cast<VarDecl>(Dc); V && V->getInit())
            Defs.push_back({V->getNameAsString(), DS});
      } else if (const auto *CE = dyn_cast<CallExpr>(S)) {
        // `read(p, len, &n)`: n is defined by a call (given the call's
        // arguments)
        for (const Expr *A : CE->arguments())
          if (const auto *U = dyn_cast<UnaryOperator>(A->IgnoreParenImpCasts());
              U && U->getOpcode() == UO_AddrOf) {
            std::string K = raptor_mem::keyOf(U->getSubExpr());
            if (!K.empty())
              Defs.push_back({K, CE});
          }
      }
    });

    // Does the value of E reach memory? (EmptyLengthDecrement's walk, plus
    // calls that take a pointer next to it.)
    std::function<bool(const Expr *, int)> reaches = [&](const Expr *E, int Depth) -> bool {
      const Stmt *Cur = E;
      for (const Stmt *P = PM.getParent(Cur); P; Cur = P, P = PM.getParent(P)) {
        if (isa<ParenExpr>(P) || isa<ImplicitCastExpr>(P) || isa<CStyleCastExpr>(P) ||
            isa<ConditionalOperator>(P))
          continue;
        if (const auto *AS = dyn_cast<ArraySubscriptExpr>(P))
          return Cur == AS->getIdx();
        if (const auto *B = dyn_cast<BinaryOperator>(P)) {
          if (B->getType()->isPointerType() || B->getLHS()->getType()->isPointerType())
            return B->isAdditiveOp() || B->getOpcode() == BO_AddAssign ||
                   B->getOpcode() == BO_SubAssign;
          if (B->isComparisonOp()) {
            const Stmt *L = PM.getParent(B);
            while (L && (isa<ParenExpr>(L) || isa<ImplicitCastExpr>(L) ||
                         (isa<BinaryOperator>(L) && cast<BinaryOperator>(L)->isLogicalOp())))
              L = PM.getParent(L);
            return L && (isa<ForStmt>(L) || isa<WhileStmt>(L) || isa<DoStmt>(L));
          }
          if (B->getOpcode() == BO_Assign && Cur == B->getRHS() && Depth == 0) {
            const auto *DR = dyn_cast<DeclRefExpr>(B->getLHS()->IgnoreParenImpCasts());
            const auto *V = DR ? dyn_cast<VarDecl>(DR->getDecl()) : nullptr;
            if (!V || !V->hasLocalStorage())
              return false;
            bool R = false;
            forEach<DeclRefExpr>(Body, [&](const DeclRefExpr *U) {
              if (!R && U != DR && U->getDecl() == V && !before(U, B))
                R = reaches(U, 1);
            });
            return R;
          }
          if (B->isAssignmentOp() || B->isLogicalOp() || B->getOpcode() == BO_Comma)
            return false;
          continue;
        }
        if (const auto *CE = dyn_cast<CallExpr>(P)) {
          StringRef N = raptor::calleeName(CE);
          N.consume_front("__builtin_");
          if (raptor::isOneOf(N, {"memcpy", "memmove", "memset", "memcmp", "mempcpy", "memchr",
                                  "strncpy", "strncat", "strndup", "strncmp", "malloc",
                                  "calloc", "realloc", "alloca", "read", "write", "fread",
                                  "fwrite", "snprintf", "vsnprintf"}))
            return true;
          if (Cur == CE->getCallee())
            return false;
          for (const Expr *A : CE->arguments())
            if (A != Cur && A->IgnoreParenImpCasts()->getType()->isPointerType() &&
                !isa<StringLiteral>(A->IgnoreParenImpCasts()))
              return true;
          return false;
        }
        if (const auto *DS = dyn_cast<DeclStmt>(P)) {
          if (Depth > 0)
            return false;
          for (const Decl *Dc : DS->decls())
            if (const auto *V = dyn_cast<VarDecl>(Dc); V && V->getInit() && V->hasLocalStorage()) {
              bool R = false;
              forEach<DeclRefExpr>(Body, [&](const DeclRefExpr *U) {
                if (!R && U->getDecl() == V)
                  R = reaches(U, 1);
              });
              if (R)
                return true;
            }
          return false;
        }
        return false;
      }
      return false;
    };
    // Is the variable/field with key K tested by a loop condition?
    auto loopTested = [&](const std::string &K) {
      bool R = false;
      forEach<Stmt>(Body, [&](const Stmt *S) {
        const Expr *C = nullptr;
        if (const auto *W = dyn_cast<WhileStmt>(S))
          C = W->getCond();
        else if (const auto *Do = dyn_cast<DoStmt>(S))
          C = Do->getCond();
        else if (const auto *F = dyn_cast<ForStmt>(S))
          C = F->getCond();
        if (C && values(C).count(K))
          R = true;
      });
      return R;
    };

    std::vector<const BinaryOperator *> Subs;
    forEach<BinaryOperator>(Body, [&](const BinaryOperator *BO) {
      if (BO->getOpcode() == BO_Sub || BO->getOpcode() == BO_SubAssign)
        Subs.push_back(BO);
    });
    std::sort(Subs.begin(), Subs.end(),
              [&](const BinaryOperator *A, const BinaryOperator *B) { return before(A, B); });

    std::set<std::string> Done;
    for (const BinaryOperator *BO : Subs) {
      const Expr *A = BO->getLHS()->IgnoreParenImpCasts();
      QualType T = BO->getOpcode() == BO_SubAssign ? A->getType() : BO->getType();
      if (!T->isUnsignedIntegerType() || T->isBooleanType() || Ctx.getTypeSize(T) < 32)
        continue;
      if (!A->getType()->isUnsignedIntegerType() || Ctx.getTypeSize(A->getType()) < 32)
        continue;
      if (!isa<DeclRefExpr>(A) && !isa<MemberExpr>(A))
        continue;
      const ValueDecl *AD = refDecl(A);
      if (!AD || !lengthName(AD->getName()))
        continue;
      std::string AK = raptor_mem::keyOf(A);
      if (AK.empty() || Done.count(AK) || intValue(BO->getRHS(), Ctx))
        continue;
      std::set<std::string> BK = values(BO->getRHS(), &PM);
      BK.erase(AK);
      if (BK.empty())
        continue;
      // `c->dlen - c->w_offset`: two cursor fields of one object
      if (const auto *AM = dyn_cast<MemberExpr>(A)) {
        std::string Base = raptor_mem::keyOf(AM->getBase());
        bool Same = false;
        for (const auto &K : BK)
          Same |= !Base.empty() && K.rfind(Base + (AM->isArrow() ? "->" : "."), 0) == 0;
        if (Same)
          continue;
      }

      // A -= B, A = A - B: the new A must be what a loop tests or what
      // reaches memory.
      bool SelfUpdate = BO->getOpcode() == BO_SubAssign;
      if (const auto *As = dyn_cast_or_null<BinaryOperator>(parentOf(BO));
          As && As->getOpcode() == BO_Assign && raptor_mem::keyOf(As->getLHS()) == AK)
        SelfUpdate = true;
      if (SelfUpdate ? !loopTested(AK) : !reaches(BO, 0))
        continue;
      Done.insert(AK);

      bool G = false;
      for (const BinaryOperator *C : Cmps) {
        if (!before(C, BO))
          continue;
        std::set<std::string> V = values(C);
        if (V.count(AK) && meets(V, BK)) {
          G = true;
          break;
        }
      }
      for (const auto &[K, S] : Defs) {
        if (G || !before(S, BO) || containsExpr(S, BO))
          continue;
        const Stmt *Rhs = S;
        if (const auto *As = dyn_cast<BinaryOperator>(S))
          Rhs = As->getRHS();
        std::set<std::string> V = values(Rhs);
        if ((BK.count(K) && V.count(AK)) || (K == AK && meets(V, BK)))
          G = true;
      }
      if (G)
        continue;
      std::string B = Lexer::getSourceText(
                          CharSourceRange::getTokenRange(BO->getRHS()->getSourceRange()), SM,
                          Ctx.getLangOpts())
                          .str();
      if (B.size() > 40 || B.empty())
        B = "the amount subtracted";
      else
        B = "'" + B + "'";
      raptor::reportAt(BR, this, "Unsigned length difference without a check",
                       "'" + AK + "' is unsigned and nothing before this compares it with " + B +
                           ": when that is larger the difference wraps to a huge value "
                           "that bounds a later read, copy or loop (CWE-191). Check '" + AK +
                           " >= ...' first",
                       BO, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(UncheckedLengthDifferenceChecker, "UncheckedLengthDifference",
               "Unsigned length reduced by an unrelated value with no comparison of the two")
