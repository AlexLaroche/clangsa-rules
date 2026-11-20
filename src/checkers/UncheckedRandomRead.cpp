// raptor.UncheckedRandomRead: random bytes are read and the call is not
// checked for having filled the buffer, so a short or failed read leaves
// zero or stale bytes in a key, nonce or session id (CWE-252, CWE-330).
//
//  - read()/pread()/fread() of a descriptor or FILE* opened in the same
//    function from a random device ("/dev/urandom", "/dev/random",
//    "/dev/hwrng"...): the result must be compared with something other than
//    0 or -1 (the requested length), or accumulated (`done += r`) to handle
//    partial reads. Discarding it, testing it only against 0 or -1
//    (`ret < 0`, `ret <= 0`, `!ret`) or only inside assert(), compiled out
//    by NDEBUG, is reported.
//  - all-or-nothing generators (getrandom, getentropy, RAND_bytes,
//    RAND_priv_bytes, BCryptGenRandom, CryptGenRandom, SecRandomCopyBytes,
//    wc_RNG_GenerateBlock, mbedtls_ctr_drbg_random, mbedtls_hmac_drbg_random,
//    psa_generate_random, gnutls_rnd): reported when the result is discarded
//    or only checked inside assert().
//
// A result that is returned or passed to another function is left to the
// caller; `(void)f()` opts out. Modelled on OpenWrt rpcd fb0302d (session ids: `ret = fread(buf,
// 1, sizeof(buf), f); if (ret < 0)`), libdogecoin b7891cf (keys:
// `assert(len_read == len)`) and Netatalk 2721b62 (AFP nonces: `ret =
// read(fd, buf, len); if (ret <= 0)`).
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {

bool isRandomDevice(const Expr *E) {
  const auto *S = dyn_cast_or_null<StringLiteral>(raptor::strip(E));
  if (!S || S->getCharByteWidth() != 1)
    return false;
  StringRef P = S->getString();
  return P.starts_with("/dev/") && (P.contains("random") || P.contains("hwrng"));
}

// Path argument of an open()/fopen() call, or null.
const Expr *openedPath(const CallExpr *CE) {
  StringRef N = raptor::calleeName(CE);
  if (raptor::isOneOf(N, {"open", "open64", "fopen", "fopen64", "__open_2"}) && CE->getNumArgs() >= 1)
    return CE->getArg(0);
  if (raptor::isOneOf(N, {"openat", "openat64"}) && CE->getNumArgs() >= 2)
    return CE->getArg(1);
  return nullptr;
}

const Stmt *parentSkippingCasts(const Stmt *S, const ParentMap &PM) {
  const Stmt *P = PM.getParent(S);
  while (P && (isa<ParenExpr>(P) || isa<ImplicitCastExpr>(P) ||
               (isa<CStyleCastExpr>(P) && !cast<CStyleCastExpr>(P)->getType()->isVoidType())))
    P = PM.getParent(P);
  return P;
}

bool isWeakConstant(const Expr *E, const ASTContext &Ctx) {
  auto V = intValue(E, Ctx);
  return V && (*V == 0 || *V == -1);
}

// Is S written inside an assert() (removed by NDEBUG)?
bool inAssert(const Stmt *S, const ASTContext &Ctx) {
  const SourceManager &SM = Ctx.getSourceManager();
  SourceLocation L = S->getBeginLoc();
  if (!L.isMacroID())
    return false;
  SourceLocation X = SM.getExpansionLoc(L);
  StringRef Tok = Lexer::getSourceText(CharSourceRange::getTokenRange(X), SM, Ctx.getLangOpts());
  return Tok == "assert";
}

enum class Check { None, Weak, Full, Caller };

// How a use U of the result (the call itself or a variable holding it) is checked.
Check classifyUse(const Expr *U, const ParentMap &PM, const ASTContext &Ctx) {
  const Stmt *P = parentSkippingCasts(U, PM);
  if (!P)
    return Check::None;
  // `(void)f()` ignores the result on purpose (as for raptor.IgnoredStatusReturn)
  if (const auto *C = dyn_cast<CStyleCastExpr>(P); C && C->getType()->isVoidType())
    return Check::Caller;
  if (isa<ReturnStmt>(P) || isa<CallExpr>(P))
    return Check::Caller;
  if (const auto *B = dyn_cast<BinaryOperator>(P)) {
    if (B->isComparisonOp()) {
      if (inAssert(B, Ctx))
        return Check::None;
      const Expr *Other = raptor::strip(B->getLHS()) == raptor::strip(U) ? B->getRHS() : B->getLHS();
      return isWeakConstant(Other, Ctx) ? Check::Weak : Check::Full;
    }
    if (B->isCompoundAssignmentOp() && raptor::strip(B->getRHS()) == raptor::strip(U))
      return Check::Full; // done += r; len -= r;
    if (B->isAdditiveOp())
      return Check::Full; // p = buf + r
    if (B->isLogicalOp())
      return inAssert(B, Ctx) ? Check::None : Check::Weak;
    return Check::None;
  }
  if (const auto *Un = dyn_cast<UnaryOperator>(P); Un && Un->getOpcode() == UO_LNot)
    return inAssert(Un, Ctx) ? Check::None : Check::Weak;
  if (isa<IfStmt>(P) || isa<WhileStmt>(P) || isa<DoStmt>(P) || isa<ForStmt>(P) ||
      isa<ConditionalOperator>(P))
    return inAssert(U, Ctx) ? Check::None : Check::Weak;
  return Check::None;
}

Check strongest(Check A, Check B) { return static_cast<int>(A) > static_cast<int>(B) ? A : B; }

// The variable the call's result is stored in, if any.
const VarDecl *resultVar(const CallExpr *CE, const ParentMap &PM) {
  const Stmt *P = parentSkippingCasts(CE, PM);
  if (const auto *B = dyn_cast_or_null<BinaryOperator>(P); B && B->getOpcode() == BO_Assign)
    if (const auto *DR = dyn_cast<DeclRefExpr>(raptor::strip(B->getLHS())))
      return dyn_cast<VarDecl>(DR->getDecl());
  if (const auto *DS = dyn_cast_or_null<DeclStmt>(P))
    for (const Decl *D : DS->decls())
      if (const auto *V = dyn_cast<VarDecl>(D); V && V->getInit() &&
                                                raptor::strip(V->getInit()) == CE)
        return V;
  return nullptr;
}

Check howChecked(const CallExpr *CE, const Stmt *Body, const ParentMap &PM, const ASTContext &Ctx) {
  if (const VarDecl *V = resultVar(CE, PM)) {
    Check C = Check::None;
    forEach<DeclRefExpr>(Body, [&](const DeclRefExpr *DR) {
      if (DR->getDecl() != V)
        return;
      // skip the assignment of the result itself
      const Stmt *P = parentSkippingCasts(DR, PM);
      if (const auto *B = dyn_cast_or_null<BinaryOperator>(P);
          B && B->getOpcode() == BO_Assign && raptor::strip(B->getLHS()) == DR)
        return;
      Check U = classifyUse(DR, PM, Ctx);
      // `if (ret < 0) return ret;` propagates the failure, it does not hand
      // the byte count to the caller
      if (U == Check::Caller && isa<ReturnStmt>(P))
        for (const Stmt *A = PM.getParent(P); A; A = PM.getParent(A))
          if (const auto *If = dyn_cast<IfStmt>(A)) {
            bool Tests = false;
            forEach<DeclRefExpr>(If->getCond(), [&](const DeclRefExpr *R) {
              Tests |= R->getDecl() == V;
            });
            if (Tests) {
              U = Check::None;
              break;
            }
          }
      C = strongest(C, U);
    });
    return C;
  }
  return classifyUse(CE, PM, Ctx);
}

class UncheckedRandomReadChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    const ASTContext &Ctx = Mgr.getASTContext();
    std::unique_ptr<ParentMap> PM;
    auto Parents = [&]() -> const ParentMap & {
      if (!PM)
        PM = std::make_unique<ParentMap>(const_cast<Stmt *>(Body));
      return *PM;
    };

    // descriptors and FILE*s opened from a random device in this function:
    // the assigned lvalue (`fd`, `r->fd`) or the initialised variable
    llvm::SmallVector<const Expr *, 4> Lvalues;
    llvm::SmallPtrSet<const ValueDecl *, 4> Vars;
    forEach<CallExpr>(Body, [&](const CallExpr *CE) {
      if (!isRandomDevice(openedPath(CE)))
        return;
      const Stmt *P = parentSkippingCasts(CE, Parents());
      if (const auto *B = dyn_cast_or_null<BinaryOperator>(P); B && B->getOpcode() == BO_Assign)
        Lvalues.push_back(B->getLHS());
      else if (const auto *DS = dyn_cast_or_null<DeclStmt>(P))
        for (const Decl *Dc : DS->decls())
          if (const auto *V = dyn_cast<VarDecl>(Dc); V && V->getInit() &&
                                                     raptor::strip(V->getInit()) == CE)
            Vars.insert(V);
    });
    auto IsHandle = [&](const Expr *E) {
      if (const auto *DR = dyn_cast<DeclRefExpr>(raptor::strip(E)); DR && Vars.count(DR->getDecl()))
        return true;
      for (const Expr *H : Lvalues)
        if (sameExpr(H, E))
          return true;
      return false;
    };

    forEach<CallExpr>(Body, [&](const CallExpr *CE) {
      StringRef N = raptor::calleeName(CE);
      bool Device = false;
      if (raptor::isOneOf(N, {"read", "pread", "pread64", "__read_chk"}) && CE->getNumArgs() >= 3)
        Device = IsHandle(CE->getArg(0));
      else if (raptor::isOneOf(N, {"fread", "fread_unlocked", "__fread_chk"}) && CE->getNumArgs() >= 4)
        Device = IsHandle(CE->getArg(CE->getNumArgs() - 1));
      bool AllOrNothing = raptor::isOneOf(
          N, {"getrandom", "getentropy", "RAND_bytes", "RAND_priv_bytes", "RAND_bytes_ex",
              "RAND_priv_bytes_ex", "BCryptGenRandom", "CryptGenRandom", "SecRandomCopyBytes",
              "wc_RNG_GenerateBlock", "mbedtls_ctr_drbg_random", "mbedtls_hmac_drbg_random",
              "psa_generate_random", "gnutls_rnd"});
      if (!Device && !AllOrNothing)
        return;
      Check C = howChecked(CE, Body, Parents(), Ctx);
      if (C == Check::Full || C == Check::Caller || (AllOrNothing && C == Check::Weak))
        return;
      std::string Msg =
          Device
              ? (N + "() from a random device is " +
                 (C == Check::Weak ? "only checked for failure, not for a short read"
                                   : "not checked") +
                 ": a short or failed read leaves part of the buffer unfilled and it is "
                 "used as random data anyway (predictable keys, nonces or ids). Compare the "
                 "result with the requested length, or use getrandom()/getentropy()")
                    .str()
              : (N + "() result is not checked (or only in assert(), removed by NDEBUG): "
                     "if it fails the buffer is used as random data anyway")
                    .str();
      raptor::reportAt(BR, this, "Unchecked read of random bytes", Msg, CE,
                       Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(UncheckedRandomReadChecker, "UncheckedRandomRead",
               "read of random bytes not checked for a short or failed read")
