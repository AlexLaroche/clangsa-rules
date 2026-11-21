// raptor.MemcpyLengthUnboundedByDest: memcpy()/memmove() into a fixed-size
// array with a length that nothing in the function bounds by that array
// (CWE-120, CWE-787).
//
//   uint8_t bytes[24];                      // a field of *insn
//   if (skipdata_bytes > size) return 0;   // the source size, not 24
//   memcpy(insn->bytes, code, skipdata_bytes);
//
// Destination: an array with a known size of at least 2 elements: a local
// (automatic or static), a global, a parameter declared with a size, or a
// struct field (`char data[1]` and flexible trailing arrays are excluded).
// The length is bounded when it is a constant, when its integer type cannot
// exceed the destination size (a uint8_t into 256 bytes), or when one of the
// variables or strlen() calls it is made of (or, for a local, assigned from)
// appears in a relational comparison with a constant no larger than the
// destination size plus one (`len >= sizeof(buf)`, `len > 63`, MIN(), `?:`).
// A comparison with anything else (the source size, a variable) is not a
// bound on the destination.
//
// capstone CVE-2025-67873 (cs_disasm skipdata bytes into insn->bytes[24]),
// esp-usb CVE-2025-68622 (USB descriptor bLength into a 100-byte local),
// libcoap CVE-2025-34468 (host name into static addrstr[256]), GnuTLS
// CVE-2025-9820 (PKCS#11 token label, strlen() into flabel[32]).
#include "BufHelpers.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {

// Size in bytes of a fixed array destination, or 0.
uint64_t destBytes(const Expr *E, ASTContext &Ctx, std::string &Name) {
  E = raptor::strip(E);
  QualType T;
  if (const auto *DRE = dyn_cast_or_null<DeclRefExpr>(E)) {
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return 0;
    T = isa<ParmVarDecl>(VD) ? cast<ParmVarDecl>(VD)->getOriginalType() : VD->getType();
    Name = VD->getNameAsString();
  } else if (const auto *ME = dyn_cast_or_null<MemberExpr>(E)) {
    T = ME->getMemberDecl()->getType();
    Name = raptor_mem::keyOf(ME);
    if (Name.empty())
      Name = ME->getMemberDecl()->getNameAsString();
  } else {
    return 0;
  }
  const auto *CAT = Ctx.getAsConstantArrayType(T);
  if (!CAT || CAT->getSize().getZExtValue() < 2)
    return 0;
  return Ctx.getTypeSizeInChars(CAT).getQuantity();
}

// Keys of the variables, fields and strlen() arguments a length is made of
// (a field counts as a whole: `a->len` adds "a->len", not "a").
void lengthKeys(const Stmt *S, std::set<std::string> &Keys) {
  if (!S)
    return;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (raptor::isOneOf(raptor::calleeName(CE), {"strlen", "wcslen", "strnlen"}) &&
        CE->getNumArgs() >= 1) {
      // strlen(s) bounds s and pointer differences inside it (`cp - s`)
      std::string K = raptor_mem::keyOf(CE->getArg(0));
      Keys.insert("strlen:" + K);
      if (!K.empty())
        Keys.insert(K);
      return;
    }
    for (const Expr *A : CE->arguments())
      lengthKeys(A, Keys);
    return;
  }
  if (isa<MemberExpr>(S) || isa<DeclRefExpr>(S)) {
    if (const auto *DRE = dyn_cast<DeclRefExpr>(S); DRE && !isa<VarDecl>(DRE->getDecl()))
      return;
    std::string K = raptor_mem::keyOf(cast<Expr>(S));
    if (!K.empty()) {
      Keys.insert(K);
      return;
    }
  }
  if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(S); U && U->getKind() == UETT_SizeOf)
    return;
  for (const Stmt *C : S->children())
    lengthKeys(C, Keys);
}

// Do two field names look related (`tag`/`taglen`, `iv`/`ivlen`, `aid_buf`/`aid_len`)?
bool relatedNames(StringRef A, StringRef B) {
  size_t N = 0;
  while (N < A.size() && N < B.size() && A[N] == B[N])
    ++N;
  return N >= std::min<size_t>(3, std::min(A.size(), B.size())) && N > 0;
}

// Largest value of E's integer type (before any implicit widening).
std::optional<uint64_t> typeMax(const Expr *E, const ASTContext &Ctx) {
  E = E->IgnoreParenImpCasts();
  QualType T = E->getType();
  if (!T->isIntegerType() || T->isBooleanType())
    return std::nullopt;
  unsigned W = Ctx.getIntWidth(T);
  if (W >= 64)
    return std::nullopt;
  return T->isSignedIntegerType() ? (uint64_t(1) << (W - 1)) - 1 : (uint64_t(1) << W) - 1;
}

// Largest value of a length built from constants: `8 + (n % 8 ? 1 : 0)`,
// `x % 16`, `c ? 4 : 8`. None when it depends on anything else.
std::optional<uint64_t> maxValue(const Expr *E, const ASTContext &Ctx, int Depth = 0) {
  if (!E || Depth > 8)
    return std::nullopt;
  E = E->IgnoreParenCasts();
  if (auto V = intValue(E, Ctx))
    return V->isNegative() ? std::nullopt : std::optional<uint64_t>(V->getZExtValue());
  if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
    auto A = maxValue(CO->getTrueExpr(), Ctx, Depth + 1);
    auto B = maxValue(CO->getFalseExpr(), Ctx, Depth + 1);
    if (A && B)
      return std::max(*A, *B);
    return std::nullopt;
  }
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    auto R = maxValue(BO->getRHS(), Ctx, Depth + 1);
    if (BO->getOpcode() == BO_Rem && R && *R > 0)
      return *R - 1;
    if (BO->getOpcode() == BO_And && R)
      return *R;
    auto L = maxValue(BO->getLHS(), Ctx, Depth + 1);
    if (!L || !R)
      return std::nullopt;
    if (BO->getOpcode() == BO_Add && *L < (1ULL << 40) && *R < (1ULL << 40))
      return *L + *R;
    if (BO->getOpcode() == BO_Mul && *L < (1ULL << 20) && *R < (1ULL << 20))
      return *L * *R;
  }
  return std::nullopt;
}

// A call to an algorithm's size getter (EVP_MD_get_size,
// EVP_CIPHER_get_iv_length, mbedtls_md_get_size): the size is fixed by the
// algorithm, not by input. strlen() and friends are not getters.
bool sizeGetter(const Expr *E) {
  const auto *CE = dyn_cast<CallExpr>(E->IgnoreParenCasts());
  if (!CE)
    return false;
  std::string N = raptor::calleeName(CE).lower();
  StringRef S(N);
  if (S.starts_with("str") || S.starts_with("wcs"))
    return false;
  bool Size = S.ends_with("size") || S.ends_with("length") || S.ends_with("_len");
  return Size && (S.contains("get") || S.ends_with("_size") || S.ends_with("_length"));
}

class MemcpyLengthUnboundedByDestChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();

    // Definitions of locals: what each one is assigned from.
    std::map<std::string, std::vector<const Expr *>> Defs;
    forEach<Stmt>(Body, [&](const Stmt *S) {
      if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *Dc : DS->decls())
          if (const auto *V = dyn_cast<VarDecl>(Dc); V && V->getInit())
            Defs[V->getNameAsString()].push_back(V->getInit());
      } else if (const auto *BO = dyn_cast<BinaryOperator>(S); BO && BO->isAssignmentOp()) {
        std::string K = raptor_mem::keyOf(BO->getLHS());
        if (!K.empty())
          Defs[K].push_back(BO->getRHS());
      }
    });
    // Comparisons of a length key with a constant (Value) or with another
    // expression (Other): relational, and equality (`len != ctx->taglen`).
    struct Bound {
      std::string Key;
      std::optional<uint64_t> Value;
      const Expr *Other;
      const BinaryOperator *Cmp;
    };
    std::vector<Bound> Bounds;
    forEach<BinaryOperator>(Body, [&](const BinaryOperator *BO) {
      if (!BO->isComparisonOp())
        return;
      for (int Side = 0; Side < 2; ++Side) {
        const Expr *Var = Side ? BO->getRHS() : BO->getLHS();
        const Expr *Lim = Side ? BO->getLHS() : BO->getRHS();
        auto C = intValue(Lim, Ctx);
        // a local set once from a constant (`s_len = sizeof(scratch)`)
        if (!C)
          if (const auto *LD = dyn_cast<DeclRefExpr>(Lim->IgnoreParenImpCasts());
              LD && isa<VarDecl>(LD->getDecl()) && cast<VarDecl>(LD->getDecl())->hasLocalStorage()) {
            auto It = Defs.find(LD->getDecl()->getNameAsString());
            if (It != Defs.end() && It->second.size() == 1)
              C = intValue(It->second[0], Ctx);
          }
        if (C && C->isNegative())
          continue;
        std::optional<uint64_t> V;
        if (C)
          V = C->getZExtValue();
        std::set<std::string> Keys;
        lengthKeys(Var, Keys);
        // `sp >= cp + sizeof(marker)` bounds `sp - cp`
        if (!C)
          if (const auto *Add = dyn_cast<BinaryOperator>(Lim->IgnoreParenImpCasts());
              Add && Add->getOpcode() == BO_Add && Add->getType()->isPointerType())
            if (auto K2 = intValue(Add->getRHS(), Ctx); K2 && !K2->isNegative()) {
              V = K2->getZExtValue();
              lengthKeys(Add->getLHS(), Keys);
              Lim = Add->getRHS();
            }
        for (const std::string &K : Keys)
          Bounds.push_back({K, V, Lim, BO});
      }
    });
    ParentMap PM(const_cast<Stmt *>(Body));
    const SourceManager &SM = Ctx.getSourceManager();
    // Does the comparison C guard the copy X? It must sit in X itself (MIN),
    // in the condition of an if/loop around X, or in a statement before X in
    // an enclosing block, and not inside the body of some other branch.
    auto guards = [&](const Stmt *C, const Stmt *X) {
      llvm::SmallPtrSet<const Stmt *, 16> Up;
      for (const Stmt *A = X; A; A = PM.getParent(A))
        Up.insert(A);
      const Stmt *N = C;
      while (N && !Up.count(N)) {
        const Stmt *P = PM.getParent(N);
        if (!P)
          return false;
        if (Up.count(P)) { // P is the lowest common ancestor
          if (isa<CompoundStmt>(P)) {
            const Stmt *XC = X;
            while (PM.getParent(XC) != P)
              XC = PM.getParent(XC);
            return SM.isBeforeInTranslationUnit(N->getBeginLoc(), XC->getBeginLoc());
          }
          if (const auto *If = dyn_cast<IfStmt>(P))
            return N == If->getCond();
          if (const auto *W = dyn_cast<WhileStmt>(P))
            return N == W->getCond();
          if (const auto *F = dyn_cast<ForStmt>(P))
            return N == F->getCond();
          if (isa<DoStmt>(P) || isa<SwitchStmt>(P))
            return false;
          return true; // an expression: `len < n ? ... : ...`, `&&`
        }
        // climbing out of a branch body below the common ancestor
        if (const auto *If = dyn_cast<IfStmt>(P); If && N != If->getCond())
          return false;
        if (isa<WhileStmt>(P) || isa<ForStmt>(P) || isa<DoStmt>(P) || isa<SwitchStmt>(P) ||
            isa<CompoundStmt>(P) || isa<CaseStmt>(P) || isa<DefaultStmt>(P) ||
            isa<LabelStmt>(P)) {
          if (const auto *W = dyn_cast<WhileStmt>(P); W && N == W->getCond()) {
          } else if (const auto *F = dyn_cast<ForStmt>(P); F && N == F->getCond()) {
          } else if (isa<LabelStmt>(P) || isa<CaseStmt>(P) || isa<DefaultStmt>(P)) {
          } else {
            return false;
          }
        }
        N = P;
      }
      return N != nullptr; // C inside X
    };

    forEach<CallExpr>(Body, [&](const CallExpr *CE) {
      StringRef N = raptor::calleeName(CE);
      if (!N.consume_front("__builtin___"))
        N.consume_front("__builtin_");
      N.consume_back("_chk");
      if (!raptor::isOneOf(N, {"memcpy", "memmove", "mempcpy"}) || CE->getNumArgs() < 3)
        return;
      std::string Name;
      uint64_t Size = destBytes(CE->getArg(0), Ctx, Name);
      if (!Size)
        return;
      const Expr *Len = CE->getArg(2);
      if (intValue(Len, Ctx))
        return;
      // The length and, for locals, what they are assigned from.
      std::set<std::string> Keys;
      lengthKeys(Len, Keys);
      std::vector<const Expr *> Sources{Len};
      for (const std::string &K : std::set<std::string>(Keys)) {
        auto It = Defs.find(K);
        if (It == Defs.end())
          continue;
        for (const Expr *Def : It->second) {
          lengthKeys(Def, Keys);
          Sources.push_back(Def);
        }
      }
      // A length that cannot exceed the destination, or comes from a size
      // getter, whatever its variables hold.
      if (auto MV = maxValue(Len, Ctx); MV && *MV <= Size)
        return;
      if (sizeGetter(Len))
        return;
      // A global or static length: configuration validated where it is set.
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Len->IgnoreParenCasts()))
        if (const auto *V = dyn_cast<VarDecl>(DRE->getDecl()); V && !V->hasLocalStorage())
          return;
      // A length field of an object other than the source: a parameter
      // set (`pParams->cbHashOutput`), not the size of what is copied. The
      // source's own size field (`memcpy(buf, a->s, a->length)`) is kept.
      if (const auto *LME = dyn_cast<MemberExpr>(Len->IgnoreParenCasts())) {
        const Expr *SrcBase = nullptr;
        if (const auto *SM2 = dyn_cast<MemberExpr>(raptor::strip(CE->getArg(1))))
          SrcBase = SM2->getBase();
        if (!SrcBase || !sameExpr(LME->getBase(), SrcBase))
          return;
      }
      // A plain parameter: the caller's contract.
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Len->IgnoreParenImpCasts());
          DRE && isa<ParmVarDecl>(DRE->getDecl()))
        return;
      // A source array no larger than the destination.
      std::string SrcName;
      const Expr *SrcE = raptor::strip(CE->getArg(1));
      if (const auto *UO = dyn_cast<UnaryOperator>(SrcE); UO && UO->getOpcode() == UO_AddrOf)
        if (const auto *AS = dyn_cast<ArraySubscriptExpr>(raptor::strip(UO->getSubExpr())))
          if (auto I = intValue(AS->getIdx(), Ctx); I && I->isZero())
            SrcE = AS->getBase(); // &a[0]
      if (uint64_t Src = destBytes(SrcE, Ctx, SrcName); Src && Src <= Size)
        return;
      // A length kept in the destination's own object (`ctx->iv`, `ctx->ivlen`).
      const auto *DstME = dyn_cast<MemberExpr>(raptor::strip(CE->getArg(0)));
      const Expr *DstBase = DstME ? DstME->getBase() : nullptr;
      // ... also one level down (`pKey->params.cbHashOutput` for `pKey->abSeed`)
      // or scaled (`r->used * sizeof(digit)` for `r->dp`)
      if (DstBase) {
        bool Own = false;
        forEach<MemberExpr>(Len, [&](const MemberExpr *LME) {
          const Expr *B = LME->getBase();
          for (int I = 0; I < 3 && B && !Own; ++I) {
            Own = sameExpr(B, DstBase);
            const auto *BM = dyn_cast<MemberExpr>(B->IgnoreParenImpCasts());
            B = BM ? BM->getBase() : nullptr;
          }
        });
        if (Own)
          return;
      }
      // A token the parser bounded: `&tok` passed to a call that also takes
      // a constant that fits (`str_quotedword(&line, &tok, MAX_LEN)`), and
      // the length read from it (`str_len(&tok)`).
      {
        bool Parsed = false;
        forEach<CallExpr>(Body, [&](const CallExpr *PC) {
          if (Parsed || PC == CE)
            return;
          bool Fits = false;
          for (const Expr *A : PC->arguments())
            if (auto C = intValue(A, Ctx); C && !C->isNegative() && C->getZExtValue() >= 2 &&
                                            C->getZExtValue() <= Size + 1)
              Fits = true;
          if (!Fits)
            return;
          for (const Expr *A : PC->arguments())
            if (const auto *U = dyn_cast<UnaryOperator>(A->IgnoreParenImpCasts());
                U && U->getOpcode() == UO_AddrOf && containsExpr(Len, U->getSubExpr()))
              Parsed = true;
        });
        if (Parsed)
          return;
      }
      // Every source of the length fits the destination by its type, or is
      // a remainder or mask that fits (`len % 16`).
      bool TypeFits = true;
      for (const Expr *S : Sources) {
        const Expr *X = S->IgnoreParenImpCasts();
        if (isa<DeclRefExpr>(X) && Defs.count(raptor_mem::keyOf(X)) && S == Len)
          continue; // judged by its definitions
        if (const auto *BO = dyn_cast<BinaryOperator>(X)) {
          auto C = intValue(BO->getRHS(), Ctx);
          if (C && !C->isNegative() &&
              ((BO->getOpcode() == BO_Rem && C->getZExtValue() <= Size) ||
               (BO->getOpcode() == BO_And && C->getZExtValue() < Size)))
            continue;
        }
        if (auto MV = maxValue(X, Ctx); MV && *MV <= Size)
          continue;
        if (sizeGetter(X))
          continue;
        auto M = typeMax(X, Ctx);
        if (!M || *M > Size) {
          TypeFits = false;
          break;
        }
      }
      if (TypeFits)
        return;
      // Comparisons inside a local's definition guard it where it is defined.
      std::vector<const Stmt *> Sites{CE};
      for (const Expr *S : Sources)
        if (S != Len)
          Sites.push_back(S);
      for (const Bound &B : Bounds) {
        if (!Keys.count(B.Key))
          continue;
        if (B.Value) {
          // 0 and 1 test for emptiness, not for room
          if (*B.Value < 2 || *B.Value > Size + 1)
            continue;
        } else {
          // a field of the destination's object that goes with it
          const auto *OME = dyn_cast<MemberExpr>(B.Other->IgnoreParenImpCasts());
          if (!OME || !DstBase || !sameExpr(OME->getBase(), DstBase) ||
              !relatedNames(OME->getMemberDecl()->getName(), DstME->getMemberDecl()->getName()))
            continue;
        }
        for (const Stmt *Site : Sites)
          if (Site == CE ? guards(B.Cmp, CE) : (containsExpr(Site, B.Cmp) || guards(B.Cmp, Site)))
            return;
      }
      raptor::reportAt(BR, this, "Copy length unbounded by destination",
                       (N + "() into '" + Name + "' (" + std::to_string(Size) +
                        " bytes) with a length that is never compared with its size "
                        "(only with other limits, or with nothing): buffer overflow "
                        "(CWE-787). Clamp it with MIN(len, sizeof(dst)) or reject longer input")
                           .str(),
                       CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(MemcpyLengthUnboundedByDestChecker, "MemcpyLengthUnboundedByDest",
               "memcpy() into a fixed-size array with a length never bounded by its size")
