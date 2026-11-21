// raptor.FixedOffsetReadNoLengthCheck: a byte buffer passed in together with
// its length is read at a fixed offset (`buf[3]`, `buf[off + 2]`, `*(buf +
// 1)`, `buf + 9` handed to a reader taking a const pointer) and nothing before
// the read compares the length with enough: a truncated input is read past its
// end (CWE-125).
//
//   type = MBEDTLS_GET_UINT32_BE(key, PUBLIC_KEY_TYPE_OFFSET);   // key[0..3]
//   ...
//   if (key_size != MBEDTLS_LMS_PUBLIC_KEY_LEN(type)) return BAD_INPUT;  // late
//
// Buffer and length: a parameter pointing to bytes (char, unsigned char,
// uint8_t; not declared as an array of fixed size) and an integer parameter
// with a length-like name that follows it directly or is named after it
// (`request_pdu`, `request_pdu_len`), and compared with something somewhere
// in the function (a length never compared is a block-size contract, as in
// hash and cipher primitives). Calls count as reads only for readers named for
// their width (a function given `buf + 16` reads what its own length says). Offsets: a constant K >= 1, or V + K
// with V not constant. Only reads count, and only the first unguarded read
// of each buffer is reported.
//
// Guards, anywhere before the read in source order:
//   - a comparison with the length on one side and, on the other side, a
//     non-constant value or (for a constant offset K) a constant >= K;
//     a comparison in which the length is inside arithmetic (`len - off < 4`);
//   - a relational comparison of the buffer pointer (`buf + 4 > end`);
//   - the length assigned, incremented or its address taken;
//   - a switch on the length;
//   - for a constant offset, the length passed to a call (a validating
//     parser); an offset V + K needs a comparison involving a non-constant
//     value, since the call that produced V (`offset = decode(pdu, len)`)
//     only bounds V itself.
//
// Mbed TLS CVE-2025-49601 (mbedtls_lms_import_public_key), BACnet-stack
// CVE-2025-66624 (npdu_is_expected_reply: `request_pdu[offset + 2]` with only
// `request_pdu_len > 0` checked).
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/Support/Regex.h"
#include <algorithm>

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {

bool lengthName(StringRef N) {
  std::string L = N.lower();
  StringRef S(L);
  if (S == "n" || S == "sz")
    return true;
  for (StringRef W : {"len", "size", "count", "cnt", "bytes", "nbyte"})
    if (S.contains(W))
      return true;
  return S.ends_with("sz");
}

bool byteBuffer(const ParmVarDecl *P) {
  if (isa<DecayedType>(P->getType()) || isa<ArrayType>(P->getType()))
    return false; // `unsigned char buf[16]`: sized by its declaration
  const auto *PT = P->getType()->getAs<PointerType>();
  if (!PT)
    return false;
  QualType T = PT->getPointeeType();
  return T->isCharType() || (T->isIntegerType() && !T->isBooleanType() &&
                             P->getASTContext().getTypeSize(T) == 8);
}

const VarDecl *varOf(const Expr *E) {
  const auto *D = dyn_cast_or_null<DeclRefExpr>(E ? E->IgnoreParenImpCasts() : nullptr);
  return D ? dyn_cast<VarDecl>(D->getDecl()) : nullptr;
}

bool mentions(const Stmt *S, const VarDecl *V) {
  bool R = false;
  forEach<DeclRefExpr>(S, [&](const DeclRefExpr *D) { R |= D->getDecl() == V; });
  return R;
}

// Offset of an index expression (later: of the last byte read): constant part K, and whether it has a
// non-constant part.
struct Offset {
  int64_t K = 0;
  bool Var = false;
};
Offset offsetOf(const Expr *E, const ASTContext &Ctx) {
  E = E->IgnoreParenImpCasts();
  if (auto I = intValue(E, Ctx))
    return {I->getExtValue(), false};
  if (const auto *B = dyn_cast<BinaryOperator>(E)) {
    if (B->getOpcode() == BO_Add) {
      Offset L = offsetOf(B->getLHS(), Ctx), R = offsetOf(B->getRHS(), Ctx);
      return {L.K + R.K, L.Var || R.Var};
    }
    if (B->getOpcode() == BO_Sub)
      if (auto I = intValue(B->getRHS(), Ctx)) {
        Offset L = offsetOf(B->getLHS(), Ctx);
        return {L.K - I->getExtValue(), L.Var};
      }
  }
  return {0, true};
}

// Bytes read by a reader whose name gives its width (ntohu32,
// mbedtls_get_unaligned_uint32, Curl_read16_le, get_u64): 2, 4, 8; else 1.
int readerWidth(StringRef Name) {
  static const llvm::Regex R("(get|read|load|ntoh|peek|fetch)[a-z_]*(16|32|64)|"
                             "(16|32|64)[a-z_]*(get|read|load)",
                             llvm::Regex::IgnoreCase);
  llvm::SmallVector<StringRef, 5> M;
  if (!R.match(Name, &M))
    return 1;
  StringRef W = !M[2].empty() ? M[2] : M[3];
  return W == "16" ? 2 : W == "32" ? 4 : 8;
}

class FixedOffsetReadNoLengthCheckChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const auto *FD = dyn_cast<FunctionDecl>(D);
    const Stmt *Body = D->getBody();
    if (!FD || !Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();

    // buffer -> length
    std::map<const VarDecl *, const VarDecl *> Len;
    for (unsigned I = 0; I < FD->getNumParams(); ++I) {
      const ParmVarDecl *B = FD->getParamDecl(I);
      if (!byteBuffer(B) || B->getName().empty())
        continue;
      for (unsigned J = 0; J < FD->getNumParams(); ++J) {
        const ParmVarDecl *L = FD->getParamDecl(J);
        if (!L->getType()->isIntegerType() || L->getType()->isBooleanType() ||
            !lengthName(L->getName()))
          continue;
        if (J == I + 1 || L->getName().starts_with(B->getName())) {
          Len[B] = L;
          break;
        }
      }
    }
    if (Len.empty())
      return;

    ParentMap PM(const_cast<Stmt *>(Body));
    auto loc = [&](const Stmt *S) { return SM.getExpansionLoc(S->getBeginLoc()); };
    auto before = [&](const Stmt *A, SourceLocation L) {
      return SM.isBeforeInTranslationUnit(loc(A), L);
    };

    // Is the read at Use (offset O) of buffer B / length L guarded?
    auto guarded = [&](const VarDecl *B, const VarDecl *L, Offset O, SourceLocation Use) {
      bool G = false;
      forEach<Stmt>(Body, [&](const Stmt *S) {
        if (G || !before(S, Use))
          return;
        if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
          if (BO->isComparisonOp()) {
            for (int Side = 0; Side < 2 && !G; ++Side) {
              const Expr *Mine = Side ? BO->getRHS() : BO->getLHS();
              const Expr *Other = Side ? BO->getLHS() : BO->getRHS();
              if (BO->isRelationalOp() && mentions(Mine, B) &&
                  Mine->IgnoreParenImpCasts()->getType()->isPointerType()) {
                G = true;
                break;
              }
              if (!mentions(Mine, L))
                continue;
              if (varOf(Mine) != L) { // inside arithmetic
                G = true;
                break;
              }
              auto C = intValue(Other, Ctx);
              if (!C)
                G = true;
              else if (!O.Var && C->getExtValue() >= O.K)
                G = true;
            }
          } else if (BO->isAssignmentOp() && varOf(BO->getLHS()) == L) {
            G = true;
          }
        } else if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
          if ((UO->isIncrementDecrementOp() || UO->getOpcode() == UO_AddrOf) &&
              varOf(UO->getSubExpr()) == L)
            G = true;
        } else if (const auto *Sw = dyn_cast<SwitchStmt>(S)) {
          if (mentions(Sw->getCond(), L))
            G = true;
        } else if (const auto *CE = dyn_cast<CallExpr>(S)) {
          if (!O.Var)
            for (const Expr *A : CE->arguments())
              if (varOf(A) == L)
                G = true;
        }
      });
      return G;
    };

    // Reads: (stmt to report, buffer, offset)
    struct Read {
      const Expr *E;
      const VarDecl *B;
      Offset O;
    };
    std::vector<Read> Reads;
    auto isRValue = [&](const Expr *E) {
      const Stmt *P = PM.getParent(E);
      while (P && isa<ParenExpr>(P))
        P = PM.getParent(P);
      const auto *IC = dyn_cast_or_null<ImplicitCastExpr>(P);
      return IC && IC->getCastKind() == CK_LValueToRValue;
    };
    // `B + off` pointer arithmetic: buffer and offset
    auto ptrPlus = [&](const Expr *E, const VarDecl *&B, Offset &O) {
      const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts());
      if (const VarDecl *V = varOf(E); V && Len.count(V)) {
        B = V;
        O = Offset();
        return true;
      }
      if (!BO || BO->getOpcode() != BO_Add)
        return false;
      const Expr *Base = BO->getLHS(), *Idx = BO->getRHS();
      if (!Base->getType()->isPointerType())
        std::swap(Base, Idx);
      B = varOf(Base);
      if (!B || !Len.count(B))
        return false;
      O = offsetOf(Idx, Ctx);
      return true;
    };
    forEach<Expr>(Body, [&](const Expr *E) {
      if (const auto *AS = dyn_cast<ArraySubscriptExpr>(E)) {
        const VarDecl *B = varOf(AS->getBase());
        if (B && Len.count(B) && isRValue(AS))
          Reads.push_back({AS, B, offsetOf(AS->getIdx(), Ctx)});
      } else if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
        const VarDecl *B;
        Offset O;
        if (UO->getOpcode() == UO_Deref && isRValue(UO) && ptrPlus(UO->getSubExpr(), B, O))
          Reads.push_back({UO, B, O});
      } else if (const auto *CE = dyn_cast<CallExpr>(E)) {
        const FunctionDecl *Callee = CE->getDirectCallee();
        if (!Callee)
          return;
        for (unsigned I = 0; I < CE->getNumArgs() && I < Callee->getNumParams(); ++I) {
          const auto *PT = Callee->getParamDecl(I)->getType()->getAs<PointerType>();
          const VarDecl *B;
          Offset O;
          int W = readerWidth(raptor::calleeName(CE));
          if (W > 1 && PT && PT->getPointeeType().isConstQualified() &&
              ptrPlus(CE->getArg(I), B, O)) {
            O.K += W - 1; // last byte read
            Reads.push_back({CE->getArg(I), B, O});
          }
        }
      }
    });
    std::sort(Reads.begin(), Reads.end(), [&](const Read &A, const Read &B) {
      return SM.isBeforeInTranslationUnit(loc(A.E), loc(B.E));
    });

    // Lengths compared with something somewhere in the function. A length
    // never compared is a block-size contract (hash and cipher primitives).
    std::set<const VarDecl *> Compared;
    forEach<Stmt>(Body, [&](const Stmt *S) {
      const Stmt *C = nullptr;
      if (const auto *BO = dyn_cast<BinaryOperator>(S); BO && BO->isComparisonOp())
        C = BO;
      else if (const auto *Sw = dyn_cast<SwitchStmt>(S))
        C = Sw->getCond();
      if (C)
        for (const auto &[B, L] : Len)
          if (mentions(C, L))
            Compared.insert(L);
    });

    std::set<const VarDecl *> Done;
    for (const Read &R : Reads) {
      if (!Compared.count(Len[R.B]))
        continue;
      if (Done.count(R.B) || R.O.K < 1)
        continue;
      const VarDecl *L = Len[R.B];
      if (guarded(R.B, L, R.O, loc(R.E)))
        continue;
      Done.insert(R.B);
      std::string B = R.B->getNameAsString(), N = L->getNameAsString();
      std::string Off = (R.O.Var ? "an offset + " : "offset ") + std::to_string(R.O.K);
      raptor::reportAt(BR, this, "Fixed-offset read without a length check",
                       "'" + B + "' is read at " + Off + " but nothing before this compares '" +
                           N + "' with that offset: a shorter input is read past its end "
                           "(CWE-125). Check '" + N + "' first",
                       R.E, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(FixedOffsetReadNoLengthCheckChecker, "FixedOffsetReadNoLengthCheck",
               "Byte buffer read at a fixed offset before its length is checked")
