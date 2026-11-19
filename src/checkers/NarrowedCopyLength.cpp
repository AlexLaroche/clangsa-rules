// raptor.NarrowedCopyLength: a copy length is narrowed, the narrowed value
// decides how big the destination is, and the copy then uses the full length
// (CWE-197, CWE-787):
//
//   int used = (pos) + (int)(n);                          // narrowed
//   if (buf->alloc < (unsigned int)used) grow(buf, used); // sizes the buffer
//   memcpy(buf->p + pos, bytes, n);                       // full length
//
// For a local or parameter V (an integer) passed as the length of
// memcpy/memmove (or bcopy/CopyMemory) in a function:
//   - a narrowing of an expression that mentions V (an explicit cast, or an
//     implicit integral conversion, to a type narrower than both the
//     expression and V),
//   - that sizes the destination: it is, or is stored in a local X that is,
//     part of an allocation size (a callee named *alloc*) or of a relational
//     comparison (a capacity check that decides whether to grow),
//   - and V itself is never compared (`if (len > INT_MAX - pos)`, PHP's fix
//     `if ((size_t)data_size < data_len)`), nor tested for (in)equality with
//     the local it was narrowed into (OpenSSL `dlen != (size_t)ilen`): such a
//     check bounds the narrowing.
// Not narrowings of V: a value that provably fits (`15 - ((len + 20) %
// 16)`), and a call's result when V is only one of its arguments.
// Macro expansions are analysed (Onigmo's BBUF_ADD); the report is at the
// narrowing.
//
// Ruby GHSA-3p8q-wmhx-vm2w (Onigmo regint.h BBUF_WRITE through add_bytes,
// fixed in 3.4.13 by computing the size in size_t and capping it), PHP bugs
// #72551/#72552 (ext/mcrypt mcrypt_generic/mdecrypt_generic: `data_size =
// (int)data_len; emalloc(data_size + 1); memcpy(data_s, data, data_len);`).
#include "Common.h"
#include "IntegerConversion.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/DenseMap.h"
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

const VarDecl *localInt(const Expr *E) {
  const auto *DR = dyn_cast_or_null<DeclRefExpr>(E ? E->IgnoreParenImpCasts() : nullptr);
  const auto *VD = DR ? dyn_cast<VarDecl>(DR->getDecl()) : nullptr;
  return VD && VD->hasLocalStorage() && VD->getType()->isIntegerType() ? VD : nullptr;
}

bool mentions(const Stmt *S, const VarDecl *V) {
  bool Found = false;
  walk(S, [&](const Stmt *X) {
    if (const auto *DR = dyn_cast<DeclRefExpr>(X))
      Found |= DR->getDecl() == V;
  });
  return Found;
}

// Does the value of S depend on V directly? A call's result does not count,
// even when V is one of its arguments (`(BYTE)get_digit(p, cb + 2)`).
bool feeds(const Stmt *S, const VarDecl *V) {
  if (!S || isa<CallExpr>(S))
    return false;
  if (const auto *DR = dyn_cast<DeclRefExpr>(S))
    return DR->getDecl() == V;
  for (const Stmt *C : S->children())
    if (feeds(C, V))
      return true;
  return false;
}

bool contains(const Stmt *Outer, const Stmt *Inner) {
  bool Found = false;
  walk(Outer, [&](const Stmt *X) { Found |= X == Inner; });
  return Found;
}

bool isCopy(StringRef Name) {
  return raptor::isOneOf(Name, {"memcpy", "memmove", "__builtin_memcpy", "__builtin_memmove",
                                "__builtin___memcpy_chk", "__builtin___memmove_chk", "bcopy",
                                "CopyMemory", "RtlCopyMemory", "MoveMemory", "RtlMoveMemory"});
}

bool isAlloc(const CallExpr *CE) {
  return raptor::calleeName(CE).lower().find("alloc") != std::string::npos;
}

class NarrowedCopyLengthChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = Ctx.getSourceManager();

    // copy lengths
    llvm::DenseMap<const VarDecl *, const CallExpr *> Copies;
    walk(Body, [&](const Stmt *S) {
      const auto *CE = dyn_cast<CallExpr>(S);
      if (!CE || CE->getNumArgs() < 3 || !isCopy(raptor::calleeName(CE)))
        return;
      if (const VarDecl *V = localInt(CE->getArg(2)); V && !Copies.count(V))
        Copies[V] = CE;
    });
    if (Copies.empty())
      return;

    // narrowings of an expression that mentions a copy length
    struct Narrowing {
      const CastExpr *At;
      const VarDecl *V;
    };
    std::vector<Narrowing> Ns;
    walk(Body, [&](const Stmt *S) {
      const auto *CE = dyn_cast<CastExpr>(S);
      if (!CE || CE->getCastKind() != CK_IntegralCast)
        return;
      QualType To = CE->getType(), From = CE->getSubExpr()->getType();
      if (!To->isIntegerType() || !From->isIntegerType())
        return;
      uint64_t WT = Ctx.getIntWidth(To);
      if (WT >= Ctx.getIntWidth(From))
        return;
      // `15 - ((len + 20) % 16)` fits whatever len is
      if (raptor_int::fits(Ctx, To, CE->getSubExpr(), Body))
        return;
      for (const auto &[V, Copy] : Copies)
        if (WT < Ctx.getIntWidth(V->getType()) && feeds(CE->getSubExpr(), V))
          Ns.push_back({CE, V});
    });
    if (Ns.empty())
      return;

    ParentMap PM(const_cast<Stmt *>(Body));

    // Does E size a buffer: inside an allocation size, or a relational
    // comparison that does not mention V?
    auto sizes = [&](const Stmt *E, const VarDecl *V) {
      for (const Stmt *P = PM.getParent(E); P; P = PM.getParent(P)) {
        if (const auto *CE = dyn_cast<CallExpr>(P))
          return isAlloc(CE);
        if (const auto *BO = dyn_cast<BinaryOperator>(P)) {
          if (BO->isRelationalOp())
            return !mentions(BO, V);
          if (BO->isAssignmentOp() || BO->isLogicalOp() || BO->isCommaOp())
            return false;
        }
        if (!isa<Expr>(P))
          return false;
      }
      return false;
    };
    // the local a narrowing is stored in, if any
    auto storedIn = [&](const CastExpr *N) -> const VarDecl * {
      for (const Stmt *P = PM.getParent(N); P; P = PM.getParent(P)) {
        if (const auto *DS = dyn_cast<DeclStmt>(P)) {
          for (const Decl *Dc : DS->decls())
            if (const auto *VD = dyn_cast<VarDecl>(Dc); VD && VD->getInit() && contains(VD->getInit(), N))
              return VD->getType()->isIntegerType() ? VD : nullptr;
          return nullptr;
        }
        if (const auto *BO = dyn_cast<BinaryOperator>(P); BO && BO->getOpcode() == BO_Assign)
          return contains(BO->getRHS(), N) ? localInt(BO->getLHS()) : nullptr;
        // `i = BIO_write(bio, buf, (unsigned)left)`: i is the call's result
        if (!isa<Expr>(P) || isa<CallExpr>(P))
          return nullptr;
      }
      return nullptr;
    };
    // V compared anywhere outside a comparison that narrows it, or compared
    // for (in)equality with the local X it was narrowed into (`dlen !=
    // (size_t)ilen`)
    auto checked = [&](const VarDecl *V, const VarDecl *X) {
      bool Found = false;
      walk(Body, [&](const Stmt *S) {
        const auto *BO = dyn_cast<BinaryOperator>(S);
        if (!BO || !BO->isComparisonOp() || !mentions(BO, V))
          return;
        if (BO->isEqualityOp()) {
          Found |= X && mentions(BO, X);
          return;
        }
        for (const Narrowing &N : Ns)
          if (N.V == V && contains(BO, N.At))
            return;
        Found = true;
      });
      return Found;
    };

    std::set<unsigned> Done; // one report per line (a macro expands to many casts)
    for (const Narrowing &N : Ns) {
      unsigned Line = SM.getExpansionLineNumber(N.At->getBeginLoc());
      if (Done.count(Line))
        continue;
      const Stmt *Sizer = nullptr;
      const VarDecl *X = storedIn(N.At);
      if (X == N.V)
        X = nullptr;
      if (sizes(N.At, N.V))
        Sizer = N.At;
      else if (X)
        walk(Body, [&](const Stmt *S) {
          if (const auto *DR = dyn_cast<DeclRefExpr>(S); !Sizer && DR && DR->getDecl() == X && sizes(DR, N.V))
            Sizer = DR;
        });
      if (!Sizer || checked(N.V, X))
        continue;
      Done.insert(Line);
      const CallExpr *Copy = Copies[N.V];
      std::string Msg;
      llvm::raw_string_ostream OS(Msg);
      OS << "'" << N.V->getName() << "' is narrowed to '" << N.At->getType().getAsString()
         << "' here and the narrowed value sizes the destination (line "
         << SM.getExpansionLineNumber(Sizer->getBeginLoc()) << "), but '"
         << raptor::calleeName(Copy) << "' (line " << SM.getExpansionLineNumber(Copy->getBeginLoc())
         << ") copies the full '" << N.V->getName()
         << "': a length the narrow type cannot hold gets a buffer that is too small "
            "(CWE-197, CWE-787)";
      raptor::reportAt(BR, this, "Narrowed copy length", Msg, N.At, Mgr.getAnalysisDeclContext(D));
    }
  }
};
} // namespace

RAPTOR_CHECKER(NarrowedCopyLengthChecker, "NarrowedCopyLength",
               "A narrowed copy length sizes the destination while the copy uses the full length")
