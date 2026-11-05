// Helpers for the "mem" batch of CFG-based checkers (DoubleFree,
// UseAfterFree, UncheckedRetMalloc). They approximate semgrep's
// `A; ... B` statement sequences with a flow-sensitive, path-insensitive
// walk of the CFG.
#pragma once

#include "Common.h"
#include "clang/Analysis/CFG.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace raptor_mem {

// Syntactic key of a pointer expression, playing the role of semgrep's
// $PTR metavariable: `p`, `s->f`, `s.f`, `a[3]`, `*p` (parens/casts
// ignored). Returns "" for expressions we do not track.
inline std::string keyOf(const clang::Expr *E) {
  using namespace clang;
  E = raptor::strip(E);
  if (!E)
    return "";
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return DRE->getDecl()->getNameAsString();
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    std::string B = keyOf(ME->getBase());
    if (B.empty())
      return "";
    return B + (ME->isArrow() ? "->" : ".") +
           ME->getMemberDecl()->getNameAsString();
  }
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    std::string B = keyOf(ASE->getBase());
    const auto *IL = dyn_cast<IntegerLiteral>(raptor::strip(ASE->getIdx()));
    if (B.empty() || !IL)
      return "";
    return B + "[" + std::to_string(IL->getValue().getZExtValue()) + "]";
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(E))
    if (UO->getOpcode() == UO_Deref) {
      std::string B = keyOf(UO->getSubExpr());
      return B.empty() ? "" : "*" + B;
    }
  return "";
}

// Does S (deeply) contain an expression whose key is in Keys? Returns it.
inline const clang::Expr *findKey(const clang::Stmt *S,
                                  const std::set<std::string> &Keys) {
  if (!S || Keys.empty())
    return nullptr;
  // sizeof/alignof do not evaluate their operand (`sizeof(p->tbl[0])`)
  if (const auto *UE = llvm::dyn_cast<clang::UnaryExprOrTypeTraitExpr>(S))
    if (!UE->isArgumentType() &&
        !UE->getArgumentExpr()->getType()->isVariableArrayType())
      return nullptr;
  if (const auto *E = llvm::dyn_cast<clang::Expr>(S)) {
    std::string K = keyOf(E);
    if (!K.empty() && Keys.count(K))
      return E;
  }
  for (const clang::Stmt *C : S->children())
    if (const clang::Expr *R = findKey(C, Keys))
      return R;
  return nullptr;
}

inline bool isCallTo(const clang::Stmt *S, llvm::StringRef Name) {
  const auto *CE = llvm::dyn_cast<clang::CallExpr>(S);
  return CE && raptor::calleeName(CE) == Name;
}

// The pointer a call releases, or null:
//  - a C releaser: free, cfree, g_free, xfree, av_free, sqlite3_free,
//    CRYPTO_free (OPENSSL_free), first argument;
//  - a library destructor named *_free, *_FREE or *Free with exactly one
//    pointer argument (OCSP_REQUEST_free(req), isns_free(p));
//  - a release hook called through a pointer named *free or *dealloc
//    (libssh2 `session->free(p, &session->abstract)`, zlib
//    `strm->zfree(strm->opaque, p)`): its only pointer argument that is
//    neither an address (`&x`) nor reached through the hook's own object.
// Releasers that also clear the pointer (av_freep(&p), *_clear*) are not:
// the pointer is null afterwards.
// With Named false (UseAfterFree), a library destructor counts only when its
// body is in the translation unit and releases the argument: names alone
// also match destructors of what an object holds (libarchive
// `__archive_write_filters_free(a)`).
inline const clang::Expr *releasedArg(const clang::CallExpr *CE, int Depth = 2,
                                      bool Named = true) {
  using namespace clang;
  auto isAddr = [](const Expr *A) {
    const auto *UO = dyn_cast_or_null<UnaryOperator>(raptor::strip(A));
    return UO && UO->getOpcode() == UO_AddrOf;
  };
  auto onlyPointer =
      [&](llvm::function_ref<bool(const Expr *)> Skip) -> const Expr * {
    const Expr *P = nullptr;
    for (const Expr *A : CE->arguments()) {
      const Expr *X = A->IgnoreParenImpCasts();
      if (!X->getType()->isPointerType() || isAddr(A) || Skip(A))
        continue;
      if (P)
        return nullptr;
      P = A;
    }
    return P;
  };
  llvm::StringRef N = raptor::calleeName(CE);
  if (!N.empty()) {
    if (raptor::isOneOf(N, {"free", "cfree", "g_free", "xfree", "av_free",
                            "sqlite3_free", "CRYPTO_free", "OPENSSL_free"}))
      return CE->getNumArgs() >= 1 && !isAddr(CE->getArg(0)) ? CE->getArg(0)
                                                             : nullptr;
    if (N.ends_with("freep") || N.contains_insensitive("clear"))
      return nullptr;
    if ((N.ends_with("_free") || N.ends_with("_FREE") ||
         (N.size() > 4 && N.ends_with("Free"))) &&
        !isa<CXXMemberCallExpr>(CE)) {
      // `Curl_req_free(&data->req, data)` releases data->req, not data.
      for (const Expr *A : CE->arguments())
        if (isAddr(A))
          return nullptr;
      const Expr *P = onlyPointer([](const Expr *) { return false; });
      // Defined here: a release only if the body releases that parameter
      // (curl's Curl_bufref_free(br) frees br->ptr, not br).
      const FunctionDecl *Def = nullptr;
      if (!P || !CE->getDirectCallee()->hasBody(Def))
        return Named ? P : nullptr;
      if (Depth <= 0)
        return nullptr;
      unsigned I = 0;
      while (I < CE->getNumArgs() && CE->getArg(I) != P)
        ++I;
      if (I >= Def->getNumParams())
        return P;
      const ParmVarDecl *PV = Def->getParamDecl(I);
      std::function<bool(const Stmt *)> releases = [&](const Stmt *S) -> bool {
        if (!S)
          return false;
        if (const auto *C = dyn_cast<CallExpr>(S))
          if (const Expr *R = releasedArg(C, Depth - 1))
            if (const auto *D = dyn_cast<DeclRefExpr>(R->IgnoreParenImpCasts());
                D && D->getDecl() == PV)
              return true;
        for (const Stmt *C : S->children())
          if (releases(C))
            return true;
        return false;
      };
      return releases(Def->getBody()) ? P : nullptr;
    }
    return nullptr;
  }
  if (CE->getDirectCallee())
    return nullptr;
  const Expr *Callee = CE->getCallee()->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(Callee);
      UO && UO->getOpcode() == UO_Deref)
    Callee = UO->getSubExpr()->IgnoreParenImpCasts();
  std::string Name, Base;
  if (const auto *ME = dyn_cast<MemberExpr>(Callee)) {
    Name = ME->getMemberDecl()->getNameAsString();
    Base = keyOf(ME->getBase());
  } else if (const auto *DRE = dyn_cast<DeclRefExpr>(Callee))
    Name = DRE->getDecl()->getNameAsString();
  llvm::StringRef L(Name);
  if (!(L.ends_with_insensitive("free") ||
        L.ends_with_insensitive("dealloc")) ||
      L.ends_with_insensitive("freep"))
    return nullptr;
  return onlyPointer([&](const Expr *A) {
    if (Base.empty())
      return false;
    llvm::StringRef K = keyOf(A);
    return K == Base || K.starts_with(Base + "->") || K.starts_with(Base + ".");
  });
}

// `$PTR = ...` (plain assignment or declaration with or without an
// initializer): the key being (re)defined by S, or "".
inline std::string definedKey(const clang::Stmt *S) {
  using namespace clang;
  if (const auto *BO = dyn_cast<BinaryOperator>(S))
    if (BO->getOpcode() == BO_Assign)
      return keyOf(BO->getLHS());
  if (const auto *DS = dyn_cast<DeclStmt>(S))
    if (DS->isSingleDecl())
      if (const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl()))
        return VD->getNameAsString();
  return "";
}

using KeySet = std::set<std::string>;

// The key S moves to another object: `$PTR = ...`, a declaration, or
// `$PTR++`, `--$PTR`, `$PTR += n`.
inline std::string movedKey(const clang::Stmt *S) {
  using namespace clang;
  std::string K = definedKey(S);
  if (!K.empty())
    return K;
  if (const auto *UO = dyn_cast<UnaryOperator>(S))
    if (UO->isIncrementDecrementOp())
      return keyOf(UO->getSubExpr());
  if (const auto *CA = dyn_cast<CompoundAssignOperator>(S))
    if (CA->getOpcode() == BO_AddAssign || CA->getOpcode() == BO_SubAssign)
      return keyOf(CA->getLHS());
  return "";
}

// Forget K and everything reached through it (`K->f`, `K.f`, `K[0]`, `*K`):
// once K points elsewhere (`s = s->next` in a list walk), those are other
// objects.
inline void eraseFrom(KeySet &Set, const std::string &K) {
  for (auto It = Set.begin(); It != Set.end();) {
    llvm::StringRef X(*It);
    // Markers: "?K" (maybe freed), "@K#..." (release site of K).
    if (X.consume_front("@"))
      X = X.take_until([](char C) { return C == '#'; });
    else
      X.consume_front("?");
    bool Derived = X == K;
    for (const char *Sep : {"->", ".", "["})
      Derived |= X.starts_with(K + Sep);
    for (llvm::StringRef Y = X; Y.consume_front("*");)
      Derived |= Y == K || Y.starts_with(K + "->") || Y.starts_with(K + ".") ||
                 Y.starts_with(K + "[");
    It = Derived ? Set.erase(It) : std::next(It);
  }
}

// A call that does not come back: a noreturn function, or one defined in
// the translation unit whose body ends by calling one (`static void
// usage(int c) { ...; exit(c); }`, a `Fatal()` that ends with exit()).
inline bool neverReturns(const clang::CallExpr *CE) {
  using namespace clang;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return false;
  if (FD->isNoReturn())
    return true;
  const FunctionDecl *Def = nullptr;
  if (!FD->hasBody(Def))
    return false;
  const auto *Body = dyn_cast_or_null<CompoundStmt>(Def->getBody());
  if (!Body || Body->body_empty())
    return false;
  const auto *Last = dyn_cast<CallExpr>(Body->body_back());
  if (!Last)
    if (const auto *E = dyn_cast<Expr>(Body->body_back()))
      Last = dyn_cast<CallExpr>(E->IgnoreParenCasts());
  const FunctionDecl *LF = Last ? Last->getDirectCallee() : nullptr;
  return LF && LF->isNoReturn();
}

inline std::string releaseSite(const std::string &K,
                               const clang::CallExpr *CE) {
  return "@" + K + "#" + std::to_string(reinterpret_cast<uintptr_t>(CE));
}

// Does FD (defined in the translation unit) set `*P` (its parameter Idx)
// before every return? Statement by statement at the top of its body: a
// direct `*P = ...` / `P[0] = ...`, or P forwarded to a callee that must set
// it, sets it; a statement that can return first does not (a null test of P
// itself is not counted: the caller passed `&p`). Unknown bodies are
// assumed to set it.
inline bool mustSet(const clang::FunctionDecl *FD, unsigned Idx, int Depth) {
  using namespace clang;
  const FunctionDecl *Def = nullptr;
  if (Depth <= 0 || !FD || !FD->hasBody(Def) || Idx >= Def->getNumParams())
    return true;
  const auto *Body = dyn_cast_or_null<CompoundStmt>(Def->getBody());
  if (!Body)
    return true;
  const ParmVarDecl *P = Def->getParamDecl(Idx);
  auto isP = [&](const Expr *E) {
    const auto *D = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
    return D && D->getDecl() == P;
  };
  std::function<bool(const Stmt *)> sets = [&](const Stmt *S) -> bool {
    if (!S)
      return false;
    if (const auto *BO = dyn_cast<BinaryOperator>(S);
        BO && BO->getOpcode() == BO_Assign) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      if (const auto *U = dyn_cast<UnaryOperator>(L);
          U && U->getOpcode() == UO_Deref && isP(U->getSubExpr()))
        return true;
      if (const auto *A = dyn_cast<ArraySubscriptExpr>(L);
          A && isP(A->getBase()))
        return true;
    }
    if (const auto *CE = dyn_cast<CallExpr>(S))
      for (unsigned I = 0; I < CE->getNumArgs(); ++I)
        if (isP(CE->getArg(I)) && mustSet(CE->getDirectCallee(), I, Depth - 1))
          return true;
    for (const Stmt *C : S->children())
      if (sets(C))
        return true;
    return false;
  };
  std::function<bool(const Stmt *)> returns = [&](const Stmt *S) -> bool {
    if (!S)
      return false;
    if (isa<ReturnStmt>(S))
      return true;
    for (const Stmt *C : S->children())
      if (returns(C))
        return true;
    return false;
  };
  // `if (!p)`, `if (p == NULL || ...)`: tests the pointer, not *p.
  std::function<bool(const Stmt *, bool &)> tests = [&](const Stmt *S,
                                                        bool &Deref) -> bool {
    if (!S)
      return false;
    if (const auto *U = dyn_cast<UnaryOperator>(S);
        U && U->getOpcode() == UO_Deref && isP(U->getSubExpr()))
      Deref = true;
    if (const auto *A = dyn_cast<ArraySubscriptExpr>(S); A && isP(A->getBase()))
      Deref = true;
    if (isa<CallExpr>(S))
      return false;
    bool T = false;
    if (const auto *E = dyn_cast<Expr>(S); E && isP(E))
      T = true;
    for (const Stmt *C : S->children())
      T |= tests(C, Deref);
    return T;
  };
  for (const Stmt *S : Body->body()) {
    if (const auto *If = dyn_cast<IfStmt>(S)) {
      if (sets(If->getCond()))
        return true;
      bool Deref = false;
      if (tests(If->getCond(), Deref) && !Deref)
        continue;
      if (returns(If))
        return false;
      continue;
    }
    if (isa<Expr>(S) || isa<DeclStmt>(S) || isa<ReturnStmt>(S)) {
      if (sets(S))
        return true;
      if (isa<ReturnStmt>(S))
        return false;
      continue;
    }
    if (returns(S))
      return false;
  }
  return false;
}

// free($PTR) (any releasedArg()) marks $PTR as freed; `$PTR = ...` (or a new
// declaration of $PTR, or moving $PTR) clears it and what is reached through
// it, as does handing it to a call that can set it again (`f(&p)`, `f(pp)` with
// pp a pointer to pointer, for *pp). A call that never returns ends the path.
inline void trackFreesWith(const clang::Stmt *S, KeySet &Freed, bool Named) {
  using namespace clang;
  std::string K = movedKey(S);
  if (!K.empty()) {
    eraseFrom(Freed, K);
    Freed.erase("?" + K);
  }
  // A read through a maybe-freed pointer: the code took the fill as done.
  const Expr *Base = nullptr;
  if (const auto *ME = dyn_cast<MemberExpr>(S); ME && ME->isArrow())
    Base = ME->getBase();
  else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(S))
    Base = ASE->getBase();
  else if (const auto *UO = dyn_cast<UnaryOperator>(S);
           UO && UO->getOpcode() == UO_Deref)
    Base = UO->getSubExpr();
  else if (const auto *BO = dyn_cast<BinaryOperator>(S);
           BO && BO->isAdditiveOp())
    Base =
        BO->getLHS()->getType()->isPointerType() ? BO->getLHS() : BO->getRHS();
  if (Base)
    if (std::string BK = keyOf(Base); !BK.empty())
      Freed.erase("?" + BK);
  // A read of another out-parameter of the fill (`if (len > 0)` after
  // `fill(&data, &len)`): the fill succeeded. Markers are "&len>data".
  if (const auto *IC = dyn_cast<ImplicitCastExpr>(S);
      IC && IC->getCastKind() == CK_LValueToRValue)
    if (std::string XK = keyOf(IC->getSubExpr()); !XK.empty())
      for (auto It = Freed.lower_bound("&" + XK + ">");
           It != Freed.end() &&
           llvm::StringRef(*It).starts_with("&" + XK + ">");) {
        Freed.erase("?" + It->substr(XK.size() + 2));
        It = Freed.erase(It);
      }
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (neverReturns(CE)) {
      Freed.clear();
      return;
    }
    if (!releasedArg(CE, 2, Named))
      for (unsigned I = 0; I < CE->getNumArgs(); ++I) {
        const Expr *A = CE->getArg(I);
        const Expr *X = raptor::strip(A);
        if (const auto *UO = dyn_cast_or_null<UnaryOperator>(X);
            UO && UO->getOpcode() == UO_AddrOf) {
          std::string AK = keyOf(UO->getSubExpr());
          if (AK.empty())
            continue;
          // f(&p) with f defined here and able to return without setting
          // *p: p may still be the freed pointer ("?p", DoubleFree only).
          bool Was = Freed.count(AK) || Freed.count("?" + AK);
          eraseFrom(Freed, AK);
          Freed.erase("?" + AK);
          if (Was && !mustSet(CE->getDirectCallee(), I, 3)) {
            Freed.insert("?" + AK);
            for (const Expr *B : CE->arguments())
              if (const auto *BU =
                      dyn_cast_or_null<UnaryOperator>(raptor::strip(B));
                  BU && BU->getOpcode() == UO_AddrOf && BU != UO)
                if (std::string BK = keyOf(BU->getSubExpr());
                    !BK.empty() && BK != AK)
                  Freed.insert("&" + BK + ">" + AK);
          }
          continue;
        }
        // Handed to a call: the code took the fill as done.
        for (auto It = Freed.begin(); It != Freed.end();) {
          if (It->front() == '?' && findKey(A, {It->substr(1)})) {
            It = Freed.erase(It);
            continue;
          }
          ++It;
        }
        if (X && X->getType()->isPointerType() &&
            X->getType()->getPointeeType()->isPointerType()) {
          std::string AK = keyOf(X);
          if (!AK.empty())
            eraseFrom(Freed, "*" + AK);
        }
      }
  }
  if (const auto *CE = dyn_cast<CallExpr>(S))
    if (const Expr *P = releasedArg(CE, 2, Named)) {
      std::string K = keyOf(P);
      if (!K.empty()) {
        Freed.insert(K);
        Freed.insert(releaseSite(K, CE));
      }
    }
}

inline void trackFrees(const clang::Stmt *S, KeySet &Freed) {
  trackFreesWith(S, Freed, true);
}
inline void trackStrictFrees(const clang::Stmt *S, KeySet &Freed) {
  trackFreesWith(S, Freed, false);
}

// Is CE, a release of K, only repeating itself: a release that returns a
// status (non-blocking, retried until done: libssh2
// `while (libssh2_channel_free(ch) == LIBSSH2_ERROR_EAGAIN)`) and the only
// release of K that reaches it?
inline bool onlyRetry(const KeySet &Freed, const std::string &K,
                      const clang::CallExpr *CE) {
  if (CE->getType()->isVoidType())
    return false;
  std::string Own = releaseSite(K, CE), Pre = "@" + K + "#";
  bool Any = false;
  for (auto It = Freed.lower_bound(Pre);
       It != Freed.end() && llvm::StringRef(*It).starts_with(Pre); ++It) {
    if (*It != Own)
      return false;
    Any = true;
  }
  return Any;
}

using Transfer = std::function<void(const clang::Stmt *, KeySet &)>;

// Forward "may" dataflow over the CFG (union at joins). Returns the set of
// keys holding at the entry of each block; the caller replays the blocks
// with these sets to emit reports.
inline llvm::DenseMap<const clang::CFGBlock *, KeySet>
solveForward(const clang::CFG &G, const Transfer &T) {
  llvm::DenseMap<const clang::CFGBlock *, KeySet> In, Out;
  llvm::SmallVector<const clang::CFGBlock *, 32> Work;
  for (const clang::CFGBlock *B : G)
    Work.push_back(B);
  while (!Work.empty()) {
    const clang::CFGBlock *B = Work.pop_back_val();
    KeySet S;
    for (const clang::CFGBlock *P : B->preds())
      if (P)
        S.insert(Out[P].begin(), Out[P].end());
    In[B] = S;
    for (const clang::CFGElement &E : *B)
      if (auto CS = E.getAs<clang::CFGStmt>())
        T(CS->getStmt(), S);
    if (S != Out[B]) {
      Out[B] = S;
      for (const clang::CFGBlock *Succ : B->succs())
        if (Succ)
          Work.push_back(Succ);
    }
  }
  return In;
}

// Is Size the size of the buffer field Ptr? Either a generic name (size,
// len, length, nbytes, used, sz) or the buffer's own name, without a
// _buffer/_buf/_data/_ptr suffix, followed by a size suffix (buf -> buf_len,
// finish_md -> finish_md_len, uncompressed_buffer -> uncompressed_size).
inline bool isSizeOf(llvm::StringRef Size, llvm::StringRef Ptr) {
  std::string S = Size.lower(), P = Ptr.lower();
  llvm::StringRef SR(S);
  // Not count or n: they count things (elements, references), not bytes.
  if (raptor::isOneOf(SR, {"size", "len", "length", "nbytes", "used", "sz", "slen"}))
    return true;
  std::vector<std::string> Stems{P};
  for (llvm::StringRef Suf :
       {"_buffer", "_buf", "_data", "_ptr", "buffer", "buf", "data", "ptr"})
    if (llvm::StringRef(P).ends_with(Suf) && P.size() > Suf.size()) {
      Stems.push_back(P.substr(0, P.size() - Suf.size()));
      break;
    }
  for (const std::string &Stem : Stems) {
    if (!SR.starts_with(Stem))
      continue;
    llvm::StringRef Rest = SR.drop_front(Stem.size());
    if (raptor::isOneOf(Rest, {"_len", "len", "_size", "size", "_length",
                               "length", "_count", "count", "_used", "used",
                               "_sz", "sz", "_bytes", "bytes"}))
      return true;
  }
  return false;
}

// isSizeOf on two fields of one struct, except a generic `size` next to an
// element count (nelts, nitems, nmemb, nalloc), which is the size of one
// element (nginx ngx_array_t).
inline bool isSizeField(const clang::FieldDecl *Size,
                        const clang::FieldDecl *Ptr) {
  if (!Size->getIdentifier() || !Ptr->getIdentifier() ||
      !isSizeOf(Size->getName(), Ptr->getName()))
    return false;
  if (Size->getName().lower() != "size")
    return true;
  for (const clang::FieldDecl *F : Size->getParent()->fields())
    if (F->getIdentifier() &&
        raptor::isOneOf(llvm::StringRef(F->getName().lower()),
                        {"nelts", "nitems", "nmemb", "nalloc"}))
      return false;
  return true;
}

} // namespace raptor_mem
