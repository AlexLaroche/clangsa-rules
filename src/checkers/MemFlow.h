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
    if (!UE->isArgumentType() && !UE->getArgumentExpr()->getType()->isVariableArrayType())
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

// free($PTR) marks $PTR as freed; `$PTR = ...` (or a new declaration of
// $PTR, or moving $PTR) clears it and what is reached through it, as does
// handing it to a call that can set it again (`f(&p)`, `f(pp)` with pp a
// pointer to pointer, for *pp). A call that never returns ends the path.
inline void trackFrees(const clang::Stmt *S, KeySet &Freed) {
  using namespace clang;
  std::string K = movedKey(S);
  if (!K.empty())
    eraseFrom(Freed, K);
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (neverReturns(CE)) {
      Freed.clear();
      return;
    }
    if (raptor::calleeName(CE) != "free")
      for (const Expr *A : CE->arguments()) {
        const Expr *X = raptor::strip(A);
        if (const auto *UO = dyn_cast_or_null<UnaryOperator>(X);
            UO && UO->getOpcode() == UO_AddrOf) {
          std::string AK = keyOf(UO->getSubExpr());
          if (!AK.empty())
            eraseFrom(Freed, AK);
        } else if (X && X->getType()->isPointerType() &&
                   X->getType()->getPointeeType()->isPointerType()) {
          std::string AK = keyOf(X);
          if (!AK.empty())
            eraseFrom(Freed, "*" + AK);
        }
      }
  }
  if (isCallTo(S, "free")) {
    const auto *CE = llvm::cast<clang::CallExpr>(S);
    if (CE->getNumArgs() == 1) {
      std::string K = keyOf(CE->getArg(0));
      if (!K.empty())
        Freed.insert(K);
    }
  }
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
  if (raptor::isOneOf(SR, {"size", "len", "length", "nbytes", "used", "sz"}))
    return true;
  std::vector<std::string> Stems{P};
  for (llvm::StringRef Suf : {"_buffer", "_buf", "_data", "_ptr", "buffer", "buf", "data", "ptr"})
    if (llvm::StringRef(P).ends_with(Suf) && P.size() > Suf.size()) {
      Stems.push_back(P.substr(0, P.size() - Suf.size()));
      break;
    }
  for (const std::string &Stem : Stems) {
    if (!SR.starts_with(Stem))
      continue;
    llvm::StringRef Rest = SR.drop_front(Stem.size());
    if (raptor::isOneOf(Rest, {"_len", "len", "_size", "size", "_length", "length", "_count",
                               "count", "_used", "used", "_sz", "sz", "_bytes", "bytes"}))
      return true;
  }
  return false;
}

// isSizeOf on two fields of one struct, except a generic `size` next to an
// element count (nelts, nitems, nmemb, nalloc), which is the size of one
// element (nginx ngx_array_t).
inline bool isSizeField(const clang::FieldDecl *Size, const clang::FieldDecl *Ptr) {
  if (!Size->getIdentifier() || !Ptr->getIdentifier() ||
      !isSizeOf(Size->getName(), Ptr->getName()))
    return false;
  if (Size->getName().lower() != "size")
    return true;
  for (const clang::FieldDecl *F : Size->getParent()->fields())
    if (F->getIdentifier() &&
        raptor::isOneOf(llvm::StringRef(F->getName().lower()), {"nelts", "nitems", "nmemb", "nalloc"}))
      return false;
  return true;
}

} // namespace raptor_mem
