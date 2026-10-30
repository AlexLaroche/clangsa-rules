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

// free($PTR) marks $PTR as freed; `$PTR = ...` (or a new declaration of
// $PTR) clears it.
inline void trackFrees(const clang::Stmt *S, KeySet &Freed) {
  std::string K = definedKey(S);
  if (!K.empty())
    Freed.erase(K);
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

} // namespace raptor_mem
