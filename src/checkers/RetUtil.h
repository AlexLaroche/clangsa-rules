// How a call's return value is used, for the unchecked-ret-* / unsafe-ret-*
// rules (semgrep's `pattern-not-inside: $_ = $FUN(...)`, `<... $FUN(...) == $_ ...>`...).
#pragma once

#include "clang/AST/ParentMapContext.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"
#include <cctype>
#include <functional>
#include <string>

namespace raptor {

struct RetUse {
  const clang::Stmt *User = nullptr; // first non-transparent parent
  const clang::Expr *Operand = nullptr; // the call, as seen by User
  bool Negated = false;                 // went through a `!`
};

// Walk up from the call through parentheses and casts (and `!` when
// ThroughNot is set) to the expression or statement that consumes the value.
inline RetUse retUse(const clang::Expr *Call, clang::ASTContext &Ctx,
                     bool ThroughNot) {
  RetUse U;
  const clang::Expr *Cur = Call;
  while (true) {
    auto Parents = Ctx.getParents(*Cur);
    if (Parents.empty())
      break;
    const clang::Stmt *P = Parents[0].get<clang::Stmt>();
    if (!P) { // e.g. a VarDecl initializer
      U.User = nullptr;
      U.Operand = Cur;
      if (Parents[0].get<clang::VarDecl>())
        U.User = Cur; // marker: used as an initializer
      return U;
    }
    if (llvm::isa<clang::ParenExpr, clang::ImplicitCastExpr,
                  clang::CStyleCastExpr>(P)) {
      Cur = llvm::cast<clang::Expr>(P);
      continue;
    }
    if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(P))
      if (ThroughNot && UO->getOpcode() == clang::UO_LNot) {
        U.Negated = true;
        Cur = UO;
        continue;
      }
    U.User = P;
    U.Operand = Cur;
    return U;
  }
  return U;
}

inline bool isInitializer(const RetUse &U) { return U.User && U.User == U.Operand; }

// The local receiving the result of Call: `T v = call;` (the call is
// Where) or `v = call` / `v += call` (Where is the assignment).
inline const clang::VarDecl *resultLocal(const clang::Stmt *Where,
                                         const clang::Expr *Call,
                                         clang::ASTContext &Ctx) {
  if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(Where)) {
    const auto *R = llvm::dyn_cast<clang::DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts());
    return R ? llvm::dyn_cast<clang::VarDecl>(R->getDecl()) : nullptr;
  }
  const clang::Stmt *Cur = Call;
  while (true) {
    auto Parents = Ctx.getParents(*Cur);
    if (Parents.empty())
      return nullptr;
    if (const auto *V = Parents[0].get<clang::VarDecl>())
      return V->hasLocalStorage() ? V : nullptr;
    const auto *E = Parents[0].get<clang::Expr>();
    if (!E || !(llvm::isa<clang::ParenExpr>(E) || llvm::isa<clang::CastExpr>(E)))
      return nullptr;
    Cur = E;
  }
}

// E as written, through parentheses and casts, without whitespace.
inline std::string squeezedText(const clang::Expr *E, clang::ASTContext &Ctx) {
  const clang::SourceManager &SM = Ctx.getSourceManager();
  // A token from a macro argument maps to where the argument is written,
  // one from a macro body to that macro call (`ASSERT(n < sizeof(buf))`).
  auto Written = [&](clang::SourceLocation L, bool End) {
    while (L.isMacroID()) {
      if (SM.isMacroArgExpansion(L))
        L = SM.getImmediateSpellingLoc(L);
      else {
        clang::CharSourceRange CR = SM.getImmediateExpansionRange(L);
        L = End ? CR.getEnd() : CR.getBegin();
      }
    }
    return L;
  };
  const clang::Expr *X = E->IgnoreParenCasts();
  clang::CharSourceRange R = clang::CharSourceRange::getTokenRange(
      Written(X->getBeginLoc(), false), Written(X->getEndLoc(), true));
  std::string T;
  for (char Ch : clang::Lexer::getSourceText(R, SM, Ctx.getLangOpts()))
    if (!std::isspace(static_cast<unsigned char>(Ch)))
      T += Ch;
  return T;
}

// V is compared (<, <=, >, >=) somewhere in Body with the same expression as
// Size, the size given to the call that produced it: the caller detects
// truncation (`if (n >= size)`, `n < cap ? n : cap - 1`).
inline bool comparedWithSize(const clang::VarDecl *V, const clang::Expr *Size,
                             const clang::Stmt *Body, clang::ASTContext &Ctx) {
  std::string Want = squeezedText(Size, Ctx);
  if (Want.empty())
    return false;
  bool Found = false;
  std::function<void(const clang::Stmt *)> Walk = [&](const clang::Stmt *S) {
    if (!S || Found)
      return;
    if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(S);
        BO && BO->isRelationalOp()) {
      for (auto [A, B] : {std::pair{BO->getLHS(), BO->getRHS()},
                          std::pair{BO->getRHS(), BO->getLHS()}}) {
        const auto *R = llvm::dyn_cast<clang::DeclRefExpr>(A->IgnoreParenCasts());
        if (R && R->getDecl() == V && squeezedText(B, Ctx) == Want)
          Found = true;
      }
    }
    for (const clang::Stmt *C : S->children())
      Walk(C);
  };
  Walk(Body);
  return Found;
}

} // namespace raptor
