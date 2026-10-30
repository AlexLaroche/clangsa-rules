// How a call's return value is used, for the unchecked-ret-* / unsafe-ret-*
// rules (semgrep's `pattern-not-inside: $_ = $FUN(...)`, `<... $FUN(...) == $_ ...>`...).
#pragma once

#include "clang/AST/ParentMapContext.h"
#include "clang/AST/Stmt.h"

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

} // namespace raptor
