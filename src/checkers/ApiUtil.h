// Helpers for the AST-based ports of the "insecure API" semgrep rules
// (header-only so that each checker stays a single translation unit).
#pragma once

#include "Common.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"
#include <functional>
#include <regex>
#include <string>

namespace raptor {
namespace api {

using namespace clang;
using clang::ento::AnalysisManager;
using clang::ento::BugReporter;

// Name of the called function as semgrep sees it in the unpreprocessed
// source: when the callee comes from a macro (e.g. glibc's
// `#define alloca(size) __builtin_alloca(size)`), the name of the outermost
// macro; otherwise the name of the called function (or function pointer
// variable). Member calls (obj.f(), obj->f(), Class::f()) yield "", since
// semgrep's `f(...)` does not match them.
inline std::string calleeAsWritten(const CallExpr *CE, ASTContext &Ctx) {
  const Expr *Callee = CE->getCallee()->IgnoreParenImpCasts();
  const SourceManager &SM = Ctx.getSourceManager();
  SourceLocation L = Callee->getBeginLoc();
  if (L.isMacroID() && !SM.isMacroArgExpansion(L)) {
    StringRef Name;
    while (L.isMacroID()) {
      Name = Lexer::getImmediateMacroName(L, SM, Ctx.getLangOpts());
      L = SM.getImmediateMacroCallerLoc(L);
    }
    return Name.str();
  }
  if (const auto *DRE = dyn_cast<DeclRefExpr>(Callee)) {
    if (isa<CXXMethodDecl>(DRE->getDecl()))
      return "";
    if (const IdentifierInfo *II = DRE->getDecl()->getIdentifier())
      return II->getName().str();
  }
  return "";
}

// The text of E as written in the source file (macros unexpanded), which is
// what semgrep's metavariable-regex is applied to.
inline std::string textAsWritten(const Expr *E, ASTContext &Ctx) {
  const SourceManager &SM = Ctx.getSourceManager();
  CharSourceRange R = SM.getExpansionRange(E->getSourceRange());
  return Lexer::getSourceText(R, SM, Ctx.getLangOpts()).str();
}

// Left-anchored match, like semgrep's metavariable-regex.
inline bool regexMatchesAtStart(const std::string &Text, const std::regex &Re) {
  return std::regex_search(Text, Re, std::regex_constants::match_continuous);
}

// Regex used by the scanf and sprintf rules on the format argument: a string
// literal containing %s/%ls/%S, or anything starting with an identifier.
inline const std::regex &unsafeFormatRegex() {
  static const std::regex Re(
      R"re((".*%l?s.*"|".*%S.*"|[a-zA-Z_][a-zA-Z0-9_]*))re");
  return Re;
}

// Is the variable VD possibly modified in Body, ignoring the reference Self?
// Conservative: any use other than reading its value, sizeof, or passing it
// as a pointer to const counts as a modification.
inline bool isPossiblyModified(const VarDecl *VD, const Stmt *Body,
                               const Expr *Self, ASTContext &Ctx) {
  using namespace ast_matchers;
  auto Refs = match(findAll(declRefExpr(to(varDecl(equalsNode(VD)))).bind("r")),
                    *Body, Ctx);
  for (const BoundNodes &N : Refs) {
    const Expr *Cur = N.getNodeAs<DeclRefExpr>("r");
    if (Cur == Self)
      continue;
    bool Safe = false;
    while (true) {
      auto Parents = Ctx.getParents(*Cur);
      if (Parents.empty())
        break;
      const Expr *P = Parents[0].get<Expr>();
      if (!P)
        break; // e.g. used as a statement or in a declaration: be conservative
      if (isa<ParenExpr>(P)) {
        Cur = P;
        continue;
      }
      if (const auto *ICE = dyn_cast<ImplicitCastExpr>(P)) {
        if (ICE->getCastKind() == CK_LValueToRValue) {
          Safe = true;
          break;
        }
        if (ICE->getType()->isPointerType() &&
            ICE->getType()->getPointeeType().isConstQualified()) {
          Safe = true;
          break;
        }
        Cur = P;
        continue;
      }
      if (isa<UnaryExprOrTypeTraitExpr>(P)) {
        Safe = true;
        break;
      }
      if (const auto *CE = dyn_cast<CallExpr>(P)) {
        // passed as a (decayed) pointer: safe only for pointer-to-const or
        // variadic parameters
        const FunctionDecl *FD = CE->getDirectCallee();
        for (unsigned I = 0; FD && I < CE->getNumArgs(); ++I) {
          if (CE->getArg(I) != Cur)
            continue;
          if (I >= FD->getNumParams())
            Safe = FD->isVariadic();
          else {
            QualType T = FD->getParamDecl(I)->getType();
            Safe = T->isPointerType() && T->getPointeeType().isConstQualified();
          }
        }
        break;
      }
      break;
    }
    if (!Safe)
      return true;
  }
  return false;
}

// Does E match semgrep's "..." pattern, i.e. is it a string literal, or a
// variable initialized with a string literal and not modified afterwards
// (semgrep's constant propagation)?
inline bool isConstantString(const Expr *E, const Stmt *Body, ASTContext &Ctx) {
  E = E->IgnoreParenImpCasts();
  if (isa<StringLiteral>(E))
    return true;
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  if (!VD || !VD->getInit() ||
      !isa<StringLiteral>(VD->getInit()->IgnoreParenImpCasts()))
    return false;
  if (!VD->isLocalVarDecl())
    return VD->getType().isConstQualified();
  return !isPossiblyModified(VD, Body, DRE, Ctx);
}

inline void forEachCall(const Decl *D, AnalysisManager &Mgr,
                        const std::function<void(const CallExpr *)> &F) {
  using namespace ast_matchers;
  for (const BoundNodes &N :
       match(findAll(callExpr().bind("call")), *D->getBody(), Mgr.getASTContext()))
    F(N.getNodeAs<CallExpr>("call"));
}

// The common case: report every call to one of Names.
inline void reportCallsTo(const Decl *D, AnalysisManager &Mgr, BugReporter &BR,
                          const ento::CheckerBase *C, StringRef Title,
                          StringRef Msg, std::initializer_list<StringRef> Names) {
  forEachCall(D, Mgr, [&](const CallExpr *CE) {
    if (isOneOf(calleeAsWritten(CE, Mgr.getASTContext()), Names))
      reportAt(BR, C, Title, Msg, CE, Mgr.getAnalysisDeclContext(D));
  });
}

} // namespace api
} // namespace raptor
