// Helpers shared by the AST-based checkers.
#pragma once

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Basic/Version.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/StringRef.h"
#include <initializer_list>

namespace raptor {

inline constexpr const char *Category = "Security (raptor)";

// Report Msg at node S for checker C (used by AST-based checkers).
void reportAt(clang::ento::BugReporter &BR, const clang::ento::CheckerBase *C,
              llvm::StringRef Name, llvm::StringRef Msg, const clang::Stmt *S,
              clang::AnalysisDeclContext *ADC);
void reportAt(clang::ento::BugReporter &BR, const clang::ento::CheckerBase *C,
              llvm::StringRef Name, llvm::StringRef Msg, const clang::Decl *D);

// Name of the function called by CE, without namespace qualifiers ("" if none).
llvm::StringRef calleeName(const clang::CallExpr *CE);

bool isOneOf(llvm::StringRef S, std::initializer_list<llvm::StringRef> L);

// Strip parentheses and implicit/explicit casts.
const clang::Expr *strip(const clang::Expr *E);

// Memory space of R (clang 21 made it depend on the program state).
inline const clang::ento::MemSpaceRegion *
memorySpace(const clang::ento::MemRegion *R, clang::ento::CheckerContext &C) {
#if CLANG_VERSION_MAJOR >= 21
  return R->getMemorySpace(C.getState());
#else
  return R->getMemorySpace();
#endif
}

} // namespace raptor
