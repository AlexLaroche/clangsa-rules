// raptor.AssertOnlyBound: the only check on a length or offset is an
// assertion, and the value is then used as a size, an index or a pointer
// offset. Release builds define NDEBUG and the check disappears (CWE-617,
// CWE-787, CWE-125).
//
//   assert(blocksize <= sizeof(buf));          // gone with NDEBUG
//   memcpy(block, buf, blocksize);
//
// Assertion: an expansion of a macro named like assert (`assert`, `ASSERT`,
// `g_assert`, `XML_ASSERT`...), not a test-framework assertion that runs in
// every build (`assert_true`, `ck_assert_int_eq`) nor `static_assert`, whose
// arguments, as written in the source, hold a <, <=, > or >= comparison. The
// arguments are lexed, so assertions compiled out with NDEBUG are seen too.
// Value: an integer local or parameter named in those arguments (not a field
// or a function).
// Sink, after the assertion: the value, or an integer expression built from
// it, passed for a parameter of unsigned type (memcpy's size, a function
// pointer's size_t), used as an array index, or added to or subtracted from a
// pointer.
// Not reported: a value also compared, outside assertions, in the condition
// of an if, a loop or a ?: against something other than a constant <= 1
// (`if (n > max)`, `i < n`, a clamp `n > MAX ? MAX : n`); a comparison that
// only classifies the value (`bool grow = size > prev;`, `size > prev ?
// size - prev : prev - size`) does not count, nor does a sign test
// (`if (len > 0)`).
//
// CVE-2026-66033 (libssh2 ssh2_cipher_crypt), CVE-2026-102633 (libexpat
// expat_realloc).
#include "Common.h"
#include "Registry.h"
#include "clang/AST/ParentMap.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/Support/Regex.h"
#include <map>
#include <set>
#include <vector>

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

// An assertion that release builds compile out.
bool isReleaseAssert(StringRef Name) {
  static const llvm::Regex RE("^[[:alnum:]_]*assert[[:alnum:]_]*$", llvm::Regex::IgnoreCase);
  std::string L = Name.lower();
  StringRef S(L);
  return RE.match(Name) && !S.starts_with("assert_") && !S.starts_with("ck_") &&
         !S.contains("static") && !S.starts_with("expect");
}

struct Assertion {
  SourceLocation Begin, End;           // expansion range in the file
  std::vector<std::string> Names;      // identifiers in the arguments
};

bool isOneOfType(StringRef N);

// A token run that is a constant as written: literals, sizeof(...), casts to
// integer types and upper-case macro names (`SIZE_MAX - sizeof(size_t)`,
// `CURL_MAX_INPUT_LENGTH`, `0x7FFFFFFFUL`).
bool constantSide(const std::vector<Token> &T) {
  bool Any = false;
  for (size_t I = 0; I < T.size(); ++I) {
    const Token &K = T[I];
    if (K.is(tok::raw_identifier)) {
      StringRef N = K.getRawIdentifier();
      if (N == "sizeof" || N == "_Alignof" || N == "alignof") {
        // skip the parenthesised operand
        size_t J = I + 1;
        if (J < T.size() && T[J].is(tok::l_paren)) {
          for (int Depth = 0; J < T.size(); ++J) {
            Depth += T[J].is(tok::l_paren) - T[J].is(tok::r_paren);
            if (Depth == 0)
              break;
          }
          I = J;
        }
        Any = true;
        continue;
      }
      if (isOneOfType(N))
        continue;
      bool Upper = llvm::any_of(N, [](char C) { return C >= 'A' && C <= 'Z'; }) &&
                   llvm::all_of(N, [](char C) { return !(C >= 'a' && C <= 'z'); });
      if (!Upper)
        return false;
      Any = true;
      continue;
    }
    if (K.is(tok::numeric_constant)) {
      Any = true;
      continue;
    }
    if (K.isOneOf(tok::period, tok::arrow, tok::l_square))
      return false;
  }
  return Any;
}

// Names of integer types, as in a cast.
bool isOneOfType(StringRef N) {
  return raptor::isOneOf(N, {"int", "unsigned", "signed", "long", "short", "char", "const"}) ||
         N.ends_with("_t");
}

// Lex the arguments of the macro invocation Call into clauses joined by &&
// or ||; for every clause `X op C` with a relational op and a constant side
// C, collect the names in X. Returns false when there is none.
bool lexArgs(CharSourceRange Call, const SourceManager &SM, const LangOptions &LO,
             std::vector<std::string> &Names) {
  SourceLocation B = SM.getSpellingLoc(Call.getBegin()), E = SM.getSpellingLoc(Call.getEnd());
  if (SM.getFileID(B) != SM.getFileID(E))
    return false;
  StringRef Text = Lexer::getSourceText(CharSourceRange::getTokenRange(B, E), SM, LO);
  Lexer L(B, LO, Text.begin(), Text.begin(), Text.end());
  std::vector<Token> Toks;
  Token Tok;
  for (bool Done = false; !Done;) {
    Done = L.LexFromRawLexer(Tok);
    Toks.push_back(Tok);
  }
  // the arguments: inside the first parenthesis
  size_t First = 0;
  while (First < Toks.size() && !Toks[First].is(tok::l_paren))
    ++First;
  if (First == Toks.size())
    return false;
  std::vector<std::vector<Token>> Clauses(1);
  int Depth = 0;
  for (size_t I = First + 1; I < Toks.size(); ++I) {
    const Token &T = Toks[I];
    if (T.is(tok::l_paren))
      ++Depth;
    if (T.is(tok::r_paren) && --Depth < 0)
      break;
    if (T.isOneOf(tok::ampamp, tok::pipepipe, tok::comma)) {
      Clauses.emplace_back();
      continue;
    }
    Clauses.back().push_back(T);
  }
  for (auto &C : Clauses) {
    // `((a < N) && (b < M))` splits into `(a < N)` and `(b < M))`: drop the
    // unbalanced parentheses at the ends, then the ones around the clause.
    int Bal = 0;
    for (const Token &T : C)
      Bal += T.is(tok::l_paren) - T.is(tok::r_paren);
    while (Bal > 0 && !C.empty() && C.front().is(tok::l_paren)) {
      C.erase(C.begin());
      --Bal;
    }
    while (Bal < 0 && !C.empty() && C.back().is(tok::r_paren)) {
      C.pop_back();
      ++Bal;
    }
    while (C.size() > 2 && C.front().is(tok::l_paren) && C.back().is(tok::r_paren)) {
      int D = 0;
      size_t Close = 0;
      for (size_t I = 0; I < C.size(); ++I) {
        D += C[I].is(tok::l_paren) - C[I].is(tok::r_paren);
        if (D == 0) {
          Close = I;
          break;
        }
      }
      if (Close != C.size() - 1)
        break;
      C.pop_back();
      C.erase(C.begin());
    }
    size_t Op = C.size();
    int D = 0;
    for (size_t I = 0; I < C.size(); ++I) {
      D += C[I].is(tok::l_paren) - C[I].is(tok::r_paren);
      if (D == 0 && C[I].isOneOf(tok::less, tok::lessequal, tok::greater, tok::greaterequal)) {
        if (Op != C.size()) {
          Op = C.size();
          break; // two comparisons: not a plain bound
        }
        Op = I;
      }
    }
    if (Op == C.size())
      continue;
    std::vector<Token> Lhs(C.begin(), C.begin() + Op), Rhs(C.begin() + Op + 1, C.end());
    const std::vector<Token> *Var = constantSide(Rhs) ? &Lhs : constantSide(Lhs) ? &Rhs : nullptr;
    if (!Var)
      continue;
    const auto &V = *Var;
    for (size_t I = 0; I < V.size(); ++I) {
      const Token &T = V[I];
      if (!T.is(tok::raw_identifier))
        continue;
      if (I > 0 && V[I - 1].isOneOf(tok::period, tok::arrow))
        continue; // a field
      if (I + 1 < V.size() && V[I + 1].is(tok::l_paren))
        continue; // a call or a macro
      Names.push_back(T.getRawIdentifier().str());
    }
  }
  return !Names.empty();
}

class AssertOnlyBoundChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = BR.getSourceManager();
    const LangOptions &LO = Ctx.getLangOpts();

    // Assertion invocations, and the expansion ranges of every assertion
    // (to tell code inside them apart).
    std::vector<Assertion> Asserts;
    std::set<unsigned> Lexed;
    std::vector<std::pair<SourceLocation, SourceLocation>> InAssert;
    walk(Body, [&](const Stmt *S) {
      SourceLocation Loc = S->getBeginLoc();
      for (; Loc.isMacroID(); Loc = SM.getImmediateMacroCallerLoc(Loc)) {
        if (SM.isMacroArgExpansion(Loc))
          continue;
        StringRef Name = Lexer::getImmediateMacroName(Loc, SM, LO);
        if (!isReleaseAssert(Name))
          continue;
        CharSourceRange Call = SM.getImmediateExpansionRange(Loc);
        if (!Lexed.insert(Call.getBegin().getRawEncoding()).second)
          break;
        SourceLocation B = SM.getExpansionLoc(Call.getBegin()), E = SM.getExpansionLoc(Call.getEnd());
        InAssert.push_back({B, E});
        Assertion A{B, E, {}};
        if (lexArgs(Call, SM, LO, A.Names))
          Asserts.push_back(std::move(A));
        break;
      }
    });
    if (Asserts.empty())
      return;
    auto within = [&](SourceLocation L, SourceLocation B, SourceLocation E) {
      return !SM.isBeforeInTranslationUnit(L, B) && !SM.isBeforeInTranslationUnit(E, L);
    };
    auto inAssert = [&](SourceLocation L) {
      L = SM.getExpansionLoc(L);
      for (auto &R : InAssert)
        if (within(L, R.first, R.second))
          return true;
      return false;
    };

    // An assertion whose own code (not its argument) calls a function that
    // returns reports and goes on in every build (a test harness's
    // assertion_assert()); one that is compiled out or calls a noreturn
    // function (__assert_fail, abort) is the debug-only kind.
    walk(Body, [&](const Stmt *S) {
      const auto *CE = dyn_cast<CallExpr>(S);
      if (!CE || !CE->getBeginLoc().isMacroID() || SM.isMacroArgExpansion(CE->getBeginLoc()))
        return;
      const FunctionDecl *FD = CE->getDirectCallee();
      if (!FD || FD->getBuiltinID() || FD->isNoReturn())
        return;
      SourceLocation L = SM.getExpansionLoc(CE->getBeginLoc());
      llvm::erase_if(Asserts, [&](const Assertion &A) { return within(L, A.Begin, A.End); });
    });
    if (Asserts.empty())
      return;

    // Integer locals and parameters by name, in declaration order.
    std::map<std::string, std::vector<const VarDecl *>> Vars;
    auto addVar = [&](const VarDecl *V) {
      QualType T = V->getType();
      if (T->isIntegerType() && !T->isBooleanType() && !T->isCharType())
        Vars[V->getNameAsString()].push_back(V);
    };
    if (const auto *FD = dyn_cast<FunctionDecl>(D))
      for (const ParmVarDecl *P : FD->parameters())
        addVar(P);
    walk(Body, [&](const Stmt *S) {
      if (const auto *DS = dyn_cast<DeclStmt>(S))
        for (const Decl *X : DS->decls())
          if (const auto *V = dyn_cast<VarDecl>(X); V && V->hasLocalStorage())
            addVar(V);
    });

    auto refersTo = [](const Stmt *S, const VarDecl *V) {
      bool Found = false;
      walk(S, [&](const Stmt *X) {
        if (const auto *DRE = dyn_cast<DeclRefExpr>(X))
          Found |= DRE->getDecl() == V;
      });
      return Found;
    };
    auto smallConst = [&](const Expr *E) {
      Expr::EvalResult R;
      return E->EvaluateAsInt(R, Ctx) && R.Val.getInt().getSExtValue() <= 1;
    };

    // Values compared at run time, in a condition.
    std::set<const VarDecl *> Checked;
    auto condition = [&](const Expr *Cond, const ConditionalOperator *CO = nullptr) {
      if (!Cond || inAssert(Cond->getBeginLoc()))
        return;
      walk(Cond, [&](const Stmt *S) {
        const auto *BO = dyn_cast<BinaryOperator>(S);
        if (!BO || !BO->isRelationalOp())
          return;
        for (auto &[Name, Vs] : Vars)
          for (const VarDecl *V : Vs) {
            // a ?: bounds V only when one branch drops it (a clamp,
            // `n > MAX ? MAX : n`), not when both use it (`a > b ? a - b : b - a`)
            if (CO && refersTo(CO->getTrueExpr(), V) && refersTo(CO->getFalseExpr(), V))
              continue;
            if (refersTo(BO->getLHS(), V) && !smallConst(BO->getRHS()))
              Checked.insert(V);
            if (refersTo(BO->getRHS(), V) && !smallConst(BO->getLHS()))
              Checked.insert(V);
          }
      });
    };
    walk(Body, [&](const Stmt *S) {
      if (const auto *If = dyn_cast<IfStmt>(S))
        condition(If->getCond());
      else if (const auto *W = dyn_cast<WhileStmt>(S))
        condition(W->getCond());
      else if (const auto *F = dyn_cast<ForStmt>(S))
        condition(F->getCond());
      else if (const auto *Do = dyn_cast<DoStmt>(S))
        condition(Do->getCond());
      else if (const auto *CO = dyn_cast<ConditionalOperator>(S))
        condition(CO->getCond(), CO);
    });

    // Sinks: uses of V as a size, an index or an offset.
    ParentMap PM(const_cast<Stmt *>(Body));
    auto unsignedParam = [](QualType T) {
      return T->isIntegerType() && T->isUnsignedIntegerType() && !T->isBooleanType();
    };
    auto isSink = [&](const DeclRefExpr *DRE) -> bool {
      const Stmt *Child = DRE;
      for (const Stmt *P = PM.getParent(Child); P; Child = P, P = PM.getParent(P)) {
        if (const auto *CE = dyn_cast<CallExpr>(P)) {
          if (Child == CE->getCallee())
            return false;
          QualType CT = CE->getCallee()->getType();
          if (const auto *PT = CT->getAs<PointerType>())
            CT = PT->getPointeeType();
          const auto *FPT = CT->getAs<FunctionProtoType>();
          if (!FPT)
            return false;
          for (unsigned I = 0; I < CE->getNumArgs() && I < FPT->getNumParams(); ++I)
            if (CE->getArg(I) == Child)
              return unsignedParam(FPT->getParamType(I));
          return false;
        }
        if (const auto *AS = dyn_cast<ArraySubscriptExpr>(P))
          return Child == AS->getIdx();
        if (const auto *BO = dyn_cast<BinaryOperator>(P)) {
          if (BO->isAdditiveOp() || BO->getOpcode() == BO_AddAssign || BO->getOpcode() == BO_SubAssign) {
            if (BO->getType()->isPointerType() || BO->getLHS()->getType()->isPointerType())
              return true;
            continue;
          }
          if (BO->isMultiplicativeOp() || BO->isShiftOp() || BO->isBitwiseOp())
            continue;
          return false;
        }
        if (isa<ParenExpr, ImplicitCastExpr, CStyleCastExpr>(P)) {
          if (!cast<Expr>(P)->getType()->isIntegerType())
            return false;
          continue;
        }
        return false;
      }
      return false;
    };

    for (const Assertion &A : Asserts) {
      std::set<const VarDecl *> Seen;
      std::string Hit;
      unsigned HitLine = 0;
      for (const std::string &N : A.Names) {
        auto It = Vars.find(N);
        if (It == Vars.end())
          continue;
        // The declaration in scope: the last one before the assertion.
        const VarDecl *V = nullptr;
        for (const VarDecl *C : It->second)
          if (SM.isBeforeInTranslationUnit(C->getLocation(), A.Begin))
            V = C;
        if (!V || Checked.count(V) || !Seen.insert(V).second)
          continue;
        walk(Body, [&](const Stmt *S) {
          const auto *DRE = dyn_cast<DeclRefExpr>(S);
          if (!Hit.empty() || !DRE || DRE->getDecl() != V)
            return;
          SourceLocation L = SM.getExpansionLoc(DRE->getBeginLoc());
          if (!SM.isBeforeInTranslationUnit(A.End, L) || inAssert(L) || !isSink(DRE))
            return;
          Hit = N;
          HitLine = SM.getExpansionLineNumber(L);
        });
        if (!Hit.empty())
          break;
      }
      if (Hit.empty())
        continue;
      PathDiagnosticLocation L(A.Begin, SM);
      BR.EmitBasicReport(D, this, "Bound checked only in an assertion", raptor::Category,
                         "'" + Hit + "' is bounded only by this assertion, which release "
                         "builds (NDEBUG) remove, and is used as a size, an index or an "
                         "offset at line " + std::to_string(HitLine) +
                         " (CWE-617, CWE-787)",
                         L, SourceRange(A.Begin, A.End));
    }
  }
};
} // namespace

RAPTOR_CHECKER(AssertOnlyBoundChecker, "AssertOnlyBound",
               "Length or offset bounded only by an assertion, then used as a size")
