// raptor.Typos: operator mistakes that change the meaning of the code.
//   for (a == b; ...)            a == b;
//   if (... a = b ...)           unless (a = b) is compared or in its own
//                                parentheses (`if ((a = b))`, `!(a = b)`)
//   if (... a & b ...)           unless (a & b) is compared  (same for |),
//                                or b is a constant mask (`flags & FLAG`)
//                                or a shifted bit (`mask & (1u << i)`),
//                                or (a & b) is compared on either side,
//                                or it builds a call argument (`f(A | B)`),
//                                or a macro's own `if` and operator test it
//                                (`msg(M_WARN | M_ERRNO)` -> `(flags) & M_FATAL`)
//   a =+ b                       (E op E) for &&, ||, ==, !=, <, <=, >, >=,
//                                unless the operands are spelled differently
//                                (`IS_ENABLED(A) || IS_ENABLED(B)`)
//   (char *)p = / == / != '\0'   if (... strcpy()/strncpy() ...)
//   if (x);   for (a; b; c);     char buf[040];  (octal array size)
// Operators coming from macro bodies are skipped: semgrep sees the macro
// call, not its body (e.g. `if (SSL_in_init(s))` expands to a bitwise &).
#include "Common.h"
#include "Registry.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
// The operator comes from a macro body (an operator written in a macro
// argument is in the source, where semgrep sees it).
bool fromMacro(const BinaryOperator *BO, const ASTContext &Ctx) {
  const SourceManager &SM = Ctx.getSourceManager();
  for (SourceLocation L = BO->getOperatorLoc(); L.isMacroID();
       L = SM.getImmediateSpellingLoc(L))
    if (!SM.isMacroArgExpansion(L))
      return true;
  return false;
}

// Where L is written: a token from a macro argument maps to where the
// argument is written, a token from a macro body to the start (or end) of
// that macro call, until a file location is reached.
SourceLocation written(SourceLocation L, const SourceManager &SM, bool End) {
  while (L.isMacroID()) {
    if (SM.isMacroArgExpansion(L))
      L = SM.getImmediateSpellingLoc(L);
    else {
      CharSourceRange R = SM.getImmediateExpansionRange(L);
      L = End ? R.getEnd() : R.getBegin();
    }
  }
  return L;
}

// The source text of E, as written (macro calls unexpanded).
StringRef spelled(const Expr *E, const ASTContext &Ctx) {
  const SourceManager &SM = Ctx.getSourceManager();
  CharSourceRange R = CharSourceRange::getTokenRange(
      written(E->getBeginLoc(), SM, false), written(E->getEndLoc(), SM, true));
  return Lexer::getSourceText(R, SM, Ctx.getLangOpts());
}

// Identical operands. Operands written differently that expand to the same
// value (`IS_ENABLED(A) || IS_ENABLED(B)`, `SIZE_A == SIZE_B`) are
// configuration checks, not typos.
bool sameExpr(const Expr *A, const Expr *B, const ASTContext &Ctx) {
  if ((A->getBeginLoc().isMacroID() || B->getBeginLoc().isMacroID()) &&
      spelled(A, Ctx) != spelled(B, Ctx))
    return false;
  llvm::FoldingSetNodeID IA, IB;
  A->IgnoreParenImpCasts()->Profile(IA, Ctx, /*Canonical=*/true);
  B->IgnoreParenImpCasts()->Profile(IB, Ctx, /*Canonical=*/true);
  return IA == IB;
}

// E (through parentheses) is the left operand of a comparison
bool isComparedLHS(const Expr *E, ASTContext &Ctx) {
  const Expr *Cur = E;
  while (true) {
    auto Parents = Ctx.getParents(*Cur);
    if (Parents.empty())
      return false;
    if (const auto *PE = Parents[0].get<ParenExpr>()) {
      Cur = PE;
      continue;
    }
    if (const auto *IC = Parents[0].get<ImplicitCastExpr>()) {
      Cur = IC;
      continue;
    }
    const auto *BO = Parents[0].get<BinaryOperator>();
    // a & b & c compared: semgrep matches & and | associatively
    BinaryOperatorKind K = cast<BinaryOperator>(E)->getOpcode();
    if (BO && (K == BO_And || K == BO_Or) && BO->getOpcode() == K) {
      Cur = BO;
      continue;
    }
    // a masked value may sit on either side ((a & m) != (b & m));
    // an assignment only on the left, as semgrep's ($E1 = $E2) CMP $_
    return BO && BO->isComparisonOp() &&
           (BO->getLHS() == Cur || K == BO_And || K == BO_Or);
  }
}

// `flags & MASK`: a flag test, the only meaning `&` can have against a
// constant (`flags && MASK` would be meaningless).
// A single bit built by a shift of a constant (`1u << i`, a BIT(i) macro).
bool isShiftedBit(const Expr *E, const ASTContext &Ctx) {
  const auto *Sh = dyn_cast<BinaryOperator>(E->IgnoreParenCasts());
  return Sh && Sh->getOpcode() == BO_Shl && !Sh->isValueDependent() &&
         Sh->getLHS()->isIntegerConstantExpr(Ctx);
}
bool isFlagTest(const BinaryOperator *BO, const ASTContext &Ctx) {
  if (BO->getOpcode() != BO_And || BO->isValueDependent())
    return false;
  if (isShiftedBit(BO->getLHS(), Ctx) || isShiftedBit(BO->getRHS(), Ctx))
    return true;
  return BO->getLHS()->isIntegerConstantExpr(Ctx) !=
         BO->getRHS()->isIntegerConstantExpr(Ctx);
}
// A constant `A | B` building the mask of a flag test: `flags & (A | B)`.
bool inFlagMask(const BinaryOperator *BO, ASTContext &Ctx) {
  if (BO->isValueDependent() || !BO->isIntegerConstantExpr(Ctx))
    return false;
  const Stmt *Cur = BO;
  while (true) {
    auto Parents = Ctx.getParents(*Cur);
    if (Parents.empty())
      return false;
    if (const auto *E = Parents[0].get<Expr>()) {
      if (const auto *P = dyn_cast<BinaryOperator>(E); P && isFlagTest(P, Ctx))
        return true;
      if (isa<ParenExpr>(E) || isa<ImplicitCastExpr>(E) ||
          (isa<BinaryOperator>(E) && !E->isValueDependent() &&
           E->isIntegerConstantExpr(Ctx))) {
        Cur = E;
        continue;
      }
    }
    return false;
  }
}
// The node E's value flows into: up through parentheses, casts, a chain of
// the same operator (`A | B | C`) and the branches of a ?:
// (`opt ? A | B : C`). Returns that consumer and sets Child to the
// expression it consumes.
DynTypedNode consumerOf(const Expr *E, ASTContext &Ctx, const Stmt *&Child) {
  const Stmt *Cur = E;
  const auto *BO = dyn_cast<BinaryOperator>(E);
  while (true) {
    auto Parents = Ctx.getParents(*Cur);
    if (Parents.empty()) {
      Child = Cur;
      return DynTypedNode();
    }
    if (const auto *P = Parents[0].get<Expr>()) {
      if (isa<ParenExpr>(P) || isa<CastExpr>(P)) {
        Cur = P;
        continue;
      }
      if (const auto *PB = dyn_cast<BinaryOperator>(P);
          PB && BO && PB->getOpcode() == BO->getOpcode() &&
          (BO->getOpcode() == BO_Or || BO->getOpcode() == BO_And)) {
        Cur = P;
        continue;
      }
      if (const auto *CO = dyn_cast<ConditionalOperator>(P);
          CO && CO->getCond() != Cur) {
        Cur = P;
        continue;
      }
    }
    Child = Cur;
    return Parents[0];
  }
}

// E is an argument of a call: it builds that argument (`lookup(t, A | B)`),
// whatever the call's result is used for.
bool isCallArgument(const Expr *E, ASTContext &Ctx) {
  const Stmt *Child = nullptr;
  DynTypedNode N = consumerOf(E, Ctx, Child);
  if (const auto *CE = N.get<CallExpr>())
    return CE->getCallee() != Child;
  return false;
}
// BO sits in its own parentheses: `if ((a = b))`, `!(a = b)`, the
// conventional way to say an assignment in a condition is meant.
bool parenthesized(const BinaryOperator *BO, ASTContext &Ctx) {
  auto Parents = Ctx.getParents(*BO);
  return !Parents.empty() && Parents[0].get<ParenExpr>();
}

// BO (through parentheses and casts) is an operand of an operator from a
// macro body, in an `if` that also comes from the macro: flags handed to a
// macro that tests them itself
// (`msg(M_WARN | M_ERRNO, ...)` -> `if ((flags) & M_FATAL)`).
bool operandOfMacroOperator(const BinaryOperator *BO, ASTContext &Ctx) {
  const Stmt *Child = nullptr;
  const auto *Outer = consumerOf(BO, Ctx, Child).get<BinaryOperator>();
  return Outer && fromMacro(Outer, Ctx);
}

bool isCharPointer(QualType T) {
  return T->isPointerType() && T->getPointeeType()->isAnyCharacterType();
}

bool isNulChar(const Expr *E) {
  const auto *CL = dyn_cast<CharacterLiteral>(E->IgnoreParenCasts());
  return CL && CL->getValue() == 0;
}

class TyposChecker : public Checker<check::ASTCodeBody> {
  mutable const Decl *CurD = nullptr;
  mutable AnalysisManager *CurMgr = nullptr;
  mutable BugReporter *CurBR = nullptr;

  void report(const Stmt *S, StringRef What) const {
    raptor::reportAt(*CurBR, this, "Typo in operator", What.str() +
                         ", which may not be what the programmer intended",
                     S, CurMgr->getAnalysisDeclContext(CurD));
  }

  // if (<... $E1 OP $E2 ...>) not inside if (<... ($E1 OP $E2) CMP $_ ...>)
  void checkIfCondition(const IfStmt *If, ASTContext &Ctx) const {
    const Expr *Cond = If->getCond();
    if (!Cond)
      return;
    bool Assign = false, BitAnd = false, BitOr = false, Copy = false;
    // the `if` itself comes from a macro body (`msg(...)` -> `if (...)`)
    const SourceManager &SM = Ctx.getSourceManager();
    bool IfFromMacro = If->getIfLoc().isMacroID() && !SM.isMacroArgExpansion(If->getIfLoc());
    auto Ops = binaryOperator(hasAnyOperatorName("=", "&", "|")).bind("op");
    for (const BoundNodes &N : match(findAll(Ops), *Cond, Ctx)) {
      const auto *BO = N.getNodeAs<BinaryOperator>("op");
      if (fromMacro(BO, Ctx) || isComparedLHS(BO, Ctx))
        continue;
      if (isFlagTest(BO, Ctx) || inFlagMask(BO, Ctx))
        continue;
      if (BO->getOpcode() != BO_Assign &&
          (isCallArgument(BO, Ctx) ||
           (IfFromMacro && operandOfMacroOperator(BO, Ctx))))
        continue;
      if (BO->getOpcode() == BO_Assign && parenthesized(BO, Ctx))
        continue;
      Assign |= BO->getOpcode() == BO_Assign;
      BitAnd |= BO->getOpcode() == BO_And;
      BitOr |= BO->getOpcode() == BO_Or;
    }
    auto Copies = callExpr(callee(functionDecl(hasAnyName("strcpy", "strncpy"))));
    Copy = !match(findAll(Copies), *Cond, Ctx).empty();
    if (Assign)
      report(If, "Assignment in an if condition, instead of a comparison");
    if (BitAnd || BitOr)
      report(If, "Bitwise operator in an if condition, instead of a logical one");
    if (Copy)
      report(If, "String copy function in an if condition");
    if (isa<NullStmt>(If->getThen()) && !If->getThen()->getBeginLoc().isMacroID())
      report(If, "Empty body after if");
  }

public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    CurD = D;
    CurMgr = &Mgr;
    CurBR = &BR;
    ASTContext &Ctx = Mgr.getASTContext();
    const Stmt *Body = D->getBody();

    for (const BoundNodes &N : match(findAll(ifStmt().bind("if")), *Body, Ctx))
      checkIfCondition(N.getNodeAs<IfStmt>("if"), Ctx);

    for (const BoundNodes &N : match(findAll(forStmt().bind("for")), *Body, Ctx)) {
      const auto *For = N.getNodeAs<ForStmt>("for");
      if (const auto *BO = dyn_cast_or_null<BinaryOperator>(For->getInit()))
        if (BO->getOpcode() == BO_EQ && !fromMacro(BO, Ctx))
          report(For, "Comparison in the initialization of a for loop");
      if (For->getInit() && For->getCond() && For->getInc() &&
          isa<NullStmt>(For->getBody()) && !For->getBody()->getBeginLoc().isMacroID())
        report(For, "Empty body after for");
    }

    // `a == b;` as a statement: its parent is a block or a statement body
    auto ExprStmtEq = binaryOperator(hasOperatorName("=="),
                                     hasParent(stmt(anyOf(compoundStmt(), ifStmt(),
                                                          whileStmt(), doStmt(),
                                                          forStmt(), caseStmt(),
                                                          defaultStmt(), labelStmt()))))
                          .bind("eq");
    for (const BoundNodes &N : match(findAll(ExprStmtEq), *Body, Ctx)) {
      const auto *BO = N.getNodeAs<BinaryOperator>("eq");
      // the condition of an if/while/for is not a statement
      auto Parents = Ctx.getParents(*BO);
      if (const auto *If = Parents[0].get<IfStmt>(); If && If->getCond() == BO)
        continue;
      if (const auto *W = Parents[0].get<WhileStmt>(); W && W->getCond() == BO)
        continue;
      if (const auto *Do = Parents[0].get<DoStmt>(); Do && Do->getCond() == BO)
        continue;
      if (const auto *F = Parents[0].get<ForStmt>(); F && F->getBody() != BO)
        continue;
      if (!fromMacro(BO, Ctx))
        report(BO, "Comparison used as a statement, instead of an assignment");
    }

    auto All = binaryOperator().bind("bo");
    for (const BoundNodes &N : match(findAll(All), *Body, Ctx)) {
      const auto *BO = N.getNodeAs<BinaryOperator>("bo");
      if (fromMacro(BO, Ctx))
        continue;
      BinaryOperatorKind K = BO->getOpcode();
      if (K == BO_Assign) {
        if (const auto *UO = dyn_cast<UnaryOperator>(BO->getRHS()->IgnoreParenImpCasts()))
          if (UO->getOpcode() == UO_Plus)
            report(BO, "Assignment of a unary plus (=+), instead of +=");
      }
      if ((BO->isLogicalOp() || BO->isComparisonOp()) &&
          sameExpr(BO->getLHS(), BO->getRHS(), Ctx))
        report(BO, "Both operands of the operator are identical");
      if ((K == BO_Assign || K == BO_EQ || K == BO_NE) &&
          isCharPointer(BO->getLHS()->IgnoreParenImpCasts()->getType()) &&
          isNulChar(BO->getRHS()))
        report(BO, "A char pointer is assigned or compared to '\\0', instead "
                   "of the character it points to");
    }

    // char buf[040];
    for (const BoundNodes &N : match(stmt(forEachDescendant(varDecl().bind("v"))),
                                     *Body, Ctx)) {
      const auto *VD = N.getNodeAs<VarDecl>("v");
      const TypeSourceInfo *TSI = VD->getTypeSourceInfo();
      if (!TSI)
        continue;
      auto ATL = TSI->getTypeLoc().getAsAdjusted<ConstantArrayTypeLoc>();
      if (!ATL || !ATL.getSizeExpr() || ATL.getSizeExpr()->getBeginLoc().isMacroID())
        continue;
      StringRef Text = Lexer::getSourceText(
          CharSourceRange::getTokenRange(ATL.getSizeExpr()->getSourceRange()),
          Ctx.getSourceManager(), Ctx.getLangOpts());
      if (Text.size() >= 2 && Text[0] == '0' && Text[1] != 'x' && Text[1] != 'X')
        raptor::reportAt(BR, this, "Typo in operator",
                         "The array size is an octal literal, which may not "
                         "be what the programmer intended",
                         VD);
    }
  }
};
} // namespace

RAPTOR_CHECKER(TyposChecker, "Typos", "Typos in operators that change the meaning of the code")
