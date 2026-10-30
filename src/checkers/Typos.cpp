// Port of raptor-typos: operator mistakes that change the meaning of the code.
//   for (a == b; ...)            a == b;
//   if (... a = b ...)           unless (a = b) is compared
//   if (... a & b ...)           unless (a & b) is compared  (same for |)
//   a =+ b                       (E op E) for &&, ||, ==, !=, <, <=, >, >=
//   (char *)p = / == / != '\0'   if (... strcpy()/strncpy() ...)
//   if (x);   for (a; b; c);     char buf[040];  (octal array size)
// Operators coming from macro expansions are skipped: semgrep sees the macro
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
bool fromMacro(const BinaryOperator *BO) { return BO->getOperatorLoc().isMacroID(); }

bool sameExpr(const Expr *A, const Expr *B, const ASTContext &Ctx) {
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
    return BO && BO->isComparisonOp() && BO->getLHS() == Cur;
  }
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
    auto Ops = binaryOperator(hasAnyOperatorName("=", "&", "|")).bind("op");
    for (const BoundNodes &N : match(findAll(Ops), *Cond, Ctx)) {
      const auto *BO = N.getNodeAs<BinaryOperator>("op");
      if (fromMacro(BO) || isComparedLHS(BO, Ctx))
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
        if (BO->getOpcode() == BO_EQ && !fromMacro(BO))
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
      if (!fromMacro(BO))
        report(BO, "Comparison used as a statement, instead of an assignment");
    }

    auto All = binaryOperator().bind("bo");
    for (const BoundNodes &N : match(findAll(All), *Body, Ctx)) {
      const auto *BO = N.getNodeAs<BinaryOperator>("bo");
      if (fromMacro(BO))
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
