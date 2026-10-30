// raptor.RegexDos: regcomp() family calls whose regex (a string
// literal passed directly, or assigned to a local variable that is then passed)
// is prone to catastrophic backtracking. semgrep's `redos` metavariable
// analyzer is approximated by detecting nested unbounded quantifiers, e.g.
// (a+)* or ((b|c+)d)+. Reported at the regex literal, like the rule's
// focus-metavariable.
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <vector>

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
// Is Re[I...] a quantifier? On success, sets Unbounded and advances I past it
// (including a lazy/possessive suffix).
bool parseQuantifier(StringRef Re, size_t &I, bool &Unbounded) {
  size_t J = I;
  char C = Re[J];
  if (C == '*' || C == '+' || C == '?') {
    Unbounded = C != '?';
    ++J;
  } else if (C == '{') {
    size_t Close = Re.find('}', J);
    if (Close == StringRef::npos)
      return false;
    StringRef Body = Re.slice(J + 1, Close);
    StringRef Min = Body.take_until([](char X) { return X == ','; });
    StringRef Rest = Body.drop_front(Min.size());
    auto IsNum = [](StringRef S) {
      return !S.empty() && llvm::all_of(S, [](char X) { return isdigit(X); });
    };
    if (!IsNum(Min) || !(Rest.empty() || Rest == "," ||
                         (Rest[0] == ',' && IsNum(Rest.drop_front()))))
      return false;
    Unbounded = Rest == ",";
    J = Close + 1;
  } else
    return false;
  if (J < Re.size() && (Re[J] == '?' || Re[J] == '+'))
    ++J;
  I = J;
  return true;
}

// Star height > 1: an unboundedly repeated group that itself contains an
// unbounded repetition.
bool hasNestedQuantifier(StringRef Re) {
  std::vector<bool> GroupHasUnbounded{false}; // [0] is the whole regex
  bool PrevIsGroup = false, PrevGroupHasUnbounded = false;
  size_t I = 0, N = Re.size();
  while (I < N) {
    char C = Re[I];
    bool Unbounded;
    if (C == '\\') {
      I += 2;
    } else if (C == '[') {
      ++I;
      if (I < N && Re[I] == '^')
        ++I;
      if (I < N && Re[I] == ']')
        ++I;
      while (I < N && Re[I] != ']') {
        if (Re[I] == '[' && I + 1 < N && StringRef(":=.").contains(Re[I + 1])) {
          size_t End = Re.find((std::string(1, Re[I + 1]) + "]").c_str(), I + 2);
          I = End == StringRef::npos ? N : End + 2;
        } else
          I += Re[I] == '\\' ? 2 : 1;
      }
      ++I;
    } else if (C == '(') {
      GroupHasUnbounded.push_back(false);
      ++I;
      continue;
    } else if (C == ')' && GroupHasUnbounded.size() > 1) {
      PrevGroupHasUnbounded = GroupHasUnbounded.back();
      GroupHasUnbounded.pop_back();
      if (PrevGroupHasUnbounded)
        GroupHasUnbounded.back() = true;
      PrevIsGroup = true;
      ++I;
      continue;
    } else if (parseQuantifier(Re, I, Unbounded)) {
      if (Unbounded) {
        if (PrevIsGroup && PrevGroupHasUnbounded)
          return true;
        GroupHasUnbounded.back() = true;
      }
    } else {
      ++I;
    }
    PrevIsGroup = false;
  }
  return false;
}

class RegexDosChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    const Stmt *Body = D->getBody();
    raptor::api::forEachCall(D, Mgr, [&](const CallExpr *CE) {
      if (CE->getNumArgs() != 3 ||
          !raptor::isOneOf(raptor::api::calleeAsWritten(CE, Ctx),
                           {"regcomp", "regncomp", "regwcomp", "regwncomp",
                            "regcomp_l", "regncomp_l", "regwcomp_l",
                            "regwncomp_l"}))
        return;
      std::vector<const StringLiteral *> Regexes;
      const Expr *Arg = CE->getArg(1)->IgnoreParenImpCasts();
      if (const auto *SL = dyn_cast<StringLiteral>(Arg)) {
        // $FUN($_, $REGEX, $_)
        Regexes.push_back(SL);
      } else if (const auto *DRE = dyn_cast<DeclRefExpr>(Arg)) {
        // $STRING = $REGEX; ... $FUN($_, $STRING, $_)
        const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
        if (!VD || !VD->isLocalVarDecl())
          return;
        if (VD->getInit())
          if (const auto *SL =
                  dyn_cast<StringLiteral>(VD->getInit()->IgnoreParenImpCasts()))
            Regexes.push_back(SL);
        auto Assign = binaryOperator(
            hasOperatorName("="),
            hasLHS(ignoringParenImpCasts(declRefExpr(to(equalsNode(VD))))),
            hasRHS(ignoringParenImpCasts(stringLiteral().bind("lit"))));
        for (const BoundNodes &N : match(findAll(Assign), *Body, Ctx)) {
          const auto *SL = N.getNodeAs<StringLiteral>("lit");
          if (Ctx.getSourceManager().isBeforeInTranslationUnit(
                  SL->getBeginLoc(), CE->getBeginLoc()))
            Regexes.push_back(SL);
        }
      }
      for (const StringLiteral *SL : Regexes)
        if ((SL->isOrdinary() || SL->isUTF8()) &&
            hasNestedQuantifier(SL->getString()))
          raptor::reportAt(BR, this, "Regular expression DoS",
                           "The software uses a regular expression with an "
                           "inefficient, possibly exponential worst-case "
                           "computational complexity (ReDoS)",
                           SL, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(RegexDosChecker, "RegexDos",
               "Regular expressions prone to catastrophic backtracking")
