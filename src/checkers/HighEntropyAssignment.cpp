// raptor.HighEntropyAssignment: a string literal assigned to a
// variable looks like a secret according to semgrep's `entropy` analyzer
// (src/engine/Entropy.ml, reimplemented here with the same trigram data):
// more than 64 bits of entropy and an information density above 0.6.
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/StringMap.h"
#include <cmath>

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
const std::pair<const char *, long> Trigrams[] = {
#include "HighEntropyAssignmentTrigrams.inc"
};

struct EntropyTables {
  llvm::StringMap<double> Trigram;
  double Char[256];

  EntropyTables() {
    double Total = 0;
    for (const auto &[T, C] : Trigrams)
      Total += C;
    for (const auto &[T, C] : Trigrams)
      Trigram[T] = std::log2(Total / C);
    double Counts[256] = {};
    for (const auto &[T, C] : Trigrams)
      for (int I = 0; I < 3; ++I)
        Counts[(unsigned char)T[I]] += C;
    for (int I = 0; I < 256; ++I)
      Char[I] = Counts[I] == 0 ? std::log2(62.0) : std::log2(3 * Total / Counts[I]);
  }

  double substring(StringRef S) const {
    auto C = [&](int I) { return Char[(unsigned char)S[I]]; };
    switch (S.size()) {
    case 3: {
      auto It = Trigram.find(S);
      return (It != Trigram.end() ? It->second : C(0) + C(1) + C(2)) / 3;
    }
    case 2:
      return (C(0) + C(1)) / 2;
    default:
      return C(0);
    }
  }

  double entropy(StringRef S) const {
    if (!S.empty() && S.find_first_not_of(S[0]) == StringRef::npos)
      return 1; // a run of the same character
    std::string N = S.upper();
    double E = 0;
    for (size_t I = 0; I + 3 <= N.size(); ++I)
      E += substring(StringRef(N).substr(I, 3));
    if (N.size() >= 2)
      E += substring(StringRef(N).take_back(2));
    if (N.size() >= 1)
      E += substring(StringRef(N).take_back(1));
    return E;
  }

  bool looksSecret(StringRef S) const {
    if (S.empty())
      return false;
    double E = entropy(S);
    return E > 64 && E / (8.0 * S.size()) > 0.6;
  }
};

class HighEntropyAssignmentChecker
    : public Checker<check::ASTCodeBody, check::ASTDecl<VarDecl>> {
  // "$X": a (possibly concatenated) literal written entirely in the source;
  // semgrep does not see the value of `"AES" OPENSSL_VERSION_PTEXT`.
  static bool isSecretLiteral(const StringLiteral *SL) {
    static const EntropyTables Tables;
    if (!SL || !(SL->isOrdinary() || SL->isUTF8()))
      return false;
    for (unsigned I = 0, N = SL->getNumConcatenated(); I < N; ++I)
      if (SL->getStrTokenLoc(I).isMacroID())
        return false;
    return Tables.looksSecret(SL->getString());
  }

  void check(const StringLiteral *SL, const Stmt *Where, const Decl *D,
             AnalysisManager &Mgr, BugReporter &BR) const {
    if (!isSecretLiteral(SL))
      return;
    raptor::reportAt(BR, this, "High-entropy string assignment",
                     "A high-entropy string is assigned to a variable; it may "
                     "be a hard-coded secret such as a password or API key",
                     Where, Mgr.getAnalysisDeclContext(D));
  }

public:
  // file-scope `T x = "..."` (function-local ones are in checkASTCodeBody)
  void checkASTDecl(const VarDecl *VD, AnalysisManager &Mgr,
                    BugReporter &BR) const {
    const Expr *Init = VD->getInit();
    if (!VD->isFileVarDecl() || !Init ||
        !isSecretLiteral(dyn_cast<StringLiteral>(Init->IgnoreParenImpCasts())))
      return;
    raptor::reportAt(BR, this, "High-entropy string assignment",
                     "A high-entropy string is assigned to a variable; it may "
                     "be a hard-coded secret such as a password or API key",
                     VD);
  }

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    // $_ = "$X", as an assignment or a declaration
    for (const BoundNodes &N :
         match(findAll(binaryOperator(hasOperatorName("=")).bind("a")), *D->getBody(), Ctx)) {
      const auto *BO = N.getNodeAs<BinaryOperator>("a");
      check(dyn_cast<StringLiteral>(BO->getRHS()->IgnoreParenImpCasts()), BO, D, Mgr, BR);
    }
    for (const BoundNodes &N :
         match(stmt(forEachDescendant(varDecl(hasInitializer(expr())).bind("v"))),
               *D->getBody(), Ctx)) {
      const auto *VD = N.getNodeAs<VarDecl>("v");
      check(dyn_cast<StringLiteral>(VD->getInit()->IgnoreParenImpCasts()),
            VD->getInit(), D, Mgr, BR);
    }
  }
};
} // namespace

RAPTOR_CHECKER(HighEntropyAssignmentChecker, "HighEntropyAssignment",
               "High-entropy string literal assigned to a variable")
