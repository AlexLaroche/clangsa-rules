// raptor.UnboundedCopyToStackArray: a string of unknown length is copied into
// a fixed-size local array and nothing in the function compares its length
// with anything: a stack overflow (CWE-121, CWE-787).
//
//   char l_pattern[2 * PATTERN_MAX];
//   strcpy(l_pattern, pattern);
//
// Destination: a sized local array with automatic storage.
// Copies: strcpy/stpcpy/strcat/wcscpy/wcscat of a source that is not a
// literal; sprintf/vsprintf with a non-literal format, or with a "%s" that
// has no precision and takes a non-literal argument.
// Not reported: a literal, a choice of literals, an element of a table of
// literals, or a local only ever set to these; a source array (local or
// field) no larger than the
// destination; a source whose length (`strlen(s)`, or a local set from it)
// appears in a relational comparison anywhere in the function.
//
// CVE-2026-40489 (editorconfig-core-c ec_glob).
#include "Common.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

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

// Size in elements of a sized local array, or 0.
uint64_t stackArraySize(const Expr *E, ASTContext &Ctx) {
  const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(E));
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  if (!VD || isa<ParmVarDecl>(VD) || !VD->hasLocalStorage())
    return 0;
  const auto *CAT = Ctx.getAsConstantArrayType(VD->getType());
  return CAT ? CAT->getSize().getZExtValue() : 0;
}

// Size of a source that is an array (local, global or field), or 0.
uint64_t arraySize(const Expr *E, ASTContext &Ctx) {
  E = raptor::strip(E);
  const ValueDecl *VD = nullptr;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    VD = DRE->getDecl();
  else if (const auto *ME = dyn_cast<MemberExpr>(E))
    VD = ME->getMemberDecl();
  if (!VD)
    return 0;
  const auto *CAT = Ctx.getAsConstantArrayType(VD->getType());
  return CAT ? CAT->getSize().getZExtValue() : 0;
}

// A string literal, a choice of literals, an element of an array initialised
// with literals (`modes[m]`), or a local whose every value is one of these.
bool isLiteral(const Expr *E, const std::map<const VarDecl *, std::vector<const Expr *>> &Defs,
               int Depth = 0) {
  E = raptor::strip(E);
  if (!E || Depth > 6)
    return false;
  if (const auto *CO = dyn_cast<ConditionalOperator>(E))
    return isLiteral(CO->getTrueExpr(), Defs, Depth + 1) &&
           isLiteral(CO->getFalseExpr(), Defs, Depth + 1);
  if (isa<StringLiteral>(E) || isa<PredefinedExpr>(E))
    return true;
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(ASE->getBase()));
    const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
    const auto *IL = VD ? dyn_cast_or_null<InitListExpr>(VD->getInit()) : nullptr;
    if (!IL || IL->getNumInits() == 0)
      return false;
    for (const Expr *I : IL->inits())
      if (!isa<StringLiteral>(raptor::strip(I)))
        return false;
    return true;
  }
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    auto It = VD ? Defs.find(VD) : Defs.end();
    if (It == Defs.end() || It->second.empty())
      return false;
    for (const Expr *D : It->second)
      if (!isLiteral(D, Defs, Depth + 1))
        return false;
    return true;
  }
  return false;
}

const StringLiteral *literalOf(const Expr *E) {
  return dyn_cast<StringLiteral>(raptor::strip(E));
}

// The arguments consumed by "%s" conversions with no precision.
std::vector<unsigned> unboundedStringArgs(StringRef Fmt, unsigned First) {
  std::vector<unsigned> Out;
  unsigned Arg = First;
  for (size_t I = 0; I < Fmt.size(); ++I) {
    if (Fmt[I] != '%')
      continue;
    if (++I < Fmt.size() && Fmt[I] == '%')
      continue;
    bool Precision = false;
    for (; I < Fmt.size() && StringRef("-+ #0123456789.*hlLqjzt'").contains(Fmt[I]); ++I) {
      if (Fmt[I] == '.')
        Precision = true;
      if (Fmt[I] == '*')
        ++Arg;
    }
    if (I >= Fmt.size())
      break;
    if ((Fmt[I] == 's' || Fmt[I] == 'S') && !Precision)
      Out.push_back(Arg);
    ++Arg;
  }
  return Out;
}

class UnboundedCopyToStackArrayChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();

    // Strings whose length is compared: keys of strlen() arguments and of
    // locals set from strlen() that appear in a relational comparison.
    std::map<std::string, std::set<std::string>> LenLocals; // local -> string keys
    walk(Body, [&](const Stmt *S) {
      auto note = [&](const std::string &Local, const Expr *Init) {
        walk(Init, [&](const Stmt *X) {
          if (const auto *CE = dyn_cast<CallExpr>(X))
            if (raptor::isOneOf(raptor::calleeName(CE), {"strlen", "wcslen", "strnlen"}) &&
                CE->getNumArgs() >= 1)
              LenLocals[Local].insert(raptor_mem::keyOf(CE->getArg(0)));
        });
      };
      if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *Dc : DS->decls())
          if (const auto *V = dyn_cast<VarDecl>(Dc))
            if (V->getInit())
              note(V->getNameAsString(), V->getInit());
      } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isAssignmentOp())
          note(raptor_mem::keyOf(BO->getLHS()), BO->getRHS());
      }
    });
    // Values of locals (pointers only): every initialiser and assignment.
    std::map<const VarDecl *, std::vector<const Expr *>> Defs;
    walk(Body, [&](const Stmt *S) {
      if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *Dc : DS->decls())
          if (const auto *V = dyn_cast<VarDecl>(Dc))
            if (V->hasLocalStorage() && !isa<ParmVarDecl>(V) && V->getType()->isPointerType())
              Defs[V].push_back(V->getInit()); // null: no initialiser, not literal
      } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->isAssignmentOp())
          if (const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(BO->getLHS())))
            if (const auto *V = dyn_cast<VarDecl>(DRE->getDecl()))
              Defs[V].push_back(BO->getRHS());
      } else if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
        if (UO->getOpcode() == UO_AddrOf) // address taken: written elsewhere
          if (const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(UO->getSubExpr())))
            if (const auto *V = dyn_cast<VarDecl>(DRE->getDecl()))
              Defs[V].push_back(nullptr);
      }
    });
    std::set<std::string> Checked;
    walk(Body, [&](const Stmt *S) {
      const auto *BO = dyn_cast<BinaryOperator>(S);
      if (!BO || !BO->isRelationalOp())
        return;
      walk(BO, [&](const Stmt *X) {
        if (const auto *CE = dyn_cast<CallExpr>(X)) {
          if (raptor::isOneOf(raptor::calleeName(CE), {"strlen", "wcslen", "strnlen"}) &&
              CE->getNumArgs() >= 1)
            Checked.insert(raptor_mem::keyOf(CE->getArg(0)));
        } else if (isa<DeclRefExpr>(X) || isa<MemberExpr>(X)) {
          auto It = LenLocals.find(raptor_mem::keyOf(cast<Expr>(X)));
          if (It != LenLocals.end())
            Checked.insert(It->second.begin(), It->second.end());
        }
      });
    });

    walk(Body, [&](const Stmt *S) {
      const auto *CE = dyn_cast<CallExpr>(S);
      if (!CE || CE->getNumArgs() < 2)
        return;
      StringRef N = raptor::calleeName(CE);
      if (!N.consume_front("__builtin___"))
        N.consume_front("__builtin_");
      N.consume_back("_chk");
      bool Copy = raptor::isOneOf(N, {"strcpy", "stpcpy", "strcat", "wcscpy", "wcscat"});
      bool Format = raptor::isOneOf(N, {"sprintf", "vsprintf"});
      if (!Copy && !Format)
        return;
      uint64_t Dst = stackArraySize(CE->getArg(0), Ctx);
      if (!Dst)
        return;
      // _chk variants carry a flag and an object size before the format.
      unsigned FmtIdx = raptor::calleeName(CE).ends_with("_chk") ? 3 : 1;
      std::vector<const Expr *> Sources;
      if (Copy) {
        Sources.push_back(CE->getArg(1));
      } else if (CE->getNumArgs() > FmtIdx) {
        const StringLiteral *Fmt = literalOf(CE->getArg(FmtIdx));
        if (!Fmt) {
          if (N == "vsprintf" || CE->getNumArgs() > FmtIdx + 1)
            Sources.push_back(CE->getArg(FmtIdx));
        } else if (Fmt->getCharByteWidth() == 1 && N == "sprintf") {
          for (unsigned A : unboundedStringArgs(Fmt->getString(), FmtIdx + 1))
            if (A < CE->getNumArgs())
              Sources.push_back(CE->getArg(A));
        }
      }
      for (const Expr *Src : Sources) {
        if (isLiteral(Src, Defs))
          continue;
        uint64_t SrcSize = arraySize(Src, Ctx);
        if (SrcSize && SrcSize <= Dst)
          continue;
        if (Checked.count(raptor_mem::keyOf(Src)))
          continue;
        const auto *DRE = cast<DeclRefExpr>(raptor::strip(CE->getArg(0)));
        raptor::reportAt(BR, this, "Unbounded copy to stack array",
                         "'" + DRE->getDecl()->getNameAsString() + "' holds " +
                             std::to_string(Dst) +
                             " elements, but the length of the string copied into it is "
                             "compared with nothing: stack overflow (CWE-121)",
                         CE, Mgr.getAnalysisDeclContext(D));
        break;
      }
    });
  }
};
} // namespace

RAPTOR_CHECKER(UnboundedCopyToStackArrayChecker, "UnboundedCopyToStackArray",
               "String of unchecked length copied into a fixed-size local array")
