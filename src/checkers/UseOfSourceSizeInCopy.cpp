// raptor.UseOfSourceSizeInCopy: copy functions whose size is
// derived from the source buffer instead of the destination:
//  - $FUN($DST, $SRC, $LEN) with $SRC declared as `$_ $SRC[$LEN]` and $DST
//    not declared as `$_ $DST[$LEN]`;
//  - $FUN($DST, $SRC, <... $SRC ...>);
//  - snprintf-like $FUN($DST, <... $SRC ...>, ..., $SRC, ...).
//  - into a destination of fixed capacity (an array, `&local_struct`), the
//    source's own length: a sibling size field (`memcpy(ha1, c->data.ptr,
//    c->data.slen)`, pjsip CVE-2026-40892) or the container's size
//    (`memcpy(s->data, v.data(), v.size())`, SimpleBLE CVE-2026-44634),
//    with no upper bound on that length before the copy (`if (len >
//    sizeof(dst)) return;`, `if (len <= cap) memcpy(...)`, a min()). A lower
//    bound (`PJ_ASSERT_RETURN(slen >= need)`) does not count.
// Not reported: a destination allocated with room for the length (`d =
// malloc(n * sizeof(*s)); memcpy(d, s, n * sizeof(*s));`, also as one term
// of the allocation through a variable: libuv uv_getaddrinfo), `sizeof(*src)`
// into a destination object at least that large (a sockaddr_in6 into a
// sockaddr_storage), and a length that contains the source but is bounded
// from above before a copy into an array (libuv `if ((size_t)(z - p) >=
// PATH_MAX) continue; memcpy(b, p, z - p);`).
// Copy functions include thin wrappers defined in the translation unit
// (`static inline void *pj_memcpy(d, s, n) { return memcpy(d, s, n); }`).
// A string literal source is excluded, including (like semgrep's constant
// propagation) a variable initialized with a literal and never assigned.
#include "ApiUtil.h"
#include "BufHelpers.h"
#include "MemFlow.h"
#include "Registry.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {
bool isCopyFunction(StringRef N) {
  return raptor::isOneOf(N, {"strncpy", "stpncpy", "strlcpy", "strscpy",
                             "memcpy", "memmove", "wmemcpy", "wmemmove",
                             "mempcpy", "wmempcpy"});
}

bool isPrintfFunction(StringRef N) {
  return raptor::isOneOf(N, {"snprintf", "vsnprintf", "swprintf", "vswprintf"});
}

// "..." or a variable holding a constant string literal.
bool isConstantString(const Expr *E, const Stmt *Body) {
  if (isStringLit(E))
    return true;
  const auto *DRE = dyn_cast<DeclRefExpr>(ign(E));
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  if (!VD || !VD->hasLocalStorage() || !isStringLit(VD->getInit()))
    return false;
  bool Assigned = false;
  forEach<BinaryOperator>(Body, [&](const BinaryOperator *BO) {
    if (BO->isAssignmentOp() && refDecl(BO->getLHS()) == VD)
      Assigned = true;
  });
  return !Assigned;
}

bool isLiteral(const Expr *E) {
  return isa<IntegerLiteral, CharacterLiteral, StringLiteral, FloatingLiteral>(
      ign(E));
}

// (dst, src, len) of a copy: a copy function, or a thin wrapper whose body
// is `return copy(p0, p1, p2);` with its parameters forwarded.
struct CopyArgs {
  const Expr *Dst = nullptr, *Src = nullptr, *Len = nullptr;
};
std::optional<CopyArgs> copyArgs(const CallExpr *CE) {
  StringRef N = raptor::calleeName(CE);
  if (isCopyFunction(N))
    return CE->getNumArgs() == 3
               ? std::optional<CopyArgs>(
                     CopyArgs{CE->getArg(0), CE->getArg(1), CE->getArg(2)})
               : std::nullopt;
  const FunctionDecl *FD = CE->getDirectCallee(), *Def = nullptr;
  if (!FD || !FD->hasBody(Def))
    return std::nullopt;
  const auto *Body = dyn_cast<CompoundStmt>(Def->getBody());
  if (!Body || Body->size() != 1)
    return std::nullopt;
  const Stmt *S = Body->body_front();
  if (const auto *RS = dyn_cast<ReturnStmt>(S))
    S = RS->getRetValue();
  const auto *Inner =
      dyn_cast_or_null<CallExpr>(ign(dyn_cast_or_null<Expr>(S)));
  if (!Inner || !isCopyFunction(raptor::calleeName(Inner)) ||
      Inner->getNumArgs() != 3)
    return std::nullopt;
  const Expr *A[3];
  for (unsigned I = 0; I < 3; ++I) {
    const auto *PV = dyn_cast_or_null<ParmVarDecl>(refDecl(Inner->getArg(I)));
    if (!PV || PV->getFunctionScopeIndex() >= CE->getNumArgs())
      return std::nullopt;
    A[I] = CE->getArg(PV->getFunctionScopeIndex());
  }
  return CopyArgs{A[0], A[1], A[2]};
}

const Expr *stripCasts(const Expr *E) {
  while (true) {
    E = E->IgnoreParenImpCasts();
    if (const auto *C = dyn_cast<ExplicitCastExpr>(E))
      E = C->getSubExpr();
    else
      return E;
  }
}

// `sizeof(*src)` into an object of that type (`memcpy(&s->pref, p,
// sizeof(*p))`).
bool sameObjectSize(const Expr *Dst, const Expr *Len, ASTContext &Ctx) {
  const auto *SZ = dyn_cast<UnaryExprOrTypeTraitExpr>(ign(Len));
  if (!SZ || SZ->getKind() != UETT_SizeOf)
    return false;
  QualType T = SZ->getTypeOfArgument();
  const Expr *D = stripCasts(Dst);
  QualType O;
  if (const auto *UO = dyn_cast<UnaryOperator>(D);
      UO && UO->getOpcode() == UO_AddrOf)
    O = UO->getSubExpr()->getType();
  else if (D->getType()->isPointerType())
    O = D->getType()->getPointeeType();
  else
    O = D->getType();
  if (O.isNull() || O->isVoidType() || O->isIncompleteType() ||
      T->isIncompleteType())
    return false;
  return Ctx.getTypeSizeInChars(O) >= Ctx.getTypeSizeInChars(T) &&
         (Ctx.hasSameUnqualifiedType(O, T) ||
          (O->isRecordType() && T->isRecordType()));
}

std::string squeezed(const Expr *E, ASTContext &Ctx) {
  std::string T;
  for (char Ch : raptor::api::textAsWritten(E, Ctx))
    if (!isspace(static_cast<unsigned char>(Ch)))
      T += Ch;
  return T;
}

// Was Dst (or the base of `Dst + off`) assigned, before Call, the result of an
// allocation whose size holds Len's text, directly or in the value of a
// local variable used in the size?
bool allocatedFor(const Stmt *Body, const CallExpr *Call, const Expr *Dst,
                  const Expr *Len, ASTContext &Ctx) {
  const SourceManager &SM = Ctx.getSourceManager();
  const Expr *Base = stripCasts(Dst);
  if (const auto *BO = dyn_cast<BinaryOperator>(Base);
      BO && BO->isAdditiveOp() && BO->getLHS()->getType()->isPointerType())
    Base = stripCasts(BO->getLHS());
  std::string L = squeezed(Len, Ctx);
  if (L.empty())
    return false;
  SourceLocation At = SM.getExpansionLoc(Call->getBeginLoc());
  auto Values = [&](const VarDecl *V, std::vector<const Expr *> &Out) {
    if (V->getInit())
      Out.push_back(V->getInit());
    forEach<BinaryOperator>(Body, [&](const BinaryOperator *A) {
      if (A->isAssignmentOp() && refDecl(A->getLHS()) == V)
        Out.push_back(A->getRHS());
    });
  };
  auto Holds = [&](const Expr *Size) {
    if (squeezed(Size, Ctx).find(L) != std::string::npos)
      return true;
    bool Found = false;
    forEach<DeclRefExpr>(Size, [&](const DeclRefExpr *R) {
      const auto *V = dyn_cast<VarDecl>(R->getDecl());
      if (Found || !V || !V->hasLocalStorage())
        return;
      std::vector<const Expr *> Vs;
      Values(V, Vs);
      for (const Expr *X : Vs)
        Found |= squeezed(X, Ctx).find(L) != std::string::npos;
    });
    return Found;
  };
  auto FromAlloc = [&](const Expr *RHS) {
    const auto *C = dyn_cast_or_null<CallExpr>(stripCasts(RHS));
    if (!C || StringRef(raptor::calleeName(C)).lower().find("alloc") ==
                  std::string::npos)
      return false;
    for (const Expr *A : C->arguments())
      if (Holds(A))
        return true;
    return false;
  };
  auto Before = [&](const Stmt *S) {
    return SM.isBeforeInTranslationUnit(SM.getExpansionLoc(S->getEndLoc()),
                                        At);
  };
  bool B = false;
  forEach<BinaryOperator>(Body, [&](const BinaryOperator *A) {
    B |= A->getOpcode() == BO_Assign && Before(A) &&
         sameExpr(A->getLHS(), Base) && FromAlloc(A->getRHS());
  });
  if (const auto *V = dyn_cast_or_null<VarDecl>(refDecl(Base)))
    B |= V->getInit() && FromAlloc(V->getInit());
  return B;
}

// An array, or the address of a local object: its capacity is known here.
bool fixedCapacity(const Expr *Dst) {
  const Expr *E = stripCasts(Dst);
  if (const auto *CAT = dyn_cast<ConstantArrayType>(
          E->getType()->getUnqualifiedDesugaredType())) {
    // `char name[1];` as the last field: sized at allocation.
    if (const auto *ME = dyn_cast<MemberExpr>(E))
      if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
        const FieldDecl *Last = nullptr;
        for (const FieldDecl *F : FD->getParent()->fields())
          Last = F;
        if (CAT->getSize().ule(1) && Last == FD)
          return false;
      }
    return true;
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(E);
      UO && UO->getOpcode() == UO_AddrOf)
    if (const auto *VD = dyn_cast_or_null<VarDecl>(refDecl(UO->getSubExpr())))
      return VD->hasLocalStorage() && !VD->getType()->isPointerType();
  return false;
}

// The part of Len that is Src's own length: `B.len` next to `B.ptr`, or
// `O.size()` for `O.data()`; null otherwise.
const Expr *sourceLength(const Expr *Src, const Expr *Len) {
  const Expr *S = stripCasts(Src);
  const Expr *Found = nullptr;
  if (const auto *MS = dyn_cast<MemberExpr>(S)) {
    const auto *FS = dyn_cast<FieldDecl>(MS->getMemberDecl());
    if (!FS)
      return nullptr;
    forEach<MemberExpr>(Len, [&](const MemberExpr *ML) {
      const auto *FL = dyn_cast<FieldDecl>(ML->getMemberDecl());
      if (!Found && FL && FL != FS && FL->getType()->isIntegerType() &&
          ML->isArrow() == MS->isArrow() &&
          sameExpr(ML->getBase(), MS->getBase()) &&
          raptor_mem::isSizeField(FL, FS))
        Found = ML;
    });
    return Found;
  }
  if (const auto *CS = dyn_cast<CXXMemberCallExpr>(S)) {
    const CXXMethodDecl *MD = CS->getMethodDecl();
    if (!MD || !MD->getIdentifier() ||
        !raptor::isOneOf(MD->getName(), {"data", "c_str"}))
      return nullptr;
    forEach<CXXMemberCallExpr>(Len, [&](const CXXMemberCallExpr *CL) {
      const CXXMethodDecl *ML = CL->getMethodDecl();
      if (!Found && ML && ML->getIdentifier() &&
          raptor::isOneOf(ML->getName(), {"size", "length"}) &&
          sameExpr(CL->getImplicitObjectArgument(),
                   CS->getImplicitObjectArgument()))
        Found = CL;
    });
    return Found;
  }
  return nullptr;
}

bool exits(const Stmt *S) {
  bool E = false;
  forEach<Stmt>(S, [&](const Stmt *X) {
    if (isa<ReturnStmt>(X) || isa<GotoStmt>(X) || isa<BreakStmt>(X) ||
        isa<ContinueStmt>(X) || isa<CXXThrowExpr>(X))
      E = true;
    else if (const auto *C = dyn_cast<CallExpr>(X);
             C && raptor_mem::neverReturns(C))
      E = true;
  });
  return E;
}

// Relational tests in Cond with the truth value each has when the code goes
// on (`!` flips it; `||` splits when going on means false, `&&` when true).
void tests(const Expr *Cond, bool True,
           std::vector<std::pair<const BinaryOperator *, bool>> &Out) {
  Cond = Cond->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(Cond);
      UO && UO->getOpcode() == UO_LNot)
    return tests(UO->getSubExpr(), !True, Out);
  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if ((BO->getOpcode() == BO_LAnd && True) ||
        (BO->getOpcode() == BO_LOr && !True)) {
      tests(BO->getLHS(), True, Out);
      tests(BO->getRHS(), True, Out);
    } else if (BO->isRelationalOp())
      Out.push_back({BO, True});
  }
}

// Is T bounded from above where Call runs: `if (T > X ...) exit;` before
// it, `if (T < X)` around it, or a min()/?: in the length itself?
bool boundedAbove(const Stmt *Body, const CallExpr *Call, const Expr *Len,
                  const Expr *T, const SourceManager &SM) {
  bool B = false;
  forEach<Stmt>(Len, [&](const Stmt *X) {
    if (isa<ConditionalOperator>(X))
      B = true;
    if (const auto *C = dyn_cast<CallExpr>(X))
      if (StringRef(raptor::calleeName(C)).lower().find("min") !=
          std::string::npos)
        B = true;
  });
  if (B)
    return true;
  SourceLocation At = SM.getExpansionLoc(Call->getBeginLoc());
  // The (ptr, len) object filled before by a call given a constant limit
  // (`str_until(&p, &out, MAX, '=')`).
  const Expr *Obj = nullptr;
  if (const auto *ME = dyn_cast<MemberExpr>(ign(T)))
    Obj = ign(ME->getBase());
  if (Obj)
    forEach<CallExpr>(Body, [&](const CallExpr *C) {
      if (B || C == Call ||
          !SM.isBeforeInTranslationUnit(SM.getExpansionLoc(C->getEndLoc()), At))
        return;
      bool Fills = false, Limit = false;
      for (const Expr *A : C->arguments()) {
        const Expr *X = ign(A);
        if (const auto *UO = dyn_cast<UnaryOperator>(X);
            UO && UO->getOpcode() == UO_AddrOf)
          Fills |= sameExpr(UO->getSubExpr(), Obj) ||
                   (isa<UnaryOperator>(Obj) && sameExpr(UO, Obj));
        if (sameExpr(X, Obj) && X->getType()->isPointerType())
          Fills = true;
        Limit |= !X->isValueDependent() && X->getType()->isIntegerType() &&
                 X->isIntegerConstantExpr(C->getCalleeDecl()->getASTContext());
      }
      B = Fills && Limit;
    });
  if (B)
    return true;
  forEach<IfStmt>(Body, [&](const IfStmt *If) {
    if (B || !If->getCond())
      return;
    bool Around = false;
    forEach<CallExpr>(If->getThen(),
                      [&](const CallExpr *C) { Around |= C == Call; });
    std::vector<std::pair<const BinaryOperator *, bool>> Ts;
    if (Around)
      tests(If->getCond(), true, Ts);
    else if (SM.isBeforeInTranslationUnit(SM.getExpansionLoc(If->getEndLoc()),
                                          At) &&
             exits(If->getThen()))
      tests(If->getCond(), false, Ts);
    for (auto [BO, V] : Ts) {
      BinaryOperatorKind Op = BO->getOpcode();
      if (containsExpr(BO->getRHS(), T) && !containsExpr(BO->getLHS(), T))
        Op = BinaryOperator::reverseComparisonOp(Op);
      else if (!containsExpr(BO->getLHS(), T))
        continue;
      bool Less = Op == BO_LT || Op == BO_LE;
      if (Less == V)
        B = true;
    }
  });
  return B;
}

class UseOfSourceSizeInCopyChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    ASTContext &Ctx = Mgr.getASTContext();
    const Stmt *Body = D->getBody();
    forEach<CallExpr>(Body, [&](const CallExpr *CE) {
      StringRef N = raptor::calleeName(CE);
      bool Bad = false;
      if (std::optional<CopyArgs> C = copyArgs(CE)) {
        const Expr *Dst = C->Dst, *Src = C->Src, *Len = C->Len;
        if (!isConstantString(Src, Body)) {
          Bad = (declaredWithSize(Src, Len, Ctx) &&
                 !declaredWithSize(Dst, Len, Ctx)) ||
                (containsExpr(Len, Src) && !sameObjectSize(Dst, Len, Ctx) &&
                 !(fixedCapacity(Dst) &&
                   boundedAbove(Body, CE, Len, Len, Ctx.getSourceManager())));
          Bad = Bad && !allocatedFor(Body, CE, Dst, Len, Ctx);
          if (!Bad && fixedCapacity(Dst))
            if (const Expr *T = sourceLength(Src, Len))
              Bad = !boundedAbove(Body, CE, Len, T, Ctx.getSourceManager());
        }
      } else if (isPrintfFunction(N) && CE->getNumArgs() >= 3) {
        for (unsigned I = 2; I < CE->getNumArgs() && !Bad; ++I)
          Bad = !isLiteral(CE->getArg(I)) &&
                containsExpr(CE->getArg(1), CE->getArg(I));
      }
      if (Bad)
        raptor::reportAt(
            BR, this, "Use of source size in copy",
            "The software uses the size of a source buffer when reading from "
            "or writing to a destination buffer, which may cause it to "
            "access memory that is outside of the bounds of the buffer.",
            CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(UseOfSourceSizeInCopyChecker, "UseOfSourceSizeInCopy",
               "Copy size derived from the source buffer")
