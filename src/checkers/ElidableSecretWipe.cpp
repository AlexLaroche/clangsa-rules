// raptor.ElidableSecretWipe: memset()/bzero() zeroes a buffer that nobody
// reads again, the usual way to wipe a key or password, but a dead store
// the optimizer is allowed to delete, leaving the secret in memory (CWE-14,
// CWE-226). Use explicit_bzero(), memset_explicit(), memset_s(),
// SecureZeroMemory() or OPENSSL_cleanse() instead. Two shapes:
//
//  - the buffer is a local (array, struct, or a member of one; not static,
//    not volatile) that held data before the wipe and that no path reads
//    after it: its lifetime ends (`unsigned char pre_master_secret[48]; ...
//    memset(pre_master_secret, 0, 48); return true;`);
//  - the wiped memory is freed by the next statement that mentions it,
//    in the same block: `memset(pair->value, 0, strlen(pair->value));
//    l_free(pair->value);`, `memset(c, 0, sizeof(*c)); free(c);`. Any
//    function whose name ends in "free" counts as the release, except one
//    of another library declared in a system header (talloc_free, g_free):
//    an opaque call that may read the bytes.
//
// A non-zero fill (poisoning), a wipe of memory that outlives the function
// (parameters, globals, statics, members of a caller's object) and a memset
// before the buffer is filled (initialisation) are not reported.
// Modelled on ell 33ed0af (TLS pre-master secret, PRF seed, PEM content,
// settings values), Netatalk 043435c (afppasswd DES key) and GDM e2ab745
// (PAM responses), all fixed by switching to explicit_bzero().
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/Analysis/CFG.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <deque>

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {

// The buffer argument of a zeroing memset()/bzero(), or null.
const Expr *wipedBuffer(const CallExpr *CE, const ASTContext &Ctx) {
  StringRef N = raptor::calleeName(CE);
  if (raptor::isOneOf(N, {"memset", "__builtin_memset", "__builtin___memset_chk"}) &&
      CE->getNumArgs() >= 3) {
    auto V = intValue(CE->getArg(1), Ctx);
    return V && *V == 0 ? CE->getArg(0) : nullptr;
  }
  if (raptor::isOneOf(N, {"bzero", "__builtin_bzero"}) && CE->getNumArgs() == 2)
    return CE->getArg(0);
  return nullptr;
}

// Local whose storage E designates: `buf`, `&s`, `s.k`, `&s.k`, `buf + i`.
const VarDecl *localObject(const Expr *E) {
  E = raptor::strip(E);
  while (true) {
    if (const auto *U = dyn_cast<UnaryOperator>(E); U && U->getOpcode() == UO_AddrOf)
      E = raptor::strip(U->getSubExpr());
    else if (const auto *M = dyn_cast<MemberExpr>(E); M && !M->isArrow())
      E = raptor::strip(M->getBase());
    else if (const auto *B = dyn_cast<BinaryOperator>(E);
             B && B->isAdditiveOp() && B->getLHS()->getType()->isPointerType())
      E = raptor::strip(B->getLHS());
    else
      break;
  }
  const auto *DR = dyn_cast<DeclRefExpr>(E);
  const auto *V = DR ? dyn_cast<VarDecl>(DR->getDecl()) : nullptr;
  if (!V || isa<ParmVarDecl>(V) || !V->hasLocalStorage() || V->getType().isVolatileQualified())
    return nullptr;
  QualType T = V->getType();
  if (!T->isArrayType() && !T->isRecordType())
    return nullptr;
  return V;
}

using VarSet = llvm::SmallPtrSet<const ValueDecl *, 4>;

// References to one of Vs in S, outside unevaluated operands (sizeof) and
// outside the call Skip.
bool refersTo(const Stmt *S, const VarSet &Vs, const Stmt *Skip) {
  if (!S || S == Skip)
    return false;
  if (isa<UnaryExprOrTypeTraitExpr>(S))
    return false;
  if (const auto *DR = dyn_cast<DeclRefExpr>(S))
    return Vs.count(DR->getDecl());
  for (const Stmt *C : S->children())
    if (refersTo(C, Vs, Skip))
      return true;
  return false;
}

// Variable at the root of an lvalue: `msg` for `msg.msg_control`, `sa` for `sa`.
const ValueDecl *rootVar(const Expr *E) {
  E = raptor::strip(E);
  while (true) {
    if (const auto *M = dyn_cast<MemberExpr>(E))
      E = raptor::strip(M->getBase());
    else if (const auto *A = dyn_cast<ArraySubscriptExpr>(E))
      E = raptor::strip(A->getBase());
    else
      break;
  }
  const auto *DR = dyn_cast<DeclRefExpr>(E);
  return DR ? DR->getDecl() : nullptr;
}

// V and every variable that is given a pointer into V somewhere in Body
// (`msg.msg_control = msg_control;`, `sa = (struct sockaddr *)&myaddr;`,
// `char *p = buf;`): reading those reads V.
VarSet withAliases(const Stmt *Body, const VarDecl *V) {
  VarSet Vs;
  Vs.insert(V);
  std::function<bool(const Expr *)> PointsInto = [&](const Expr *E) -> bool {
    if (!E)
      return false;
    if (const auto *C = dyn_cast<ConditionalOperator>(raptor::strip(E)))
      return PointsInto(C->getTrueExpr()) || PointsInto(C->getFalseExpr());
    return localObject(E) == V;
  };
  forEach<BinaryOperator>(Body, [&](const BinaryOperator *B) {
    if (B->getOpcode() == BO_Assign && PointsInto(B->getRHS()))
      if (const ValueDecl *R = rootVar(B->getLHS()))
        Vs.insert(R);
  });
  forEach<VarDecl>(Body, [&](const VarDecl *D) {
    if (D != V && PointsInto(D->getInit()))
      Vs.insert(D);
  });
  return Vs;
}

// Does any path from the wipe CE read V (or an alias of it) again?
bool readAfter(const CFG &G, const CallExpr *CE, const VarSet &V) {
  const CFGBlock *Start = nullptr;
  unsigned Index = 0;
  for (const CFGBlock *B : G) {
    unsigned I = 0;
    for (const CFGElement &E : *B) {
      if (auto CS = E.getAs<CFGStmt>(); CS && CS->getStmt() == CE) {
        Start = B;
        Index = I;
      }
      ++I;
    }
  }
  if (!Start)
    return true; // be conservative
  auto Reads = [&](const CFGBlock *B, unsigned From) {
    unsigned I = 0;
    for (const CFGElement &E : *B) {
      if (I++ < From)
        continue;
      if (auto CS = E.getAs<CFGStmt>())
        if (refersTo(CS->getStmt(), V, CE))
          return true;
    }
    if (const Stmt *T = B->getTerminatorCondition())
      if (refersTo(T, V, CE))
        return true;
    return false;
  };
  if (Reads(Start, Index + 1))
    return true;
  llvm::SmallPtrSet<const CFGBlock *, 32> Seen;
  std::deque<const CFGBlock *> Work;
  for (const CFGBlock *S : Start->succs())
    if (S)
      Work.push_back(S);
  while (!Work.empty()) {
    const CFGBlock *B = Work.front();
    Work.pop_front();
    if (!Seen.insert(B).second)
      continue;
    if (Reads(B, 0))
      return true;
    for (const CFGBlock *S : B->succs())
      if (S)
        Work.push_back(S);
  }
  return false;
}

// Is V used (outside sizeof and outside CE) somewhere in S before CE?
bool usedBefore(const Stmt *S, const VarDecl *V, const CallExpr *CE,
                const SourceManager &SM) {
  if (!S || S == CE || isa<UnaryExprOrTypeTraitExpr>(S))
    return false;
  if (const auto *DR = dyn_cast<DeclRefExpr>(S))
    return DR->getDecl() == V &&
           SM.isBeforeInTranslationUnit(DR->getBeginLoc(), CE->getBeginLoc());
  if (const auto *DS = dyn_cast<DeclStmt>(S))
    for (const Decl *D : DS->decls())
      if (const auto *VD = dyn_cast<VarDecl>(D))
        if (usedBefore(VD->getInit(), V, CE, SM))
          return true;
  for (const Stmt *C : S->children())
    if (usedBefore(C, V, CE, SM))
      return true;
  return false;
}

// Was V given a value before the wipe (an initialiser or any earlier use
// other than sizeof)? A memset before that initialises rather than wipes.
bool heldData(const Stmt *Body, const VarDecl *V, const CallExpr *CE,
              const SourceManager &SM) {
  if (V->hasInit() && !isa<InitListExpr>(V->getInit()->IgnoreImplicit()))
    return true;
  return usedBefore(Body, V, CE, SM);
}

// Can T hold secret bytes: an integer array, directly or in a struct/union
// field. Arrays of pointers and structs of pointers and scalars (list nodes,
// argv-style tables) are wiped for hygiene, not secrecy.
bool holdsBytes(QualType T, const ASTContext &Ctx, unsigned Depth = 0) {
  if (Depth > 4)
    return false;
  T = T.getCanonicalType();
  if (const auto *A = Ctx.getAsArrayType(T)) {
    QualType E = A->getElementType().getCanonicalType();
    return E->isIntegerType() || holdsBytes(E, Ctx, Depth + 1);
  }
  if (const auto *RT = T->getAs<RecordType>()) {
    const RecordDecl *RD = RT->getDecl()->getDefinition();
    if (!RD)
      return false;
    for (const FieldDecl *F : RD->fields())
      if (!F->getType()->isPointerType() && holdsBytes(F->getType(), Ctx, Depth + 1))
        return true;
  }
  return false;
}

// Is the memory a pointer points to a data buffer (void, char, integers) or
// an object holding bytes?
bool pointeeHoldsBytes(QualType P, const ASTContext &Ctx) {
  QualType T = P->getPointeeType().getCanonicalType();
  return T->isVoidType() || T->isIntegerType() || holdsBytes(T, Ctx);
}

bool isRelease(const Stmt *S, const Expr *Buf) {
  const auto *Call = dyn_cast_or_null<CallExpr>(raptor::strip(dyn_cast_or_null<Expr>(S)));
  if (!Call || Call->getNumArgs() < 1 || !raptor::calleeName(Call).ends_with_insensitive("free"))
    return false;
  // A release function of another shared library, declared in a system
  // header (talloc's _talloc_free, g_free): the compiler cannot see into it
  // and must assume it reads the bytes. libc's free() it knows; a project's
  // own (ell l_free) it may inline or see under LTO.
  if (const FunctionDecl *FD = Call->getDirectCallee(); FD && !FD->getBuiltinID()) {
    const SourceManager &SM = FD->getASTContext().getSourceManager();
    StringRef N = FD->getName();
    if (SM.isInSystemHeader(FD->getLocation()) &&
        !raptor::isOneOf(N, {"free", "cfree", "kfree", "kvfree", "kfree_sensitive", "kzfree"}) &&
        !FD->hasAttr<OwnershipAttr>())
      return false;
  }
  const Expr *Arg = Call->getArg(0);
  // the buffer itself, or memory inside the freed object (`&c->k`, `c->k`)
  for (const Expr *E = raptor::strip(Buf); E;) {
    if (sameExpr(E, Arg))
      return true;
    if (const auto *U = dyn_cast<UnaryOperator>(E); U && U->getOpcode() == UO_AddrOf)
      E = raptor::strip(U->getSubExpr());
    else if (const auto *M = dyn_cast<MemberExpr>(E); M && M->isArrow() &&
                                                      M->getType()->isArrayType())
      E = raptor::strip(M->getBase());
    else
      break;
  }
  return false;
}

// Is the wiped memory released by the next statement of the enclosing block
// that mentions it?
bool freedNext(const CallExpr *CE, const Expr *Buf, const ParentMap &PM) {
  const Stmt *Cur = CE;
  const Stmt *P = PM.getParent(Cur);
  while (P && !isa<CompoundStmt>(P)) {
    if (!isa<Expr>(P) && !isa<LabelStmt>(P))
      return false; // the wipe is a branch or loop body of its own
    Cur = P;
    P = PM.getParent(P);
  }
  const auto *Block = dyn_cast_or_null<CompoundStmt>(P);
  if (!Block)
    return false;
  bool After = false;
  for (const Stmt *S : Block->body()) {
    if (S == Cur) {
      After = true;
      continue;
    }
    if (!After)
      continue;
    if (const auto *L = dyn_cast<LabelStmt>(S))
      S = L->getSubStmt();
    if (isRelease(S, Buf))
      return true;
    if (containsExpr(S, raptor::strip(Buf)))
      return false;
    // the root pointer of `p->f` reassigned or used
    const Expr *Root = raptor::strip(Buf);
    while (const auto *M = dyn_cast<MemberExpr>(Root))
      Root = raptor::strip(M->getBase());
    if (Root != raptor::strip(Buf) && containsExpr(S, Root))
      return false;
  }
  return false;
}

class ElidableSecretWipeChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(D);
    const CFG *G = nullptr;
    std::unique_ptr<ParentMap> PM;
    forEach<CallExpr>(Body, [&](const CallExpr *CE) {
      const Expr *Buf = wipedBuffer(CE, Ctx);
      if (!Buf)
        return;
      bool Dead = false;
      if (const VarDecl *V = localObject(Buf)) {
        if (!G)
          G = Mgr.getCFG(D);
        Dead = G && holdsBytes(V->getType(), Ctx) &&
               heldData(Body, V, CE, Ctx.getSourceManager()) &&
               !readAfter(*G, CE, withAliases(Body, V));
      } else if (raptor::strip(Buf)->getType()->isPointerType() &&
                 pointeeHoldsBytes(raptor::strip(Buf)->getType(), Ctx)) {
        if (!PM)
          PM = std::make_unique<ParentMap>(const_cast<Stmt *>(Body));
        Dead = freedNext(CE, Buf, *PM);
      }
      if (!Dead)
        return;
      std::string What;
      llvm::raw_string_ostream OS(What);
      Buf->IgnoreImpCasts()->printPretty(OS, nullptr, PrintingPolicy(Ctx.getLangOpts()));
      OS.flush();
      raptor::reportAt(
          BR, this, "Wipe the compiler may remove",
          (raptor::calleeName(CE) + "() clears '" + What +
           "', which is never read again: the compiler may remove this dead store "
           "and leave the data in memory (CWE-14). Use explicit_bzero(), "
           "memset_explicit() or memset_s() to wipe secrets")
              .str(),
          CE, ADC);
    });
  }
};
} // namespace

RAPTOR_CHECKER(ElidableSecretWipeChecker, "ElidableSecretWipe",
               "memset()/bzero() wipe of a buffer that is never read again (dead store)")
