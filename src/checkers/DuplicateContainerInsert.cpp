// raptor.DuplicateContainerInsert: an existing object is added to a
// long-lived container (a struct field or a variable) from several places in
// the file, and an add site does not check that the object is not already in
// it. A state test (`if (stream_is_running(s))`, `if (chan->state == X)`) is
// not a membership test: when two event paths both decide to add the object,
// it is in the container twice, and whoever drains the container releases it
// twice (CWE-415) or keeps using it after the first release (CWE-416).
//
//   static void c1c2_stream_joined(h2_mplx *m, h2_stream *stream) {
//     ...
//     APR_ARRAY_PUSH(m->spurge, h2_stream *) = stream;   // and again in
//   }                                                     // m_stream_cleanup
//   static void c1_purge_streams(h2_mplx *m) {
//     for (i = 0; i < m->spurge->nelts; ++i)
//       h2_stream_destroy(APR_ARRAY_IDX(m->spurge, i, h2_stream *));
//   }
//
// Add site: a call whose name has a push/add/append/insert/enqueue/prepend
// component (`smartlist_pqueue_add(c, ..., x)`, `g_ptr_array_add(c, x)`),
// with the container as first argument and the object as the last argument,
// passed to a `void *` parameter (a generic container of pointers; typed APIs
// such as `dav_push_error(pool, ..., err)` and a context in the middle, as in
// `ap_add_output_filter_handle(h, ctx, r, c)`, are not; nor is the argument
// that follows a callback, `isc_work_enqueue(loop, lane, cb, done, arg)`), or an
// assignment through the slot such a call returns (`*(T *)apr_array_push(c) =
// x`). Keyed containers (hash, map, dict, table, tree, trie, cache) are left
// out: adding a key again replaces the entry. A call to a function defined in
// the file is not an add site: the add inside it is checked where it is.
// Object: a variable holding a pointer to a struct, not one set in the
// function from an allocator (`*_new`, malloc...): a fresh object cannot be
// in the container yet.
// Reported when the container has at least two such add sites in the file
// and this one has no membership guard before it in its function:
//   - a condition that mentions both the object and the container, or a local
//     read from the container (`if (s == stream)` with `s =
//     APR_ARRAY_IDX(m->spurge, i, ...)`, `if (!smartlist_contains(cp, x))`);
//   - a condition on the object's position field: the field the add itself
//     maintains (`offsetof(channel_t, sched_heap_idx)`), or one named like a
//     position or a membership flag (`*idx`, `*index`, `queued`, `in_*`);
//   - the object removed or popped from the same container earlier in the
//     function (`smartlist_pqueue_remove(c, ..., x)`, `x = pop(c)`).
//
// CVE-2026-23918 (Apache httpd mod_http2 m->spurge, double free on early
// reset), CVE-2018-0491 (Tor KIST channels_pending, use after free).
#include "Common.h"
#include "Registry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Support/Regex.h"
#include <string>
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

bool nameMatches(StringRef Name, const char *Pattern) {
  llvm::Regex R(Pattern, llvm::Regex::IgnoreCase);
  return R.match(Name);
}

bool isAddName(StringRef N) {
  return nameMatches(N, "(^|_)(push|add|append|insert|enqueue|prepend)(_|$)") &&
         !nameMatches(N, "hash|map|dict|table|tree|trie|cache");
}
bool isRemoveName(StringRef N) {
  return nameMatches(N, "(^|_)(remove|del|delete|pop|take|unlink|erase|detach|steal|shift)(_|$)");
}
bool isFreshName(StringRef N) {
  return nameMatches(N, "alloc|(^|_)(new|create|make|dup|clone|copy)(_|$)|_new$|^new");
}
bool isMembershipField(StringRef N) {
  return nameMatches(N, "idx|index|queued|listed|linked|^(is_)?(in|on)_");
}

// The decl naming the container in E: `m->spurge` -> spurge, `&list` /
// `list` -> list.
const ValueDecl *containerOf(const Expr *E) {
  E = raptor::strip(E);
  if (const auto *U = dyn_cast<UnaryOperator>(E))
    if (U->getOpcode() == UO_AddrOf)
      E = raptor::strip(U->getSubExpr());
  if (const auto *ME = dyn_cast<MemberExpr>(E))
    return dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return dyn_cast<VarDecl>(DRE->getDecl());
  return nullptr;
}

// E as a variable holding a pointer to a struct.
const VarDecl *objectOf(const Expr *E) {
  const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(E));
  if (!DRE)
    return nullptr;
  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return nullptr;
  QualType T = VD->getType().getCanonicalType();
  if (!T->isPointerType() || !T->getPointeeType()->isRecordType())
    return nullptr;
  return VD;
}

bool refersTo(const Stmt *S, const ValueDecl *D) {
  bool Found = false;
  walk(S, [&](const Stmt *N) {
    if (const auto *ME = dyn_cast<MemberExpr>(N))
      Found |= ME->getMemberDecl() == D;
    else if (const auto *DRE = dyn_cast<DeclRefExpr>(N))
      Found |= DRE->getDecl() == D;
  });
  return Found;
}

bool refersToAny(const Stmt *S, const llvm::SmallPtrSetImpl<const ValueDecl *> &Ds) {
  for (const ValueDecl *D : Ds)
    if (refersTo(S, D))
      return true;
  return false;
}

struct Site {
  const Stmt *At;               // the add call, or the assignment through its slot
  const CallExpr *Call;         // the add call
  const ValueDecl *Container;
  const VarDecl *Object;
  const FunctionDecl *In;
};

// The add site rooted at S, if any.
bool addSite(const Stmt *S, Site &Out) {
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() != BO_Assign)
      return false;
    const auto *U = dyn_cast<UnaryOperator>(raptor::strip(BO->getLHS()));
    if (!U || U->getOpcode() != UO_Deref)
      return false;
    const auto *CE = dyn_cast<CallExpr>(raptor::strip(U->getSubExpr()));
    if (!CE || CE->getNumArgs() < 1 || !isAddName(raptor::calleeName(CE)))
      return false;
    const ValueDecl *C = containerOf(CE->getArg(0));
    const VarDecl *X = objectOf(BO->getRHS());
    if (!C || !X)
      return false;
    Out = {BO, CE, C, X, nullptr};
    return true;
  }
  const auto *CE = dyn_cast<CallExpr>(S);
  if (!CE || CE->getNumArgs() < 2 || !isAddName(raptor::calleeName(CE)))
    return false;
  // A helper defined in this file (`add_for_purge(m, stream)`) is not an add
  // site: the add inside it is checked where it is.
  if (const FunctionDecl *F = CE->getDirectCallee())
    if (F->hasBody())
      return false;
  const ValueDecl *C = containerOf(CE->getArg(0));
  if (!C)
    return false;
  // The object goes into a generic slot: a `void *` parameter
  // (`smartlist_add(sl, void *item)`, `g_ptr_array_add(a, gpointer)`). A
  // typed parameter (`dav_push_error(pool, ..., dav_error *prev)`,
  // `apr_pollset_add(set, const apr_pollfd_t *)`) is an API of its own, not a
  // container of pointers.
  // The item is the last argument, as in every generic container API
  // (`smartlist_pqueue_add(sl, cmp, idx_off, item)`); a `void *` context in
  // the middle (`ap_add_output_filter_handle(h, ctx, r, c)`) is not stored.
  const FunctionDecl *Callee = CE->getDirectCallee();
  unsigned I = CE->getNumArgs() - 1;
  if (Callee && I < Callee->getNumParams()) {
    QualType PT = Callee->getParamDecl(I)->getType().getCanonicalType();
    if (!PT->isPointerType() || !PT->getPointeeType()->isVoidType())
      return false;
  }
  // (callback, argument): a `void *` right after a function pointer is the
  // callback's argument (`isc_work_enqueue(loop, lane, cb, done_cb, arg)`).
  if (I > 0) {
    QualType PT = raptor::strip(CE->getArg(I - 1))->getType().getCanonicalType();
    if (PT->isFunctionPointerType() || PT->isFunctionType())
      return false;
  }
  const VarDecl *X = objectOf(CE->getArg(I));
  if (!X || X == C)
    return false;
  Out = {CE, CE, C, X, nullptr};
  return true;
}

// Fields named in offsetof() arguments of the add call: the position field
// the container keeps in the object.
void offsetofFields(const CallExpr *CE, llvm::SmallPtrSetImpl<const ValueDecl *> &Out) {
  for (const Expr *A : CE->arguments())
    walk(A, [&](const Stmt *N) {
      if (const auto *OE = dyn_cast<OffsetOfExpr>(N))
        for (unsigned I = 0; I < OE->getNumComponents(); ++I)
          if (OE->getComponent(I).getKind() == OffsetOfNode::Field)
            Out.insert(OE->getComponent(I).getField());
    });
}

class Analysis {
public:
  Analysis(const FunctionDecl *FD, const SourceManager &SM) : FD(FD), SM(SM) {
    walk(FD->getBody(), [&](const Stmt *N) {
      if (const auto *If = dyn_cast<IfStmt>(N))
        Conds.push_back(If->getCond());
      else if (const auto *W = dyn_cast<WhileStmt>(N))
        Conds.push_back(W->getCond());
      else if (const auto *D = dyn_cast<DoStmt>(N))
        Conds.push_back(D->getCond());
      else if (const auto *F = dyn_cast<ForStmt>(N))
        Conds.push_back(F->getCond());
      else if (const auto *CO = dyn_cast<ConditionalOperator>(N))
        Conds.push_back(CO->getCond());
      else if (const auto *BO = dyn_cast<BinaryOperator>(N)) {
        if (BO->isLogicalOp())
          Conds.push_back(BO->getLHS());
      }
    });
  }

  bool before(const Stmt *A, const Stmt *B) const {
    return SM.isBeforeInTranslationUnit(A->getBeginLoc(), B->getBeginLoc());
  }

  // Locals set (initialised or assigned) from an expression that mentions
  // one of Ds.
  void readFrom(llvm::SmallPtrSetImpl<const ValueDecl *> &Ds) const {
    walk(FD->getBody(), [&](const Stmt *N) {
      if (const auto *DS = dyn_cast<DeclStmt>(N)) {
        for (const Decl *D : DS->decls())
          if (const auto *VD = dyn_cast<VarDecl>(D))
            if (VD->getInit() && refersToAny(VD->getInit(), Ds))
              Ds.insert(VD);
      } else if (const auto *BO = dyn_cast<BinaryOperator>(N)) {
        if (BO->getOpcode() == BO_Assign)
          if (const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(BO->getLHS())))
            if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
              if (VD->hasLocalStorage() && refersToAny(BO->getRHS(), Ds))
                Ds.insert(VD);
      }
    });
  }

  // The object is set in this function, before S, from an allocator, or
  // from a removal out of container C.
  bool freshOrTaken(const Site &S) const {
    bool Yes = false;
    auto Check = [&](const Expr *RHS, const Stmt *At) {
      if (!RHS || !before(At, S.At))
        return;
      const auto *CE = dyn_cast<CallExpr>(raptor::strip(RHS));
      if (!CE)
        return;
      StringRef N = raptor::calleeName(CE);
      if (isFreshName(N) || (isRemoveName(N) && refersTo(CE, S.Container)))
        Yes = true;
    };
    if (S.Object->getInit() && S.Object->getDeclContext() == FD)
      Check(S.Object->getInit(), S.Object->getInit());
    walk(FD->getBody(), [&](const Stmt *N) {
      if (const auto *BO = dyn_cast<BinaryOperator>(N))
        if (BO->getOpcode() == BO_Assign)
          if (const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(BO->getLHS())))
            if (DRE->getDecl() == S.Object)
              Check(BO->getRHS(), BO);
    });
    return Yes;
  }

  bool guarded(const Site &S) const {
    // Removed from the same container first.
    bool Removed = false;
    walk(FD->getBody(), [&](const Stmt *N) {
      if (const auto *CE = dyn_cast<CallExpr>(N))
        if (CE != S.Call && before(CE, S.At) && isRemoveName(raptor::calleeName(CE)) &&
            CE->getNumArgs() >= 2 && containerOf(CE->getArg(0)) == S.Container &&
            refersTo(CE, S.Object))
          Removed = true;
    });
    if (Removed)
      return true;

    llvm::SmallPtrSet<const ValueDecl *, 8> FromC;
    FromC.insert(S.Container);
    readFrom(FromC);
    FromC.erase(S.Object);
    llvm::SmallPtrSet<const ValueDecl *, 4> PosFields;
    offsetofFields(S.Call, PosFields);

    for (const Expr *C : Conds) {
      if (!C || !before(C, S.At))
        continue;
      if (refersTo(C, S.Object) && refersToAny(C, FromC))
        return true;
      bool Pos = false;
      walk(C, [&](const Stmt *N) {
        const auto *ME = dyn_cast<MemberExpr>(N);
        if (!ME)
          return;
        const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(ME->getBase()));
        if (!DRE || DRE->getDecl() != S.Object)
          return;
        const ValueDecl *F = ME->getMemberDecl();
        if (PosFields.count(F) || isMembershipField(F->getName()))
          Pos = true;
      });
      if (Pos)
        return true;
    }
    return false;
  }

  const FunctionDecl *FD;
  const SourceManager &SM;
  std::vector<const Expr *> Conds;
};

struct FunctionCollector : RecursiveASTVisitor<FunctionCollector> {
  std::vector<const FunctionDecl *> Defs;
  bool VisitFunctionDecl(FunctionDecl *FD) {
    if (FD->doesThisDeclarationHaveABody())
      Defs.push_back(FD);
    return true;
  }
};

std::string containerName(const ValueDecl *D) { return D->getNameAsString(); }

class DuplicateContainerInsertChecker : public Checker<check::EndOfTranslationUnit> {
public:
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                                 BugReporter &BR) const {
    const SourceManager &SM = Mgr.getASTContext().getSourceManager();
    FunctionCollector Col;
    Col.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));

    struct Found {
      Site S;
      bool Guarded;
    };
    llvm::DenseMap<const ValueDecl *, std::vector<Found>> ByContainer;
    for (const FunctionDecl *FD : Col.Defs) {
      Analysis A(FD, SM);
      walk(FD->getBody(), [&](const Stmt *N) {
        Site S;
        if (!addSite(N, S))
          return;
        S.In = FD;
        if (A.freshOrTaken(S))
          return;
        ByContainer[S.Container].push_back({S, A.guarded(S)});
      });
    }

    for (auto &[C, List] : ByContainer) {
      if (List.size() < 2)
        continue;
      for (const Found &F : List) {
        if (F.Guarded)
          continue;
        std::string Msg = "'" + F.S.Object->getNameAsString() + "' is added to '" +
                          containerName(C) +
                          "' without checking that it is not already there; '" +
                          containerName(C) + "' is filled in " + std::to_string(List.size()) +
                          " places in this file, so the object can end up in it twice and be "
                          "released twice";
        raptor::reportAt(BR, this, "Duplicate container insert", Msg, F.S.At,
                         Mgr.getAnalysisDeclContext(F.S.In));
      }
    }
  }
};
} // namespace

RAPTOR_CHECKER(DuplicateContainerInsertChecker, "DuplicateContainerInsert",
               "An existing object is added to a container from several places without "
               "a check that it is not already there (double free / use after free)")
