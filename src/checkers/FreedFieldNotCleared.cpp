// raptor.FreedFieldNotCleared: on an error path a function frees a field it
// filled in earlier and returns, leaving the dangling pointer in an object
// that outlives the call; whoever cleans the object up frees it again
// (CWE-415, CWE-416).
//
//   doodad = XkbAddGeomDoodad(geom, ...);           // owned by geom
//   _GetCountedString(&wire, client, &doodad->text.text);
//   if (_GetCountedString(&wire, client, &doodad->text.font) != Success) {
//     free(doodad->text.text);                       // no = NULL
//     return status;                                 // geom frees it again
//   }
//
// Error path: a branch of an if that ends with a return. The release (free,
// g_free, xfree, OPENSSL_free, `*_free(p)` with one argument; not
// `av_freep(&p)`, which clears) is a statement of that branch, on a field
// reached through a pointer (`x->f`, `x->a.b`).
// Filled in: earlier in the function the field is assigned or its address is
// passed to a call.
// Outlives the call: the pointer is a parameter, or a local set from a call
// that is not an allocator (it hands back an object something else owns).
// Not reported when, between the release and the return, the field is
// assigned, its address is passed on, or the object itself is passed to a
// call (`free(x)`, `destroy(x)`); nor when the field is in a union whose tag
// (another member of the union, or a field next to the union in the struct
// holding it) the function sets only after the release, so that a cleanup
// dispatching on the tag leaves the field alone (wolfSSL
// `attr->value->value.asn1_string` with `attr->value->type` set on success).
//
// CVE-2026-88812 (X.Org xserver _CheckSetDoodad), CVE-2026-55995 (open-isns
// isns_attr_type_string_decode / _opaque_decode).
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include <algorithm>
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

// The field path of E (`x->a.b`): the base pointer variable and the fields,
// when the first access from the variable is `->`.
struct FieldPath {
  const VarDecl *Base = nullptr;
  std::vector<const FieldDecl *> Fields;
  bool operator==(const FieldPath &O) const { return Base == O.Base && Fields == O.Fields; }
};
bool fieldPath(const Expr *E, FieldPath &P) {
  E = raptor::strip(E);
  std::vector<const FieldDecl *> Rev;
  bool Arrow = false;
  while (const auto *ME = dyn_cast<MemberExpr>(E)) {
    const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!FD)
      return false;
    Rev.push_back(FD);
    Arrow = ME->isArrow();
    E = raptor::strip(ME->getBase());
  }
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  if (!VD || Rev.empty() || !Arrow || !VD->getType()->isPointerType())
    return false;
  P.Base = VD;
  P.Fields.assign(Rev.rbegin(), Rev.rend());
  return true;
}

bool isRelease(const CallExpr *CE) {
  StringRef N = raptor::calleeName(CE);
  if (N.ends_with("freep") || CE->getNumArgs() == 0)
    return false;
  if (raptor::isOneOf(N, {"free", "g_free", "xfree", "cfree", "CRYPTO_free", "OPENSSL_free"}))
    return true;
  return N.ends_with("_free") && CE->getNumArgs() == 1;
}

bool isAllocator(StringRef N) {
  std::string L = N.lower();
  StringRef S(L);
  return S.contains("alloc") || S.contains("dup") || S.starts_with("new") || S.ends_with("_new") ||
         S.contains("create");
}

class FreedFieldNotClearedChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    const SourceManager &SM = BR.getSourceManager();

    // Writes to field paths, with their location: assignments and addresses
    // passed to calls.
    struct Write {
      FieldPath P;
      SourceLocation Loc;
      bool Assign; // an assignment, not an address passed to a call
    };
    std::vector<Write> Writes;
    // Locals set from a call that is not an allocator, or from an allocator.
    llvm::SmallPtrSet<const VarDecl *, 8> FromCall, FromAlloc;
    auto noteDef = [&](const VarDecl *V, const Expr *Init) {
      if (!V || !Init)
        return;
      if (const auto *CE = dyn_cast<CallExpr>(raptor::strip(Init)))
        (isAllocator(raptor::calleeName(CE)) ? FromAlloc : FromCall).insert(V);
      else
        FromAlloc.insert(V); // set otherwise: not known to be shared
    };
    walk(Body, [&](const Stmt *S) {
      if (const auto *BO = dyn_cast<BinaryOperator>(S); BO && BO->isAssignmentOp()) {
        FieldPath P;
        if (fieldPath(BO->getLHS(), P))
          Writes.push_back({P, BO->getBeginLoc(), true});
        if (const auto *DRE = dyn_cast<DeclRefExpr>(raptor::strip(BO->getLHS())))
          noteDef(dyn_cast<VarDecl>(DRE->getDecl()), BO->getRHS());
      } else if (const auto *CE = dyn_cast<CallExpr>(S)) {
        for (const Expr *A : CE->arguments())
          if (const auto *UO = dyn_cast<UnaryOperator>(raptor::strip(A)); UO && UO->getOpcode() == UO_AddrOf) {
            FieldPath P;
            if (fieldPath(UO->getSubExpr(), P))
              Writes.push_back({P, CE->getBeginLoc(), false});
          }
      } else if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *X : DS->decls())
          if (const auto *V = dyn_cast<VarDecl>(X); V && V->hasInit())
            noteDef(V, V->getInit());
      }
    });

    auto outlives = [&](const VarDecl *V) {
      if (isa<ParmVarDecl>(V))
        return true;
      return FromCall.count(V) && !FromAlloc.count(V);
    };

    // The field lives in a union (`d->text.text` with `d` a union, or
    // `a->value->value.ptr` with `value` a union inside a struct): a cleanup
    // frees it only according to a tag. The tag candidates are the union's
    // other members, or the fields next to the union in the struct that holds
    // it. When the function sets such a tag only after the release, the tag
    // still says the field is not in use, and the cleanup leaves it alone.
    auto tagSetOnlyAfter = [&](const FieldPath &P, SourceLocation Free) {
      size_t U = P.Fields.size();
      for (size_t I = 0; I < P.Fields.size(); ++I)
        if (P.Fields[I]->getParent()->isUnion()) {
          U = I;
          break;
        }
      if (U == P.Fields.size())
        return false;
      size_t J = U == 0 ? 0 : U - 1; // the level where the tag sits
      bool Before = false, After = false;
      for (const Write &W : Writes) {
        if (!W.Assign || W.P.Base != P.Base || W.P.Fields.size() <= J ||
            !std::equal(P.Fields.begin(), P.Fields.begin() + J, W.P.Fields.begin()) ||
            W.P.Fields[J] == P.Fields[J])
          continue;
        (SM.isBeforeInTranslationUnit(W.Loc, Free) ? Before : After) = true;
      }
      return After && !Before;
    };

    auto branch = [&](const Stmt *Br) {
      const auto *CS = dyn_cast_or_null<CompoundStmt>(Br);
      if (!CS || CS->body_empty() || !isa<ReturnStmt>(CS->body_back()))
        return;
      std::vector<const Stmt *> Stmts(CS->body_begin(), CS->body_end());
      for (size_t I = 0; I + 1 < Stmts.size(); ++I) {
        const auto *CE = dyn_cast<CallExpr>(Stmts[I]);
        FieldPath P;
        if (!CE || !isRelease(CE) || !fieldPath(CE->getArg(0), P) || !outlives(P.Base))
          continue;
        // filled in earlier in the function
        bool Filled = false;
        for (const Write &W : Writes)
          Filled |= W.P == P && SM.isBeforeInTranslationUnit(W.Loc, CE->getBeginLoc());
        if (!Filled)
          continue;
        if (tagSetOnlyAfter(P, CE->getBeginLoc()))
          continue;
        // cleared, handed on, or the object released, before the return
        bool Handled = false;
        for (size_t J = I + 1; J < Stmts.size() && !Handled; ++J) {
          walk(Stmts[J], [&](const Stmt *S) {
            if (const auto *BO = dyn_cast<BinaryOperator>(S); BO && BO->isAssignmentOp()) {
              FieldPath Q;
              Handled |= fieldPath(BO->getLHS(), Q) && Q == P;
            } else if (const auto *C2 = dyn_cast<CallExpr>(S)) {
              for (const Expr *A : C2->arguments()) {
                const Expr *SA = raptor::strip(A);
                if (const auto *DRE = dyn_cast<DeclRefExpr>(SA))
                  Handled |= DRE->getDecl() == P.Base;
                if (const auto *UO = dyn_cast<UnaryOperator>(SA); UO && UO->getOpcode() == UO_AddrOf) {
                  FieldPath Q;
                  Handled |= fieldPath(UO->getSubExpr(), Q) && Q == P;
                }
              }
            }
          });
        }
        if (Handled)
          continue;
        std::string Name;
        for (const FieldDecl *F : P.Fields)
          Name += (Name.empty() ? "" : ".") + F->getNameAsString();
        raptor::reportAt(BR, this, "Freed field not cleared",
                         "'" + P.Base->getNameAsString() + "->" + Name +
                             "' is freed on this error path but left in the object, which "
                             "outlives the call: whoever cleans it up frees it again "
                             "(CWE-415, CWE-416)",
                         CE, Mgr.getAnalysisDeclContext(D));
      }
    };
    walk(Body, [&](const Stmt *S) {
      if (const auto *If = dyn_cast<IfStmt>(S)) {
        branch(If->getThen());
        branch(If->getElse());
      }
    });
  }
};
} // namespace

RAPTOR_CHECKER(FreedFieldNotClearedChecker, "FreedFieldNotCleared",
               "Field freed on an error path and left dangling in a live object")
