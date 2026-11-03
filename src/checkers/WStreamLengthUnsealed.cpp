// raptor.WStreamLengthUnsealed: Stream_Length() of a WinPR wStream that is
// filled by position and never sealed (FreeRDP; CWE-130, CWE-201).
//
// A wStream has a position (where the next write goes) and a length. Writing
// (Stream_Write_*, Stream_Seek, Stream_SafeSeek, Stream_SetPosition,
// Stream_Zero, Stream_Fill, the destination of Stream_Copy) only moves the
// position; the length stays what Stream_New() set, the capacity, until
// Stream_SealLength() or Stream_SetLength(). Sending Stream_Length() bytes of
// such a stream sends stale memory after the data.
//
// Within a translation unit, streams are followed by identity: a struct field
// (ctx->responseStreamBuffer), a variable, and for a parameter every argument
// passed to it. Stream_Length(s) is reported when some identity of s is
// written by position and no identity of s is ever sealed.
//
// This is CVE-2026-67292 (FreeRDP < 3.29.0, libfreerdp/core/gateway/websocket.c):
// the Pong reply took Stream_Length() of the 1024-byte responseStreamBuffer
// filled with Stream_SafeSeek(); the fix calls Stream_SealLength() first.
#include "Common.h"
#include "Registry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;

namespace {
using IdSet = llvm::SmallPtrSet<const Decl *, 8>;

struct Call {
  const CallExpr *CE;
  const FunctionDecl *In;
};

class Collector : public RecursiveASTVisitor<Collector> {
public:
  std::vector<Call> Calls;
  llvm::DenseMap<const VarDecl *, std::vector<const Expr *>> Assigned;
  const FunctionDecl *Cur = nullptr;

  bool TraverseFunctionDecl(FunctionDecl *FD) {
    const FunctionDecl *Saved = Cur;
    if (FD->doesThisDeclarationHaveABody())
      Cur = FD;
    bool R = RecursiveASTVisitor::TraverseFunctionDecl(FD);
    Cur = Saved;
    return R;
  }
  bool VisitCallExpr(CallExpr *CE) {
    if (Cur)
      Calls.push_back({CE, Cur});
    return true;
  }
  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_Assign)
      if (const auto *DRE = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts()))
        if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
          Assigned[VD].push_back(BO->getRHS());
    return true;
  }
};

class Identities {
  const Collector &C;
  llvm::DenseMap<const ParmVarDecl *, IdSet> ParamIds;

public:
  explicit Identities(const Collector &Col) : C(Col) {
    // Parameters stand for every argument passed to them (fixpoint).
    for (int Pass = 0; Pass < 8; ++Pass) {
      bool Changed = false;
      for (const Call &K : C.Calls) {
        const FunctionDecl *FD = K.CE->getDirectCallee();
        const FunctionDecl *Def = nullptr;
        if (!FD || !FD->hasBody(Def) || !Def)
          continue;
        for (unsigned I = 0; I < K.CE->getNumArgs() && I < Def->getNumParams(); ++I) {
          const ParmVarDecl *P = Def->getParamDecl(I);
          if (!P->getType()->isPointerType())
            continue;
          IdSet S;
          of(K.CE->getArg(I), S, 0);
          IdSet &T = ParamIds[P];
          for (const Decl *D : S)
            Changed |= T.insert(D).second;
        }
      }
      if (!Changed)
        break;
    }
  }

  void of(const Expr *E, IdSet &Out, int Depth) const {
    if (!E || Depth > 6)
      return;
    E = E->IgnoreParenCasts();
    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      Out.insert(ME->getMemberDecl());
      return;
    }
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_AddrOf)
        of(UO->getSubExpr(), Out, Depth + 1);
      return;
    }
    const auto *DRE = dyn_cast<DeclRefExpr>(E);
    const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
    if (!VD)
      return;
    if (!Out.insert(VD).second)
      return;
    if (const auto *P = dyn_cast<ParmVarDecl>(VD)) {
      auto It = ParamIds.find(P);
      if (It != ParamIds.end())
        for (const Decl *D : It->second)
          Out.insert(D);
      return;
    }
    if (VD->getInit())
      of(VD->getInit(), Out, Depth + 1);
    auto It = C.Assigned.find(VD);
    if (It != C.Assigned.end())
      for (const Expr *R : It->second)
        of(R, Out, Depth + 1);
  }
};

bool isPositionWrite(StringRef N, unsigned &Arg) {
  Arg = 0;
  if (N == "Stream_Copy") {
    Arg = 1;
    return true;
  }
  return N.starts_with("Stream_Write") || N.starts_with("Stream_Seek") ||
         N.starts_with("Stream_SafeSeek") || N == "Stream_SetPosition" ||
         N.starts_with("Stream_Zero") || N.starts_with("Stream_Fill");
}

class WStreamLengthUnsealedChecker : public Checker<check::EndOfTranslationUnit> {
public:
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                                 BugReporter &BR) const {
    Collector Col;
    Col.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));
    Identities Ids(Col);
    IdSet Positioned, Sealed;
    for (const Call &K : Col.Calls) {
      StringRef N = raptor::calleeName(K.CE);
      unsigned Arg;
      if (isPositionWrite(N, Arg) && K.CE->getNumArgs() > Arg)
        Ids.of(K.CE->getArg(Arg), Positioned, 0);
      else if ((N == "Stream_SealLength" || N == "Stream_SetLength") && K.CE->getNumArgs() > 0)
        Ids.of(K.CE->getArg(0), Sealed, 0);
    }
    const SourceManager &SM = Mgr.getASTContext().getSourceManager();
    for (const Call &K : Col.Calls) {
      if (raptor::calleeName(K.CE) != "Stream_Length" || K.CE->getNumArgs() != 1)
        continue;
      // Report in the main file only (not inside the WinPR headers).
      if (!SM.isInMainFile(SM.getExpansionLoc(K.CE->getBeginLoc())))
        continue;
      IdSet S;
      Ids.of(K.CE->getArg(0), S, 0);
      bool Written = false, IsSealed = false;
      for (const Decl *D : S) {
        Written |= Positioned.count(D) > 0;
        IsSealed |= Sealed.count(D) > 0;
      }
      if (!Written || IsSealed)
        continue;
      raptor::reportAt(BR, this, "Unsealed wStream length",
                       "Stream_Length() of a stream filled by position and never "
                       "sealed (Stream_SealLength) is its capacity, not the data "
                       "written: using it as a size sends or copies stale memory "
                       "(CWE-130, CWE-201)",
                       K.CE, Mgr.getAnalysisDeclContext(K.In));
    }
  }
};
} // namespace

RAPTOR_CHECKER(WStreamLengthUnsealedChecker, "WStreamLengthUnsealed",
               "Stream_Length() of a wStream written by position and never sealed")
