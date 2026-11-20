// raptor.WideCountInBytes: a function that takes the size of a wide-character
// buffer as a number of characters is given a number of bytes, so it may
// write two (WCHAR, char16_t) or four (Linux wchar_t) times past the end of
// the buffer (CWE-135, CWE-787). The count is a byte count when it is
//
//  - sizeof of an array whose elements are wider than a byte, possibly minus
//    or plus a constant (`sizeof(szTitle)`, `sizeof(buf) - 1`);
//  - a product with sizeof of the element type (`(len + 1) * sizeof(WCHAR)`);
//  - a local variable assigned such a product (`buflen = max(len *
//    sizeof(WCHAR), 64)`), unless divided again before the call.
//
// Only calls whose destination element is wider than a byte are checked, so
// TCHAR code built narrow, WideCharToMultiByte's output and the A functions
// are not reported. Functions and argument positions (count, buffer):
// MultiByteToWideChar, the C library's mbstowcs family, wcsncpy, wcslcpy,
// wmemcpy/wmemmove/wmemset, swprintf family, wcsftime, fgetws, and the Win32
// W functions that fill a caller's buffer (GetModuleFileNameW,
// GetWindowTextW, LoadStringW, GetCurrentDirectoryW, StringCch*W...).
// Modelled on Wine bd7ec9a (comctl32: MultiByteToWideChar given
// sizeof(szTitle), (len+1)*sizeof(WCHAR) and a byte-sized buflen), CPython
// bpo-32869 and BambuStudio (GetModuleFileNameW(nullptr, app_path,
// sizeof(app_path))).
#include "BufHelpers.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/StringMap.h"

using namespace clang;
using namespace ento;
using namespace raptor::buf;

namespace {

struct Slots {
  unsigned Count, Buf;
};

const llvm::StringMap<Slots> &table() {
  static const llvm::StringMap<Slots> T = {
      {"MultiByteToWideChar", {5, 4}},
      {"mbstowcs", {2, 0}},
      {"mbsrtowcs", {2, 0}},
      {"mbsnrtowcs", {3, 0}},
      {"mbstowcs_s", {2, 1}},
      {"wcsncpy", {2, 0}},
      {"wcslcpy", {2, 0}},
      {"wcslcat", {2, 0}},
      {"wmemcpy", {2, 0}},
      {"wmemmove", {2, 0}},
      {"wmemset", {2, 0}},
      {"swprintf", {1, 0}},
      {"vswprintf", {1, 0}},
      {"_snwprintf", {1, 0}},
      {"_vsnwprintf", {1, 0}},
      {"wcsftime", {1, 0}},
      {"fgetws", {1, 0}},
      {"lstrcpynW", {2, 0}},
      {"GetModuleFileNameW", {2, 1}},
      {"GetModuleFileNameExW", {3, 2}},
      {"GetModuleBaseNameW", {3, 2}},
      {"GetWindowTextW", {2, 1}},
      {"GetClassNameW", {2, 1}},
      {"GetDlgItemTextW", {3, 2}},
      {"GetCurrentDirectoryW", {0, 1}},
      {"GetTempPathW", {0, 1}},
      {"GetSystemDirectoryW", {1, 0}},
      {"GetWindowsDirectoryW", {1, 0}},
      {"GetEnvironmentVariableW", {2, 1}},
      {"ExpandEnvironmentStringsW", {2, 1}},
      {"GetFullPathNameW", {1, 2}},
      {"GetLongPathNameW", {2, 1}},
      {"GetShortPathNameW", {2, 1}},
      {"LoadStringW", {3, 2}},
      {"GetPrivateProfileStringW", {4, 3}},
      {"GetLocaleInfoW", {3, 2}},
      {"GetLocaleInfoEx", {3, 2}},
      {"StringCchCopyW", {1, 0}},
      {"StringCchCopyNW", {1, 0}},
      {"StringCchCatW", {1, 0}},
      {"StringCchPrintfW", {1, 0}},
      {"StringCchVPrintfW", {1, 0}},
      {"wcscpy_s", {1, 0}},
      {"wcsncpy_s", {1, 0}},
      {"wcscat_s", {1, 0}},
      {"swprintf_s", {1, 0}},
      {"_snwprintf_s", {1, 0}},
  };
  return T;
}

// Element type of the buffer argument (pointer or array), if wider than a byte.
std::optional<CharUnits> wideElement(const Expr *Buf, const ASTContext &Ctx) {
  QualType T = Buf->IgnoreParenImpCasts()->getType();
  QualType E;
  if (const auto *A = Ctx.getAsArrayType(T))
    E = A->getElementType();
  else if (T->isPointerType())
    E = T->getPointeeType();
  else
    return std::nullopt;
  if (E->isIncompleteType() || E->isVoidType() || !E->isIntegerType())
    return std::nullopt;
  CharUnits S = Ctx.getTypeSizeInChars(E);
  return S.getQuantity() > 1 ? std::optional<CharUnits>(S) : std::nullopt;
}

// sizeof applied to an array of wide elements (or to such an array type).
bool isSizeofWideArray(const Expr *E, const ASTContext &Ctx) {
  const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(raptor::strip(E));
  if (!U || U->getKind() != UETT_SizeOf)
    return false;
  QualType T = U->getTypeOfArgument();
  const auto *A = Ctx.getAsArrayType(T);
  return A && Ctx.getTypeSizeInChars(A->getElementType()).getQuantity() > 1;
}

// sizeof of a type (or expression) that is exactly Elem bytes and wider than one.
bool isSizeofElem(const Expr *E, CharUnits Elem, const ASTContext &Ctx) {
  const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(raptor::strip(E));
  if (!U || U->getKind() != UETT_SizeOf)
    return false;
  QualType T = U->getTypeOfArgument();
  return !T->isArrayType() && !T->isIncompleteType() && Ctx.getTypeSizeInChars(T) == Elem;
}

// N * sizeof(elem) anywhere in E, not under a division.
bool hasBytesProduct(const Stmt *S, CharUnits Elem, const ASTContext &Ctx) {
  const auto *E = dyn_cast_or_null<Expr>(S);
  if (!E)
    return false;
  E = raptor::strip(E);
  if (const auto *B = dyn_cast<BinaryOperator>(E)) {
    if (B->getOpcode() == BO_Div || B->getOpcode() == BO_Shr)
      return false;
    if (B->getOpcode() == BO_Mul &&
        (isSizeofElem(B->getLHS(), Elem, Ctx) || isSizeofElem(B->getRHS(), Elem, Ctx)))
      return true;
  }
  for (const Stmt *C : E->children())
    if (hasBytesProduct(C, Elem, Ctx))
      return true;
  return false;
}

// The count is sizeof(wide array) [+/- constant] or a product with sizeof(elem).
bool isByteCountExpr(const Expr *C, CharUnits Elem, const ASTContext &Ctx) {
  C = raptor::strip(C);
  if (isSizeofWideArray(C, Ctx))
    return true;
  if (const auto *B = dyn_cast<BinaryOperator>(C)) {
    if (B->isAdditiveOp())
      return (isSizeofWideArray(B->getLHS(), Ctx) && intValue(B->getRHS(), Ctx)) ||
             (B->getOpcode() == BO_Add && isSizeofWideArray(B->getRHS(), Ctx) &&
              intValue(B->getLHS(), Ctx));
    if (B->getOpcode() == BO_Mul)
      return isSizeofElem(B->getLHS(), Elem, Ctx) || isSizeofElem(B->getRHS(), Elem, Ctx);
  }
  return false;
}

// A local variable whose every assignment in Body computes bytes for Elem.
bool isByteCountVar(const Expr *C, CharUnits Elem, const Stmt *Body, const ASTContext &Ctx) {
  const auto *DR = dyn_cast<DeclRefExpr>(raptor::strip(C));
  const auto *V = DR ? dyn_cast<VarDecl>(DR->getDecl()) : nullptr;
  if (!V || !V->hasLocalStorage() || isa<ParmVarDecl>(V))
    return false;
  bool Any = false, Other = false;
  auto Value = [&](const Expr *RHS) {
    if (hasBytesProduct(RHS, Elem, Ctx))
      Any = true;
    else
      Other = true;
  };
  if (const Expr *Init = V->getInit())
    Value(Init);
  forEach<BinaryOperator>(Body, [&](const BinaryOperator *B) {
    const auto *L = dyn_cast<DeclRefExpr>(raptor::strip(B->getLHS()));
    if (!L || L->getDecl() != V)
      return;
    if (B->getOpcode() == BO_Assign)
      Value(B->getRHS());
    else if (B->isCompoundAssignmentOp())
      Other = true;
  });
  return Any && !Other;
}

class WideCountInBytesChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const Stmt *Body = D->getBody();
    if (!Body)
      return;
    const ASTContext &Ctx = Mgr.getASTContext();
    forEach<CallExpr>(Body, [&](const CallExpr *CE) {
      auto It = table().find(raptor::calleeName(CE));
      if (It == table().end())
        return;
      Slots S = It->second;
      if (CE->getNumArgs() <= std::max(S.Count, S.Buf))
        return;
      const Expr *Buf = CE->getArg(S.Buf), *Count = CE->getArg(S.Count);
      auto Elem = wideElement(Buf, Ctx);
      if (!Elem)
        return;
      if (!isByteCountExpr(Count, *Elem, Ctx) && !isByteCountVar(Count, *Elem, Body, Ctx))
        return;
      std::string CountText = raptor::oneLine(
          Lexer::getSourceText(CharSourceRange::getTokenRange(Count->getSourceRange()),
                               Ctx.getSourceManager(), Ctx.getLangOpts()));
      raptor::reportAt(
          BR, this, "Wide-character count given in bytes",
          (It->first() + "() takes the size of its buffer in characters, but '" +
           CountText + "' is a size in bytes (" + std::to_string(Elem->getQuantity()) +
           " bytes per character): it may write past the end of the buffer. Divide by "
           "the element size, e.g. sizeof(buf) / sizeof(buf[0])")
              .str(),
          CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(WideCountInBytesChecker, "WideCountInBytes",
               "wide-character buffer size passed in bytes where characters are expected")
