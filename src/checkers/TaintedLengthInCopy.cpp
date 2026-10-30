// raptor.TaintedLengthInCopy: a length decoded from untrusted bytes reaches
// the size argument of a memory copy without being compared to anything
// first (the Heartbleed pattern, CVE-2014-0160):
//
//   n2s(p, payload);          // payload = (p[0] << 8) | p[1]
//   memcpy(bp, pl, payload);  // no check against the record length
//
// Path-sensitive. Sources: a byte read from memory and shifted by a multiple
// of 8 (big- or little-endian decoding, by hand or through macros such as
// n2s/n2l), and the result of byte-order and decoding functions (ntohs,
// be32toh, Curl_read16_le...).
// Values computed from a source stay tainted. Sanitizer: the value takes
// part in a <, <=, > or >= comparison (a comparison of the length alone
// with 0 or 1 is only a lower bound), or in == / != with a non-constant
// value, which marks it checked on the paths that follow. A comparison of a
// sum of two unchecked decoded values (offset + len > size) does not count,
// because the sum can wrap around. Sink: the size argument of memcpy() and
// friends.
#include "Common.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/Support/Regex.h"

using namespace clang;
using namespace ento;

// decoded symbol -> the expression that decoded it
REGISTER_MAP_WITH_PROGRAMSTATE(RaptorDecodedLen, SymbolRef, const Stmt *)
// decoded symbols that took part in a comparison
REGISTER_SET_WITH_PROGRAMSTATE(RaptorCheckedLen, SymbolRef)

namespace {
const Expr *ign(const Expr *E) { return E->IgnoreParenCasts(); }

// *p, p[i], *p++: a single character read from memory
bool isByteLoad(const Expr *E) {
  E = ign(E);
  if (!E->getType()->isCharType())
    return false;
  if (isa<ArraySubscriptExpr>(E))
    return true;
  const auto *UO = dyn_cast<UnaryOperator>(E);
  return UO && UO->getOpcode() == UO_Deref;
}

// byte << 8, byte << 16, ...
bool isShiftedByte(const Expr *E) {
  const auto *BO = dyn_cast<BinaryOperator>(ign(E));
  if (!BO || BO->getOpcode() != BO_Shl || !isByteLoad(BO->getLHS()))
    return false;
  const auto *Amount = dyn_cast<IntegerLiteral>(ign(BO->getRHS()));
  if (!Amount)
    return false;
  uint64_t N = Amount->getValue().getZExtValue();
  return N > 0 && N < 64 && N % 8 == 0;
}

// byte-order functions and the usual names of decoding helpers
// (Curl_read16_le, get_u32, read_be16, ...)
bool isByteOrderFunction(StringRef Name) {
  static const llvm::Regex RE(
      "^(ntoh(s|l|ll)|be(16|32|64)toh|le(16|32|64)toh|_?_?bswap_?(16|32|64)|"
      "get_unaligned(_be|_le)?(16|32|64)?|.*ntohu(16|24|32|64)|"
      ".*read_?(16|24|32|64)(_?(le|be))?|.*(get|read)_?(u|be|le|net)_?"
      "(16|24|32|64))$",
      llvm::Regex::IgnoreCase);
  return RE.match(Name);
}

// a + b + 16 -> a, b (constants dropped)
void addOperands(SymbolRef S, SmallVectorImpl<SymbolRef> &Out) {
  if (const auto *SC = dyn_cast<SymbolCast>(S))
    return addOperands(SC->getOperand(), Out);
  if (const auto *SS = dyn_cast<SymSymExpr>(S))
    if (SS->getOpcode() == BO_Add) {
      addOperands(SS->getLHS(), Out);
      addOperands(SS->getRHS(), Out);
      return;
    }
  if (const auto *SI = dyn_cast<SymIntExpr>(S))
    if (SI->getOpcode() == BO_Add)
      return addOperands(SI->getLHS(), Out);
  if (const auto *IS = dyn_cast<IntSymExpr>(S))
    if (IS->getOpcode() == BO_Add)
      return addOperands(IS->getRHS(), Out);
  Out.push_back(S);
}

// copy functions and the index of their size argument
int sizeArgIndex(StringRef Name) {
  if (raptor::isOneOf(Name, {"memcpy", "memmove", "memcmp", "bcopy",
                             "mempcpy", "wmemcpy", "wmemmove", "strncpy",
                             "stpncpy", "strncat", "strlcpy", "strlcat",
                             "CRYPTO_memcmp"}))
    return 2;
  if (Name == "memccpy")
    return 3;
  return -1;
}

class TaintedLengthInCopyChecker
    : public Checker<check::PostStmt<BinaryOperator>, check::PostCall,
                     check::PreCall> {
  const BugType BT{this, "Tainted length in copy", raptor::Category};

  // Mark the value of E (conjuring a symbol when the engine has none) as a
  // decoded length.
  void taint(const Expr *E, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const LocationContext *LCtx = C.getLocationContext();
    SVal V = C.getSVal(E);
    SymbolRef Sym = V.getAsSymbol(/*IncludeBaseRegions=*/false);
    if (!Sym) {
      if (!V.isUnknown())
        return; // a concrete value
      V = C.getSValBuilder().conjureSymbolVal(nullptr, E, LCtx, E->getType(),
                                             C.blockCount());
      State = State->BindExpr(E, LCtx, V);
      Sym = V.getAsSymbol();
      if (!Sym)
        return;
    }
    C.addTransition(State->set<RaptorDecodedLen>(Sym, E));
  }

  // A decoded symbol inside V that was never compared, if any.
  static std::pair<SymbolRef, const Stmt *> unchecked(ProgramStateRef State,
                                                      SVal V) {
    SymbolRef Sym = V.getAsSymbol(/*IncludeBaseRegions=*/false);
    if (!Sym)
      return {};
    for (SymbolRef S : Sym->symbols())
      if (const Stmt *const *Src = State->get<RaptorDecodedLen>(S))
        if (!State->contains<RaptorCheckedLen>(S))
          return {S, *Src};
    return {};
  }

  static ProgramStateRef markChecked(ProgramStateRef State, SVal V) {
    SymbolRef Sym = V.getAsSymbol(/*IncludeBaseRegions=*/false);
    if (!Sym)
      return State;
    for (SymbolRef S : Sym->symbols())
      if (State->get<RaptorDecodedLen>(S))
        State = State->add<RaptorCheckedLen>(S);
    return State;
  }

  // offset + len > size, with offset and len both unchecked decoded values:
  // the sum can wrap around, so the comparison bounds neither of them
  // (CVE-2018-16890). It does once one of them was checked on its own.
  // Does V involve a value other than decoded ones and constants? Then
  // `total - len < 0` bounds len, unlike `len > 0`.
  static bool hasOtherValue(ProgramStateRef State, SymbolRef S) {
    if (State->get<RaptorDecodedLen>(S))
      return false;
    if (isa<SymbolData>(S))
      return true;
    if (const auto *SC = dyn_cast<SymbolCast>(S))
      return hasOtherValue(State, SC->getOperand());
    if (const auto *SI = dyn_cast<SymIntExpr>(S))
      return hasOtherValue(State, SI->getLHS());
    if (const auto *IS = dyn_cast<IntSymExpr>(S))
      return hasOtherValue(State, IS->getRHS());
    if (const auto *SS = dyn_cast<SymSymExpr>(S))
      return hasOtherValue(State, SS->getLHS()) ||
             hasOtherValue(State, SS->getRHS());
    if (const auto *US = dyn_cast<UnarySymExpr>(S))
      return hasOtherValue(State, US->getOperand());
    return true;
  }
  static bool hasOtherValue(ProgramStateRef State, SVal V) {
    SymbolRef Sym = V.getAsSymbol(/*IncludeBaseRegions=*/false);
    return Sym && hasOtherValue(State, Sym);
  }

  static bool sumCanWrap(ProgramStateRef State, SVal V) {
    SymbolRef Sym = V.getAsSymbol(/*IncludeBaseRegions=*/false);
    if (!Sym)
      return false;
    SmallVector<SymbolRef, 4> Ops;
    addOperands(Sym, Ops);
    unsigned Unchecked = 0;
    for (SymbolRef Op : Ops)
      Unchecked += unchecked(State, nonloc::SymbolVal(Op)).first != nullptr;
    return Unchecked >= 2;
  }

public:
  void checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const {
    if (BO->isComparisonOp()) {
      SVal L = C.getSVal(BO->getLHS()), R = C.getSVal(BO->getRHS());
      // len == n bounds len; len != 0, len > 0 and len < 1 do not
      if (BO->isEqualityOp() && (L.isConstant() || R.isConstant()))
        return;
      if ((L.isConstant(0) || L.isConstant(1) || R.isConstant(0) ||
           R.isConstant(1)) &&
          !hasOtherValue(C.getState(), L) && !hasOtherValue(C.getState(), R))
        return;
      ProgramStateRef State = C.getState();
      ProgramStateRef New = State;
      if (!sumCanWrap(State, L))
        New = markChecked(New, L);
      if (!sumCanWrap(State, R))
        New = markChecked(New, R);
      if (New != State)
        C.addTransition(New);
      return;
    }
    if (isShiftedByte(BO)) {
      taint(BO, C);
      return;
    }
    // (b0 << 8) | b1, l |= b2 << 8: the whole value is the decoded length
    BinaryOperatorKind K = BO->getOpcode();
    if ((K == BO_Or || K == BO_OrAssign) &&
        (unchecked(C.getState(), C.getSVal(BO->getLHS())).first ||
         unchecked(C.getState(), C.getSVal(BO->getRHS())).first) &&
        (isByteLoad(BO->getRHS()) || isShiftedByte(BO->getRHS()) ||
         isByteLoad(BO->getLHS()) || isShiftedByte(BO->getLHS())))
      taint(BO, C);
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (FD && FD->getIdentifier() && isByteOrderFunction(FD->getName()) &&
        Call.getOriginExpr())
      taint(Call.getOriginExpr(), C);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return;
    int Idx = sizeArgIndex(FD->getName());
    if (Idx < 0 || Call.getNumArgs() <= unsigned(Idx))
      return;
    auto [Sym, Src] = unchecked(C.getState(), Call.getArgSVal(Idx));
    if (!Sym)
      return;
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Rep = std::make_unique<PathSensitiveBugReport>(
        BT,
        (llvm::Twine("The size argument of ") + FD->getName() +
         "() comes from bytes decoded from a buffer (e.g. a length field "
         "read from the network) and is not checked against the size of "
         "the source or destination buffer first; this may lead to an "
         "out-of-bounds read or write")
            .str(),
        N);
    Rep->addRange(Call.getArgExpr(Idx)->getSourceRange());
    Rep->markInteresting(Sym);
    Rep->addNote("Length decoded here",
                 PathDiagnosticLocation::createBegin(
                     Src, C.getSourceManager(), C.getLocationContext()));
    C.emitReport(std::move(Rep));
  }
};
} // namespace

RAPTOR_CHECKER(TaintedLengthInCopyChecker, "TaintedLengthInCopy",
               "Length decoded from untrusted bytes used as a copy size "
               "without a bounds check (CWE-130)")
