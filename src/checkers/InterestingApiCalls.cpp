// raptor.InterestingApiCalls: calls to functions whose name matches
// one of the rule's (case-insensitive) regexes. For the memcpy() family, the
// length must not be a sizeof expression or a plain integer literal.
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
// The rule's metavariable-regex patterns on $FUN, minus the leading (?i).
const char *const FunRegexes[] = {
    // priv
    R"(^\w*set\w*(u|g)id\s*$|^\w*(init|set)groups\s*$|^\w*Impersonate\w*\s*$)",
    // strcpy
    R"(^\w*str\w?(cpy|add)(_s)?(_l)?\s*$|^\w*stpn?cpy(_s)?(_l)?\s*$|^\w*(wc|mb|ftc|tc)s\w?cpy(_s)?(_l)?\s*$|^\w*wcpn?cpy(_s)?(_l)?\s*$)",
    // strcat
    R"(^\w*str\w?cat(_s)?(_l)?\s*$|^\w*(wc|mb|ftc|tc)s\w?cat(_s)?(_l)?\s*$)",
    // strtok
    R"(^\w*strtok(_r)?(_s)?(_l)?\s*$|^\w*(wc|mb)stok(_r)?(_s)?(_l)?\s*$|^\w*str(find|rspn|trns)\s*$)",
    // printf
    R"(^\w*s\w*printf(_s)?(_l)?\w*\s*$)",
    // scanf
    R"(^\w*scanf(_s)?(_l)?\s*$)",
    // get
    R"(^\w*get(s|ws(_l)?|ts|tws|c|char|pw|pass|wd|cwd|login(_r)?|groups|hostname|domainname|opt|opt_long)\s*$|^\w*cuserid\s*$)",
    // environment
    R"(^\w*(get|set|put|unset)env\s*$|^\w*g_get_(home|tmp)_dir\s*$)",
    // alloc
    R"(^\w*alloc(a|f)?\s*$|^\w*alloc_?array\s*$)",
    // exec
    R"(^\w*exec(l|v)?(p|e)?e?\s*$|^\w*system\s*$|^\w*spawn\w?\s*$|^\w*wordexp\s*$|^\w*WinExec\s*$|^\w*ShellExecute(A|ExA|W|ExW)?\s*$|^\w*CreateProcess(A|AsUserA|W|AsUserW|WithLogonW|WithTokenW)?\s*$)",
    // i/o
    R"(^\w*open(at)?(64)?\s*$|^\w*pipe\s*$|^\w*read\s*$|^\w*recv(from)?\s*$|^\w*copylist\s*$|^\w*dbminit\s*$|^\w*LoadLibrary(A|ExA|W|ExW)?\s*$)",
    // proc
    R"(^\w*fork\s*$)",
    // rand
    R"(^\w*rand(_r|48)?\s*$)",
    // tmp
    R"(^\w*mk\w?temp(64)?\s*$|^\w*te?mpnam(_r)?\s*$|^\w*tmpfile\s*$|^\w*GetTempFileName(A|W)?\s*$)",
    // file
    R"(^\w*(mk|ch)(dir|nod)(at)?\s*$|^\w*creat\s*$|^\w*link(at)?\s*$|^\w*rename(at)?\s*$|^\w*access(at|at2|_ok)?\s*$|^\w*stat(at)?\s*$|^\w*ch(own|mod|root)(at)?\s*$|^\w*realpath\s*$|^\w*readlink(at)?\s*$|^\w*(tty|pts)name_r\s*$)",
    // more file
    R"(^\w*locale\s*$|^\w*(make|split)path\s*$|^\w*fattach\s*$|^\w*ftw\s*$|^\w*truncate\s*$|^\w*u(mask|limit)\s*$|^\w*AddAccessAllowedAce\s*$)",
    // conf
    R"(^\w*confstr\s*$|^\w*utmpx?name\s*$)",
    // string conversions
    R"(^\w*mbs(nr|r)?towcs(_l)?\s*$|^\w*wcs(nr|r)?tombs(_l)?\s*$|^\w*OemToCharW\s*$|^\w*MultiByteToWideChar\s*$)",
    // inet
    R"(^\w*inet_(ntop|pton)\s*$)",
    // time
    R"(^\w*cftime\s*$)",
    // syscall
    R"(^\w*syscall\s*$)",
    // kernel
    R"(^\w*copy_(from|to)_user\s*$|^\w*(get|put)_user\s*$|^\w*copy(in|out)\s*$|^\w*cdev_init\s*$)",
};

// memcpy: $FUN($_, $_, $LEN, ...)
const char *const MemcpyRegex =
    R"(^\w*mem(c|p)?cpy(_s)?\s*$|^\w*memmove(_s)?\s*$|^\w*bcopy\s*$|^\w*CopyMemory\s*$)";
// $LEN must not be a numeric literal
const char *const LenRegex =
    R"(^(?!\s*(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)[uUlL]*\s*$).+)";

std::regex icase(const char *Re) {
  return std::regex(Re, std::regex::ECMAScript | std::regex::icase);
}

class InterestingApiCallsChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    static const std::vector<std::regex> Funs = [] {
      std::vector<std::regex> V;
      for (const char *R : FunRegexes)
        V.push_back(icase(R));
      return V;
    }();
    static const std::regex Memcpy = icase(MemcpyRegex);
    static const std::regex Len(LenRegex);

    ASTContext &Ctx = Mgr.getASTContext();
    raptor::api::forEachCall(D, Mgr, [&](const CallExpr *CE) {
      std::string Name = raptor::api::calleeAsWritten(CE, Ctx);
      if (Name.empty())
        return;
      bool Match = false;
      for (const std::regex &R : Funs)
        Match = Match || std::regex_search(Name, R);
      if (!Match && CE->getNumArgs() >= 3 && std::regex_search(Name, Memcpy)) {
        const Expr *L = CE->getArg(2);
        const auto *SizeOf =
            dyn_cast<UnaryExprOrTypeTraitExpr>(L->IgnoreParenImpCasts());
        bool IsSizeOf = SizeOf && SizeOf->getKind() == UETT_SizeOf &&
                        !L->getBeginLoc().isMacroID();
        Match = !IsSizeOf && raptor::api::regexMatchesAtStart(
                                 raptor::api::textAsWritten(L, Ctx), Len);
      }
      if (Match)
        raptor::reportAt(BR, this, "Interesting API call",
                         "Call to an interesting and potentially insecure API "
                         "function (candidate point): backtrace from here to "
                         "find pathways allowing access from untrusted input",
                         CE, Mgr.getAnalysisDeclContext(D));
    });
  }
};
} // namespace

RAPTOR_CHECKER(InterestingApiCallsChecker, "InterestingApiCalls",
               "Calls to interesting and potentially insecure API functions")
