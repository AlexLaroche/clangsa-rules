// Port of raptor-insecure-api-mktemp-tmpnam-tempnam: any call to mktemp(), tmpnam(), tempnam(), tmpnam_r().
#include "ApiUtil.h"
#include "Registry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
class InsecureApiMktempTmpnamTempnamChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    raptor::api::reportCallsTo(
        D, Mgr, BR, this, "Insecure temporary file",
        "Creating and using insecure temporary files can leave application and system data vulnerable to attack",
        {"mktemp", "tmpnam", "tempnam", "tmpnam_r"});
  }
};
} // namespace

RAPTOR_CHECKER(InsecureApiMktempTmpnamTempnamChecker, "InsecureApiMktempTmpnamTempnam",
               "Use of mktemp(), tmpnam(), and tempnam()")
