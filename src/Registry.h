// Self-registration so that every checker lives in its own source file and
// the plugin needs no central list.
#pragma once

#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include <vector>

namespace raptor {

using RegisterFn = void (*)(clang::ento::CheckerRegistry &);

std::vector<RegisterFn> &registry();

struct Registrar {
  explicit Registrar(RegisterFn F) { registry().push_back(F); }
};

} // namespace raptor

// RAPTOR_CHECKER(DoubleFreeChecker, "DoubleFree", "The software calls free() twice ...")
// registers the checker as raptor.DoubleFree.
#define RAPTOR_CHECKER(CLASS, NAME, DESC)                                      \
  static ::raptor::Registrar CLASS##Registrar(                                 \
      [](clang::ento::CheckerRegistry &R) {                                    \
        R.addChecker<CLASS>("raptor." NAME, DESC,                              \
                            "https://github.com/0xdea/semgrep-rules");         \
      });
