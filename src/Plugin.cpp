#include "Registry.h"

std::vector<raptor::RegisterFn> &raptor::registry() {
  static std::vector<RegisterFn> Fns;
  return Fns;
}

extern "C" void clang_registerCheckers(clang::ento::CheckerRegistry &R) {
  for (raptor::RegisterFn F : raptor::registry())
    F(R);
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
