cmake_minimum_required(VERSION 3.20)
project(RaptorCheckers CXX)

# Clang Static Analyzer plugin with checkers ported from
# https://github.com/0xdea/semgrep-rules (one checker per semgrep rule).
find_package(Clang REQUIRED CONFIG HINTS /usr/lib/llvm-18/lib/cmake/clang)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build only a subset of checkers, e.g. -DRAPTOR_ONLY="DoubleFree;UseAfterFree"
set(RAPTOR_ONLY "" CACHE STRING "Checker source basenames to build (default: all)")
if(RAPTOR_ONLY)
  set(CHECKER_SRCS "")
  foreach(name IN LISTS RAPTOR_ONLY)
    list(APPEND CHECKER_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/checkers/${name}.cpp)
  endforeach()
else()
  file(GLOB CHECKER_SRCS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/checkers/*.cpp)
endif()

add_library(RaptorCheckers MODULE src/Plugin.cpp src/Common.cpp ${CHECKER_SRCS})
target_include_directories(RaptorCheckers PRIVATE src ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
separate_arguments(LLVM_DEFS NATIVE_COMMAND "${LLVM_DEFINITIONS}")
target_compile_definitions(RaptorCheckers PRIVATE ${LLVM_DEFS})
# LLVM/Clang are built without RTTI; symbols resolve against the loading clang
target_compile_options(RaptorCheckers PRIVATE -fno-rtti -Wall -Wno-unused-parameter)
set_target_properties(RaptorCheckers PROPERTIES PREFIX "")
# The clang headers dominate build time; precompile them once
target_precompile_headers(RaptorCheckers PRIVATE
  <clang/ASTMatchers/ASTMatchFinder.h>
  <clang/StaticAnalyzer/Core/Checker.h>
  <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
  <clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h>
  <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
  <clang/StaticAnalyzer/Frontend/CheckerRegistry.h>)
