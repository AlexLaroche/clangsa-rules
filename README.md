# clang-rules

Clang Static Analyzer checkers ported from
[0xdea/semgrep-rules](https://github.com/0xdea/semgrep-rules): one checker per
semgrep rule (50 rules: 49 in `rules/c` plus `rules/noisy/generic/bad-words`),
registered as `raptor.<CamelCaseRuleName>`, e.g. `raptor-use-after-free` ->
`raptor.UseAfterFree`.

Because clang runs the preprocessor, every file that compiles is analysed:
`#if`/`#else` splits that make semgrep drop whole files (e.g. OpenSSL
`ssl/d1_both.c`) are not a problem. The flip side is that only the build
configuration you compile is analysed, and macros are seen expanded.

## Build

Requires clang 18 with its development files (`libclang-18-dev`,
`clang-tools-18`).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

This produces `build/RaptorCheckers.so`. A subset can be built with
`-DRAPTOR_ONLY="DoubleFree;UseAfterFree"`.

## Use

One file:

```sh
clang --analyze -Xclang -load -Xclang build/RaptorCheckers.so \
      -Xclang -analyzer-checker=raptor file.c          # or raptor.UseAfterFree
```

A whole project, with its real build flags from `compile_commands.json`
(e.g. from `intercept-build make` or CMake's `CMAKE_EXPORT_COMPILE_COMMANDS`):

```sh
tools/scan.py compile_commands.json -o findings.json -j 8 [--filter REGEX]
```

`scan-build -load-plugin build/RaptorCheckers.so -enable-checker raptor make`
also works.

## Tests

`tests/<rule>.c(pp)` are the semgrep test files, made compilable (stub
declarations added, duplicate function names renamed) with every
`// ruleid:` / `// ok:` annotation kept. `tools/run_tests.py` runs each with
only its checker enabled and reports missed and incorrect lines, like
`semgrep --test`:

```sh
python3 tools/run_tests.py            # all, or: tools/run_tests.py typos
```

Annotation changes from the originals:

- `double-free.c`, `use-after-free.c`: one `todoruleid` each became `ruleid`
  (the path-sensitive checkers find a case semgrep misses).
- `unsafe-ret-snprintf-vsnprintf.c`: the original's misspelled `todoruled`
  is spelled `todoruleid`.
- `command-injection.cpp`, `insecure-api-access-stat.cpp`: extra C++ tests.

## Layout

```
src/Plugin.cpp, src/Registry.h   plugin entry point and self-registration
src/Common.h/.cpp                helpers shared by the AST-based checkers
src/checkers/*.cpp               one checker per rule (+ batch helpers *.h)
tools/run_tests.py               semgrep --test equivalent
tools/scan.py                    project scan driver
```

## Differences from semgrep

- Macros are expanded: the checkers see code inside macros (more findings for
  e.g. integer truncation in `s2n()`) but no longer see macro names
  (`OPENSSL_malloc` is `CRYPTO_malloc`; `return` hidden in `OPENSSL_EXIT()`
  is visible, which removes semgrep's missing-return false positives).
  `raptor.Typos` ignores operators that come from macro bodies.
- Code in inactive `#if` branches is not analysed.
- Lifetime rules (double free, use after free, unchecked malloc...) use the
  path-sensitive engine instead of semgrep's `A; ... B;` sequences.
- `raptor.HighEntropyAssignment` reimplements semgrep's entropy analyzer
  (`src/engine/Entropy.ml`) with the same trigram table; on a 41-string
  differential test it flags exactly the same strings.
