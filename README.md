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
- `format-string-bugs.c`, `high-entropy-assignment.c`, `incorrect-use-of-sizeof.c`,
  `suspicious-assert.c`, `typos.c`, `write-into-stack-buffer.c`: regression
  tests appended at the end of the file for bugs found on OpenSSL.

## Rules

### C/C++

One checker per rule of the semgrep C/C++ ruleset.

#### buffer overflows

* [**raptor.InsecureApiGets**](src/checkers/InsecureApiGets.cpp). Use of the insecure API function `gets`.
* [**raptor.InsecureApiStrcpyStrcat**](src/checkers/InsecureApiStrcpyStrcat.cpp). Use of potentially insecure API functions `strcpy`, `stpcpy`, `strcat`.
* [**raptor.InsecureApiSprintfVsprintf**](src/checkers/InsecureApiSprintfVsprintf.cpp). Use of potentially insecure API functions `sprintf` and `vsprintf`.
* [**raptor.InsecureApiScanf**](src/checkers/InsecureApiScanf.cpp). Use of potentially insecure API functions in the `scanf` family.
* [**raptor.IncorrectUseOfStrncat**](src/checkers/IncorrectUseOfStrncat.cpp). Wrong size argument passed to `strncat`.
* [**raptor.UseOfSourceSizeInCopy**](src/checkers/UseOfSourceSizeInCopy.cpp). Wrong size argument passed to `strncpy`, `memcpy`, `snprintf`, and variants.
* [**raptor.IncorrectUseOfSizeof**](src/checkers/IncorrectUseOfSizeof.cpp). Accidental use of the `sizeof` operator on a pointer instead of its target.
* [**raptor.UnterminatedStringStrncpy**](src/checkers/UnterminatedStringStrncpy.cpp). Lack of explicit NUL-termination after `strncpy` and `stpncpy`.
* [**raptor.OffByOne**](src/checkers/OffByOne.cpp). Potential off-by-one error.
* [**raptor.UnsafeRetSnprintfVsnprintf**](src/checkers/UnsafeRetSnprintfVsnprintf.cpp). Potentially unsafe use of the return value of `snprintf` and `vsnprintf`.
* [**raptor.UnsafeRetStrlcpyStrlcat**](src/checkers/UnsafeRetStrlcpyStrlcat.cpp). Potentially unsafe use of the return value of `strlcpy` and `strlcat`.
* [**raptor.PointerSubtraction**](src/checkers/PointerSubtraction.cpp). Potential use of pointer subtraction to determine size.
* [**raptor.WriteIntoStackBuffer**](src/checkers/WriteIntoStackBuffer.cpp). Direct write into buffer allocated on the stack.

#### integer overflows

* [**raptor.IntegerWraparound**](src/checkers/IntegerWraparound.cpp). Potential integer wraparound errors.
* [**raptor.UnsafeStrlen**](src/checkers/UnsafeStrlen.cpp). Casting the return value of `strlen` to short might be dangerous.
* [**raptor.IntegerTruncation**](src/checkers/IntegerTruncation.cpp). Potential integer truncation errors.
* [**raptor.SignedUnsignedConversion**](src/checkers/SignedUnsignedConversion.cpp). Potential signed/unsigned conversion errors.
* [**raptor.IncorrectUnsignedComparison**](src/checkers/IncorrectUnsignedComparison.cpp). Checking if an unsigned variable is negative.

#### format strings

* [**raptor.FormatStringBugs**](src/checkers/FormatStringBugs.cpp). Potential format string bugs.

#### memory management

* [**raptor.InsecureApiAlloca**](src/checkers/InsecureApiAlloca.cpp). Use of the potentially insecure API function `alloca`.
* [**raptor.UseAfterFree**](src/checkers/UseAfterFree.cpp). Potential use after `free`.
* [**raptor.DoubleFree**](src/checkers/DoubleFree.cpp). Potential double `free`.
* [**raptor.IncorrectUseOfFree**](src/checkers/IncorrectUseOfFree.cpp). Calling `free` on memory not in the heap.
* [**raptor.UncheckedRetMalloc**](src/checkers/UncheckedRetMalloc.cpp). Unchecked return code of `malloc`, `calloc`, `realloc`, etc.
* [**raptor.PutenvStackVar**](src/checkers/PutenvStackVar.cpp). Call to `putenv` with a stack-allocated variable.
* [**raptor.RetStackAddress**](src/checkers/RetStackAddress.cpp). Potential return of the address of a stack-allocated variable.
* [**raptor.MismatchedMemoryManagement**](src/checkers/MismatchedMemoryManagement.cpp). Potentially mismatched C memory management routines.
* [**raptor.MismatchedMemoryManagementCpp**](src/checkers/MismatchedMemoryManagementCpp.cpp). Potentially mismatched C++ memory management routines.
* [**raptor.MemoryAddressExposure**](src/checkers/MemoryAddressExposure.cpp). Potential exposure of underlying memory addresses.

#### command injection

* [**raptor.CommandInjection**](src/checkers/CommandInjection.cpp). Potential OS command injection via `system` or `popen`.

#### race conditions

* [**raptor.InsecureApiAccessStat**](src/checkers/InsecureApiAccessStat.cpp). Use of insecure API functions `access`, `stat`, `lstat`, etc.
* [**raptor.InsecureApiMktempTmpnamTempnam**](src/checkers/InsecureApiMktempTmpnamTempnam.cpp). Use of insecure API functions `mktemp`, `tmpnam`, `tempnam`.
* [**raptor.InsecureApiSignal**](src/checkers/InsecureApiSignal.cpp). Use of insecure API function `signal`.

#### privilege management

* [**raptor.IncorrectOrderSetuidSetgid**](src/checkers/IncorrectOrderSetuidSetgid.cpp). Privilege management functions called in the wrong order.
* [**raptor.UncheckedRetSetuidSeteuid**](src/checkers/UncheckedRetSetuidSeteuid.cpp). Unchecked return code of `setuid` and `seteuid`.

#### denial of service

* [**raptor.RegexDos**](src/checkers/RegexDos.cpp). Regular expression that may exhibit exponential runtime and lead to ReDoS.

#### miscellaneous

* [**raptor.IncorrectUseOfMemset**](src/checkers/IncorrectUseOfMemset.cpp). Wrong order of arguments to `memset`.
* [**raptor.InsecureApiRandSrand**](src/checkers/InsecureApiRandSrand.cpp). Use of potentially insecure API functions `rand` and `srand`.
* [**raptor.OverlappingSourceDestination**](src/checkers/OverlappingSourceDestination.cpp). Source and destination overlap in copy functions.
* [**raptor.SuspiciousAssert**](src/checkers/SuspiciousAssert.cpp). Potentially invalid size check due to use of assertion macros.
* [**raptor.InterestingApiCalls**](src/checkers/InterestingApiCalls.cpp). Calls to interesting and potentially insecure API functions.
* [**raptor.UncheckedRetScanf**](src/checkers/UncheckedRetScanf.cpp). Unchecked return code of functions in the `scanf` family.
* [**raptor.InsecureApiAto**](src/checkers/InsecureApiAto.cpp). Use of potentially insecure API functions `atoi`, `atol`, `atof`.
* [**raptor.HighEntropyAssignment**](src/checkers/HighEntropyAssignment.cpp). Assignment of a high-entropy value that might be a secret.
* [**raptor.ArgvEnvpAccess**](src/checkers/ArgvEnvpAccess.cpp). Command-line argument or environment variable access.
* [**raptor.MissingDefaultInSwitch**](src/checkers/MissingDefaultInSwitch.cpp). Missing default case in a switch statement.
* [**raptor.MissingBreakInSwitch**](src/checkers/MissingBreakInSwitch.cpp). Missing break or equivalent in a switch statement.
* [**raptor.MissingReturn**](src/checkers/MissingReturn.cpp). Missing return statement in non-void function.
* [**raptor.Typos**](src/checkers/Typos.cpp). Potential typos with security implications.

### Noisy

Potentially too noisy for general use. It is part of `raptor`; skip it with `-Xclang -analyzer-disable-checker=raptor.BadWords`.

#### generic

* [**raptor.BadWords**](src/checkers/BadWords.cpp). Keywords and comments that suggest the presence of bugs.


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

## License

[MIT](LICENSE). The checkers are ports of, and the tests are adapted from,
[0xdea/semgrep-rules](https://github.com/0xdea/semgrep-rules), MIT-licensed,
Copyright (c) 2022 raptor; that copyright notice is kept in [LICENSE](LICENSE).
