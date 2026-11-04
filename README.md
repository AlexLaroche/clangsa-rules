# clang-rules

Clang Static Analyzer checkers ported from
[0xdea/semgrep-rules](https://github.com/0xdea/semgrep-rules): one checker per
semgrep rule (50 rules: 49 in `rules/c` plus `rules/noisy/generic/bad-words`),
registered as `raptor.<CamelCaseRuleName>`, e.g. `raptor-use-after-free` ->
`raptor.UseAfterFree`, plus checkers of our own such as
`raptor.TaintedLengthInCopy`, `raptor.IgnoredStatusReturn`,
`raptor.UncheckedCursorWrite`, `raptor.UncheckedSourceOffset`,
`raptor.WStreamLengthUnsealed`, `raptor.UncheckedAllocProduct`,
`raptor.CopyIgnoresSourceSize`, `raptor.NegativeLengthUnchecked`,
`raptor.UnboundedCopyToStackArray` and `raptor.SizeFieldIgnoresCapacity`.

Because clang runs the preprocessor, every file that compiles is analysed:
`#if`/`#else` splits that make semgrep drop whole files (e.g. OpenSSL
`ssl/d1_both.c`) are not a problem. The flip side is that only the build
configuration you compile is analysed, and macros are seen expanded.

## Build

Requires clang 18 or later (tested with 18 and 23) with its development files
(`libclang-<N>-dev`, `llvm-<N>-dev`, `clang-tools-<N>`).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

This produces `build/RaptorCheckers.so`. A subset can be built with
`-DRAPTOR_ONLY="DoubleFree;UseAfterFree"`. CMake looks for clang 18 by default;
for another version pass
`-DClang_DIR=/usr/lib/llvm-<N>/lib/cmake/clang -DLLVM_DIR=/usr/lib/llvm-<N>/lib/cmake/llvm`,
and load the plugin with the same clang it was built against (the plugin is
tied to one clang major version).

CI (`.github/workflows/ci.yml`) builds and runs the tests with the latest LLVM
release from apt.llvm.org.

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

### Integration tests

`tests/integration/` holds one file per real vulnerability (`<name>.json`), each with the
upstream commit that fixed it and that commit's parent.
`tools/run_integration.py` fetches both commits (shallow, by SHA, cached in
`build/integration-src`) and analyses the affected files:

- at the vulnerable commit, every vulnerable line must be reported;
- at the fixed commit, none of them may be reported (negative test).

Each vulnerable line is located by a regex that must match exactly one line
at both commits, so a case cannot pass because the code moved.

| Case | CVE | Checker | Vulnerable → fixed commit |
|------|-----|---------|---------------------------|
| `heartbleed` | CVE-2014-0160 | `raptor.TaintedLengthInCopy` | openssl `0d7717f` → `96db902` (1.0.1g) |
| `heartbleed-source-size` | CVE-2014-0160 | `raptor.CopyIgnoresSourceSize` | openssl `0d7717f` → `96db902` (1.0.1g) |
| `openjpeg-image-create` | CVE-2016-9118 | `raptor.UncheckedAllocProduct` | OpenJPEG `83342f2` → `c22cbd8` (2.2.0) |
| `libtiff-rgba-strip` | CVE-2019-17546 | `raptor.UncheckedAllocProduct` | libtiff `2218055` → `4bb584a` (4.1.0, 32-bit build) |
| `libexif-save-entry` | CVE-2020-0093 | `raptor.CopyIgnoresSourceSize` | libexif `154189b` → `5ae5973` (0.6.22) |
| `libmicrodns-rr-decode` | CVE-2020-6072 | `raptor.IgnoredStatusReturn` | libmicrodns `0103f40` → `89de67f` (0.1.2) |
| `webp-huffman` | CVE-2023-4863 | `raptor.UncheckedCursorWrite` | libwebp `7ba44f8` → `902bc91` (1.3.2) |
| `mbedtls-lms-verify` | CVE-2025-49600 | `raptor.IgnoredStatusReturn` | Mbed TLS `caaffc1` → `ae449bf` (3.6.4, with `MBEDTLS_LMS_PRIVATE`) |
| `editorconfig-glob-pattern-copy` | CVE-2026-40489 | `raptor.UnboundedCopyToStackArray` | editorconfig-core-c `b4724e4` → `5159be8` |
| `sail-tga-raw-packet` | CVE-2026-40494 | `raptor.UncheckedCursorWrite` | SAIL `c930284` → `45d48d1` |
| `thrift-header-negative-string-length` | CVE-2026-58662 | `raptor.NegativeLengthUnchecked` | Thrift `0ab16e3` → `f961cdb` |
| `freerdp-websocket-pong` | CVE-2026-67292 | `raptor.WStreamLengthUnsealed` | FreeRDP `efe40e1` → `91bbb4e` (3.29.0) |
| `ffmpeg-raw-rgb` | CVE-2026-70628 | `raptor.UncheckedAllocProduct` | FFmpeg `3538578` → `d32b387` |
| `dcmtk-concatenation` | CVE-2026-97059 | `raptor.UncheckedSourceOffset` | DCMTK `30cc153` → `18379d5` |
| `freerdp-persistent-cache-v2` | CVE-2026-111381 | `raptor.SizeFieldIgnoresCapacity` | FreeRDP `b99ed85` → `bb10797` (3.32.0) |
| `broccoli2shell` | CVE-2026-111497 | `raptor.IgnoredStatusReturn` | brotli `e61745a` (1.0.9) → `50a9b70` (1.0.10) |
| `freeimage-iff-pbm-rle` | CVE-2026-118752 | `raptor.UncheckedCursorWrite` | FreeImage `5af27d0` → `38fbe82` (3.19.22) |

```sh
python3 tools/run_integration.py      # all, or: tools/run_integration.py heartbleed
```

It needs network access, `git`, `perl` (OpenSSL's `./config`), `cmake` and `ninja`
(DCMTK's and FreeRDP's configure steps; FreeRDP also needs the OpenSSL and zlib
development headers).

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
* [**raptor.CopyIgnoresSourceSize**](src/checkers/CopyIgnoresSourceSize.cpp). `memcpy`/`memmove` reads from a struct buffer field (`e->data`, `&s->s3->rrec.data[0]`, also through local pointers) whose own size field is known (`e->size`, `rrec.length`, `buf_len` for `buf`), but the copy length neither comes from that size nor is compared with it: a heap over-read, as in libexif (CVE-2020-0093) and Heartbleed (CVE-2014-0160). Constant lengths, lengths that are plain fields, in-place moves and positions computed from the size are not reported.
* [**raptor.TaintedLengthInCopy**](src/checkers/TaintedLengthInCopy.cpp). Length decoded from untrusted bytes (`n2s`, `ntohs`, `(p[0] << 8) | p[1]`...) used as the size of `memcpy` and friends without a bounds check, as in Heartbleed (CVE-2014-0160). Path-sensitive.
* [**raptor.UncheckedCursorWrite**](src/checkers/UncheckedCursorWrite.cpp). A write position advanced by data-dependent steps with no end check, in two shapes. *Unbounded writer*: a buffer passed to a function that advances a cursor in a loop (`table += table_size`) and writes through it without ever comparing it to a bound or counting down the room left, when the caller does not compare that buffer pointer either (libwebp CVE-2023-4863). *Run loop*: an outer loop checks an index against the end (`while (written < line)`), but an inner loop whose count comes from the data moves that index and writes (`for (k = 0; k < count; k++) bits[written++] = b;`) with no clamp on the way to it or inside it (FreeImage CVE-2026-118752, SAIL CVE-2026-40494). Loops bounded by a parameter, writers that count down their room, single offsets, constant runs and runs that test a position in their own condition are not reported.
* [**raptor.UncheckedSourceOffset**](src/checkers/UncheckedSourceOffset.cpp). A `memcpy`/`memmove` reading a buffer obtained from a call at an offset scaled by a loop counter (`base + i * k`), when nothing compares the loop bound, or a size computed from it, with anything: a heap over-read, as in DCMTK's NumberOfFrames copy (CVE-2026-97059).
* [**raptor.WStreamLengthUnsealed**](src/checkers/WStreamLengthUnsealed.cpp). FreeRDP/WinPR: `Stream_Length()` of a `wStream` that is filled by position (`Stream_Write_*`, `Stream_Seek`...) and never sealed (`Stream_SealLength`) is its capacity, not the data written; streams are followed across the file through fields, variables and parameters. As in the WebSocket Pong over-disclosure (CVE-2026-67292).
* [**raptor.NegativeLengthUnchecked**](src/checkers/NegativeLengthUnchecked.cpp). A signed length read from the data (an out-parameter such as `readVarint32(p, &len, end)`, or a call result) is checked only from above, in a signed comparison (`if (len > end - p) throw`), then used as a size or a pointer advance: a negative value passes the check and becomes a huge `size_t`, as in Apache Thrift's `THeaderTransport::readString` (CVE-2026-58662). A comparison with 0 or 1, an unsigned comparison, a bound from below on the path that uses the length (`if (n >= need) use`, `while (i < n)`), lengths kept in fields and narrower unsigned values widened are not reported.
* [**raptor.UnboundedCopyToStackArray**](src/checkers/UnboundedCopyToStackArray.cpp). A string of unknown length is copied into a fixed-size local array (`strcpy`, `strcat`, `sprintf` with a `%s` that has no precision, `vsprintf`) and nothing in the function compares its length (`strlen(s)`, or a local set from it) with anything: a stack overflow, as in editorconfig-core-c's `ec_glob` (CVE-2026-40489). Literals, tables of literals, locals only set to literals and source arrays that fit are not reported.
* [**raptor.SizeFieldIgnoresCapacity**](src/checkers/SizeFieldIgnoresCapacity.cpp). A (pointer, size) pair is set up in one block to describe another object's buffer (`entry->data = persistent->bmpData; entry->size = w * h * 4;`), but the size neither comes from that buffer's capacity field (`bmpSize`) nor is compared with it, so whoever uses the pair reads or writes past the end, as in FreeRDP's persistent cache v2 parser (CVE-2026-111381). Constant sizes, sizes derived from the capacity or from the field's own old value, and fresh allocations are not reported.

#### integer overflows

* [**raptor.IntegerWraparound**](src/checkers/IntegerWraparound.cpp). Potential integer wraparound errors.
* [**raptor.UncheckedAllocProduct**](src/checkers/UncheckedAllocProduct.cpp). An allocation sized by a 32-bit product of two run-time factors (`stride * height`, `w * h`), written in the call or computed into a local first, with no overflow guard on the factors (`a > INT_MAX / b`, `*_mul_overflow`, `av_size_mult`, both factors bounded by constants): when the product wraps, whatever fills the buffer writes past it. Products computed in `size_t` and constant factors do not match. As in FFmpeg's raw RGB reshuffle (CVE-2026-70628, CVE-2026-70632) OpenJPEG's `opj_image_create` (CVE-2016-9118) and libtiff's RGBA strip reader on 32-bit builds (CVE-2019-17546).
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
* [**raptor.IgnoredStatusReturn**](src/checkers/IgnoredStatusReturn.cpp). Discarded result of a function defined in the same file that reports success or failure: either every `return` is a constant such as `BROTLI_TRUE`/`BROTLI_FALSE` (or forwards another status), as in Broccoli2Shell (CVE-2026-111497, Brotli <= 1.0.9 `DecodeLiteralBlockSwitch`), or its integer or pointer result is checked at most of its other call sites (`ret = f(); if (ret)`, `if ((p = f()) == NULL)`), as in Mbed TLS `mbedtls_lms_verify` (CVE-2025-49600) and libmicrodns `rr_decode` (CVE-2020-6072). Not reported when the file discards the result more often than it checks it, for teardown functions (close, cleanup, free, final...), or for cleanup on a path that is already failing (`f(); break;`, `f(); return result;`). `(void)f()` opts out.
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
