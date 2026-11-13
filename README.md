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
`raptor.UnboundedCopyToStackArray`, `raptor.SizeFieldIgnoresCapacity` and
`raptor.DuplicateContainerInsert`.

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
- `write-into-stack-buffer.c`: `strlcpy(buf, string, BUFSIZE)` and
  `memcpy(buf, string, BUFSIZE)` into `char buf[BUFSIZE]` became `ok`: a
  length that cannot exceed the array cannot overflow it (noise cut after
  the SymCrypt triage).
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
at both commits, so a case cannot pass because the code moved. When the same
text appears elsewhere, `{"re": ..., "after": ...}` takes the first match
after a line matching `after` (a label, a function header).

| Case | CVE | Checker | Vulnerable → fixed commit |
|------|-----|---------|---------------------------|
| `heartbleed` | CVE-2014-0160 | `raptor.TaintedLengthInCopy` | openssl `0d7717f` → `96db902` (1.0.1g) |
| `heartbleed-source-size` | CVE-2014-0160 | `raptor.CopyIgnoresSourceSize` | openssl `0d7717f` → `96db902` (1.0.1g) |
| `openjpeg-image-create` | CVE-2016-9118 | `raptor.UncheckedAllocProduct` | OpenJPEG `83342f2` → `c22cbd8` (2.2.0) |
| `tor-kist-pending-double-add` | CVE-2018-0491 | `raptor.DuplicateContainerInsert` | Tor `df312b3` → `cb5654f` (0.3.3.2-alpha) |
| `libtiff-rgba-strip` | CVE-2019-17546 | `raptor.UncheckedAllocProduct` | libtiff `2218055` → `4bb584a` (4.1.0, 32-bit build) |
| `libexif-save-entry` | CVE-2020-0093 | `raptor.CopyIgnoresSourceSize` | libexif `154189b` → `5ae5973` (0.6.22) |
| `libmicrodns-rr-decode` | CVE-2020-6072 | `raptor.IgnoredStatusReturn` | libmicrodns `0103f40` → `89de67f` (0.1.2) |
| `webp-huffman` | CVE-2023-4863 | `raptor.UncheckedCursorWrite` | libwebp `7ba44f8` → `902bc91` (1.3.2) |
| `mbedtls-lms-verify` | CVE-2025-49600 | `raptor.IgnoredStatusReturn` | Mbed TLS `caaffc1` → `ae449bf` (3.6.4, with `MBEDTLS_LMS_PRIVATE`) |
| `openjpeg-pi-encode-include-size` | CVE-2026-6192 | `raptor.UncheckedAllocProduct` | OpenJPEG `1ad9bec` → `839936a` |
| `radare2-str-append-int-length` | CVE-2026-14761 | `raptor.IntegerWraparound` | radare2 `8b25c77` → `a20a569` |
| `gegl-rgbe-pixels-alloc` | CVE-2026-18300 | `raptor.UncheckedAllocProduct` | GEGL `cd4afd4` → `d3d2620` |
| `iccdev-sparse-matrix-needed-size` | CVE-2026-21486 | `raptor.NarrowProductWidened` | iccDEV `3942df5` → `1ab7363` |
| `iccdev-calc-args-product` | CVE-2026-21688 | `raptor.TruncatedProduct` | iccDEV `3da74f5` → `b835299` |
| `httpd-h2-spurge-double-purge` | CVE-2026-23918 | `raptor.DuplicateContainerInsert` | Apache httpd `0245037` → `542e0da` (mod_http2 2.0.37, 2.4.67) |
| `iccdev-floatnum-getvalues-loop` | CVE-2026-25584 | `raptor.LoopBoundIgnoresCapacityParam` | iccDEV `ba81cd9` → `c9cb108` |
| `gpac-nhml-xml-header-end` | CVE-2026-27821 | `raptor.UnboundedCopyToStackArray` | GPAC `bec127d` → `9bd7137` |
| `swupdate-multipart-chunk-length` | CVE-2026-28525 | `raptor.UncheckedUnsignedSubtraction` | SWUpdate `e3b3c97` → `beee2dc` |
| `pjsip-opus-parse-frame-count` | CVE-2026-29068 | `raptor.LoopBoundIgnoresCapacityParam` | pjsip `63e7490` → `6c90245` |
| `iccdev-tagnum-getvalues-loop` | CVE-2026-30987 | `raptor.LoopBoundIgnoresCapacityParam` | iccDEV `04025bd` → `73ae1f5` |
| `htslib-byte-array-stop-off-by-one` | CVE-2026-31969 | `raptor.PostDecrementOffByOne` | HTSlib `d8127ae` → `88cdf69` |
| `freerdp-clear-vbar-size-before-realloc` | CVE-2026-33984 | `raptor.CapacityUpdatedBeforeRealloc` | FreeRDP `f6e43e2` → `dc7fdb1` |
| `freerdp-clear-glyph-count-before-realloc` | CVE-2026-33985 | `raptor.CapacityUpdatedBeforeRealloc` | FreeRDP `dc7fdb1` → `c49d1ad` |
| `freerdp-h264-yuv-dimensions-before-realloc` | CVE-2026-33986 | `raptor.CapacityUpdatedBeforeRealloc` | FreeRDP `1a890eb` → `f6e43e2` |
| `openexr-pxr24-widened-product` | CVE-2026-34380 | `raptor.NarrowProductWidened` | OpenEXR `881b546` → `a5e5a2e` |
| `openexr-piz-wavelet-offset` | CVE-2026-34588 | `raptor.NarrowProductWidened` | OpenEXR `f5beec2` → `e464a33` |
| `osslsigncode-message-digest` | CVE-2026-39853 | `raptor.WriteIntoStackBuffer` | osslsigncode `f90327d` → `cbee1e7` |
| `editorconfig-glob-pattern-copy` | CVE-2026-40489 | `raptor.UnboundedCopyToStackArray` | editorconfig-core-c `b4724e4` → `5159be8` |
| `sail-tga-raw-packet` | CVE-2026-40494 | `raptor.UncheckedCursorWrite` | SAIL `c930284` → `45d48d1` |
| `pjsip-auth-digest-ha1-copy` | CVE-2026-40892 | `raptor.UseOfSourceSizeInCopy` | pjproject `97deb02` → `c82123e` |
| `openexr-image-channel-num-pixels` | CVE-2026-41142 | `raptor.NarrowProductWidened` | OpenEXR `21eaa33` → `0592ee5` |
| `kissfft-fftndr-alloc` | CVE-2026-41445 | `raptor.UncheckedAllocProduct` | KissFFT `39c9781` → `8a8e66e` |
| `simpleble-peripheral-data-copy` | CVE-2026-44634 | `raptor.UseOfSourceSizeInCopy` | SimpleBLE `2a9cbfb` → `1501d59` |
| `libsixel-highcolor-alloc` | CVE-2026-44636 | `raptor.UncheckedAllocProduct` | libsixel `15c4c21` → `2d8c7b0` |
| `nimble-adv-report-sizeof-pointer` | CVE-2026-45812 | `raptor.IncorrectUseOfSizeof` | Apache NimBLE `5778cd6` → `605c758` |
| `libde265-image-plane-alloc` | CVE-2026-49346 | `raptor.UncheckedAllocProduct` | libde265 `56fb7b8` → `8a1b5cf` |
| `freerdp-avc444-buffer-alloc` | CVE-2026-55191 | `raptor.UncheckedAllocProduct` | FreeRDP `3248c0c` → `97f40b9` |
| `open-isns-attr-decode-free` | CVE-2026-55995 | `raptor.FreedFieldNotCleared` | open-isns `296d533` → `56718d4` |
| `hydra-ntlm-response-sprintf` | CVE-2026-56766 | `raptor.UnboundedCopyToStackArray` | THC-Hydra `2d7330f` → `9cc84c2` |
| `trafficserver-mime-u16-assert` | CVE-2026-58154 (CVE-2026-58152, CVE-2026-58158) | `raptor.AssertOnlyBound` | Apache Traffic Server `9d13175` → `8a7a963` |
| `thrift-header-negative-string-length` | CVE-2026-58662 | `raptor.NegativeLengthUnchecked` | Thrift `0ab16e3` → `f961cdb` |
| `freerdp-rdpsnd-client-formats-free` | CVE-2026-63652 | `raptor.FreedFieldNotCleared` | FreeRDP `2701474` → `caf653c` |
| `libssh2-sftp-open-double-free` | CVE-2026-66032 | `raptor.DoubleFree` | libssh2 `f784c21` → `5e47761` |
| `libssh2-aes-gcm-assert-bound` | CVE-2026-66033 | `raptor.AssertOnlyBound` | libssh2 `74a09eb` → `a2ed82d` |
| `freerdp-websocket-pong` | CVE-2026-67292 | `raptor.WStreamLengthUnsealed` | FreeRDP `efe40e1` → `91bbb4e` (3.29.0) |
| `ffmpeg-raw-rgb` | CVE-2026-70628 | `raptor.UncheckedAllocProduct` | FFmpeg `3538578` → `d32b387` |
| `indi-lilxml-error-format` | CVE-2026-71979 | `raptor.UnboundedCopyToStackArray` | INDI `3220880` → `96bbd7f` |
| `mongoose-tls-record-size` | CVE-2026-73252 | `raptor.UncheckedUnsignedSubtraction` | Mongoose `7fa830f` → `758e301` |
| `mongo-c-driver-ocsp-request-double-free` | CVE-2026-84964 | `raptor.DoubleFree` | mongo-c-driver `aba7244` → `7e4c665` |
| `xserver-xkb-doodad-text-free` | CVE-2026-88812 | `raptor.FreedFieldNotCleared` | X.Org xserver `effe0ba` → `0d1b1b0` |
| `dcmtk-concatenation` | CVE-2026-97059 | `raptor.UncheckedSourceOffset` | DCMTK `30cc153` → `18379d5` |
| `libexpat-realloc-assert-overflow` | CVE-2026-102633 | `raptor.AssertOnlyBound` | libexpat `cccede3` → `209801d` |
| `freerdp-persistent-cache-v2` | CVE-2026-111381 | `raptor.SizeFieldIgnoresCapacity` | FreeRDP `b99ed85` → `bb10797` (3.32.0) |
| `broccoli2shell` | CVE-2026-111497 | `raptor.IgnoredStatusReturn` | brotli `e61745a` (1.0.9) → `50a9b70` (1.0.10) |
| `mikmod-dsm-numtrk-product` | CVE-2026-105837 | `raptor.TruncatedProduct` | libmikmod `08d7d21` → `a125eab` |
| `mikmod-okt-numtrk-product` | CVE-2026-105839 | `raptor.TruncatedProduct` | libmikmod `e7c6c9e` → `097b692` |
| `libsmb2-dcerpc-carray-alloc` | CVE-2026-115505 | `raptor.UncheckedAllocProduct` | libsmb2 `312feca` → `a79f691` (6.3) |
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
* [**raptor.UseOfSourceSizeInCopy**](src/checkers/UseOfSourceSizeInCopy.cpp). Wrong size argument passed to `strncpy`, `memcpy`, `snprintf`, and variants, or to thin wrappers defined in the translation unit (`pj_memcpy`): the size of the source (`sizeof(src)`, a source declared `src[n]` copied for `n`), or, into a destination of fixed capacity (an array, `&local`), the source's own length, a sibling size field or the container's size, with no upper bound on it before the copy. As in pjsip's `pjsip_auth_create_digest2` (CVE-2026-40892, `pj_memcpy(ha1, cred_info->data.ptr, cred_info->data.slen)`, checked only by `PJ_ASSERT_RETURN(cred_info->data.slen >= digest_strlen)`) and SimpleBLE's C bindings (CVE-2026-44634, `memcpy(services->data, service.data().data(), service.data().size())` into a 27-byte array). Upper bounds (`if (len > sizeof(dst)) return;`, an enclosing `if (len <= cap)`, `std::min`), objects filled by a call given a constant limit (`curlx_str_until(&p, &out, MAX, '=')`), trailing one-element arrays, `sizeof(*src)` into an object of the same type and destinations whose capacity is not known here are not reported.
* [**raptor.IncorrectUseOfSizeof**](src/checkers/IncorrectUseOfSizeof.cpp). Accidental use of the `sizeof` operator on a pointer instead of its target. Apache NimBLE advanced its advertising-report cursor by `sizeof(rpt)` instead of `sizeof(*rpt)` (CVE-2026-45812). A `sizeof` compared with a constant or used as a `switch` condition checks a width, as in the kernel's `READ_ONCE` (`sizeof(x) == sizeof(long)`), and is not reported. Neither is the pointer variable used as data: `sizeof(p)` beside `&p` in an initializer list or call (OpenSSL `OSSL_PARAM {..., &handle, sizeof(handle)}`), or compared for equality with a received size.
* [**raptor.UnterminatedStringStrncpy**](src/checkers/UnterminatedStringStrncpy.cpp). Lack of explicit NUL-termination after `strncpy` and `stpncpy`.
* [**raptor.OffByOne**](src/checkers/OffByOne.cpp). Potential off-by-one error.
* [**raptor.UnsafeRetSnprintfVsnprintf**](src/checkers/UnsafeRetSnprintfVsnprintf.cpp). Potentially unsafe use of the return value of `snprintf` and `vsnprintf`. A result compared with the size given to the call (`if (len < 0 || len >= (int)sizeof(tmp))`, `n < cap ? n : cap - 1`), which detects truncation, is not reported.
* [**raptor.UnsafeRetStrlcpyStrlcat**](src/checkers/UnsafeRetStrlcpyStrlcat.cpp). Potentially unsafe use of the return value of `strlcpy` and `strlcat`. A result compared with the size given to the call (`if (len < 0 || len >= (int)sizeof(tmp))`, `n < cap ? n : cap - 1`), which detects truncation, is not reported.
* [**raptor.PointerSubtraction**](src/checkers/PointerSubtraction.cpp). Potential use of pointer subtraction to determine size.
* [**raptor.WriteIntoStackBuffer**](src/checkers/WriteIntoStackBuffer.cpp). Direct write into buffer allocated on the stack. As in osslsigncode (CVE-2026-39853: a signature's message digest, an ASN.1 string of any length, copied into `u_char mdbuf[EVP_MAX_MD_SIZE]` in six verifiers).
* [**raptor.CopyIgnoresSourceSize**](src/checkers/CopyIgnoresSourceSize.cpp). `memcpy`/`memmove` reads from a struct buffer field (`e->data`, `&s->s3->rrec.data[0]`, also through local pointers) whose own size field is known (`e->size`, `rrec.length`, `buf_len` for `buf`; not `count`, a reference or element count, nor a `size` next to `nelts`, an element size), but the copy length neither comes from that size nor is compared with it: a heap over-read, as in libexif (CVE-2020-0093) and Heartbleed (CVE-2014-0160). Constant lengths, lengths that are plain fields, in-place moves and positions computed from the size are not reported.
* [**raptor.TaintedLengthInCopy**](src/checkers/TaintedLengthInCopy.cpp). Length decoded from untrusted bytes (`n2s`, `ntohs`, `(p[0] << 8) | p[1]`...) used as the size of `memcpy` and friends without a bounds check, as in Heartbleed (CVE-2014-0160). Path-sensitive. A bound written on the pointer (`if (cp + n > end) goto fail;`, OpenSSH's `NEED(n)`) checks `n` too.
* [**raptor.UncheckedCursorWrite**](src/checkers/UncheckedCursorWrite.cpp). A write position advanced by data-dependent steps with no end check, in two shapes. *Unbounded writer*: a buffer passed to a function that advances a cursor in a loop (`table += table_size`) and writes through it without ever comparing it to a bound or counting down the room left, when the caller does not compare that buffer pointer either (libwebp CVE-2023-4863). *Run loop*: an outer loop checks an index against the end (`while (written < line)`), but an inner loop whose count comes from the data moves that index and writes (`for (k = 0; k < count; k++) bits[written++] = b;`) with no clamp on the way to it or inside it (FreeImage CVE-2026-118752, SAIL CVE-2026-40494). Loops bounded by a parameter, writers that count down their room or hand it to the callee that writes and move by what it reports using (`put(cfg, out, &room); out += room;`, wolfSSL `GetEchConfigsEx`), single offsets, constant runs and runs that test a position in their own condition are not reported.
* [**raptor.UncheckedSourceOffset**](src/checkers/UncheckedSourceOffset.cpp). A `memcpy`/`memmove` reading a buffer obtained from a call at an offset scaled by a loop counter (`base + i * k`), when nothing compares the loop bound, or a size computed from it, with anything: a heap over-read, as in DCMTK's NumberOfFrames copy (CVE-2026-97059).
* [**raptor.WStreamLengthUnsealed**](src/checkers/WStreamLengthUnsealed.cpp). FreeRDP/WinPR: `Stream_Length()` of a `wStream` that is filled by position (`Stream_Write_*`, `Stream_Seek`...) and never sealed (`Stream_SealLength`) is its capacity, not the data written; streams are followed across the file through fields, variables and parameters. As in the WebSocket Pong over-disclosure (CVE-2026-67292).
* [**raptor.AssertOnlyBound**](src/checkers/AssertOnlyBound.cpp). The only check on a length or offset is an assertion that compares it with a constant (`assert(blocksize <= sizeof(buf))`, `assert(SIZE_MAX - PAD >= size)`, `assert(len >= 0)`), and the value is then used as a size, an index or a pointer offset, or implicitly narrowed into a smaller type (`*d_len = s_len;` into a `uint16_t` after `assert(s_len < UINT16_MAX)`): release builds define `NDEBUG`, the check disappears and the value reaches the copy unchecked, as in libssh2's AES-GCM `ssh2_cipher_crypt` (CVE-2026-66033) libexpat's `expat_realloc` (CVE-2026-102633) and Apache Traffic Server's `mime_str_u16_set` (CVE-2026-58154, `ink_assert(s_len >= 0 && s_len < UINT16_MAX)` before storing the length in a 16-bit field). The assertion's arguments are lexed from the source, so builds with `NDEBUG` are covered too. Values also compared at run time (an `if`, a loop condition, a `?:` clamp), invariants between two run-time values (`assert(i < n)`), explicit, deliberate truncations (`(int)(n & MASK)`), test-framework assertions that run in every build (`assert_true`, a macro calling a function that returns), assertions that abort through the project's own handler in every build (OpenVPN's `ASSERT` calling `assert_failed()`, defined outside any `DEBUG`/`NDEBUG` `#if`) and `static_assert` are not reported. A narrower companion of `raptor.SuspiciousAssert`.
* [**raptor.FreedFieldNotCleared**](src/checkers/FreedFieldNotCleared.cpp). On an error path (an `if` branch that ends with a return, or a cleanup label reached by `goto` that the code above cannot fall into, up to its return) a function frees a field it filled in earlier (assigned, or its address passed to a call) and returns without clearing it, while the object outlives the call (a parameter, or a pointer handed back by a call that is not an allocator): whoever cleans the object up frees the pointer again, as in X.Org's `_CheckSetDoodad` (CVE-2026-88812, `free(doodad->text.text); return status;` with the doodad already attached to the geometry) open-isns's attribute decoders (CVE-2026-55995, `isns_free(value->iv_string); return 0;` when `buf_get()` fails) and FreeRDP's rdpsnd server (CVE-2026-63652, `out_free: free(context->client_formats); return error;`, freed again by `rdpsnd_server_context_free()`). Releases followed by an assignment of the field, by passing the object to a call (`free(obj)`), fresh allocations, stack objects and fields not filled in by the function are not reported, nor is a field in a union whose tag (another member of the union, or a field next to it in the struct holding it) the function sets only after the release, so that a cleanup dispatching on the tag leaves the field alone (wolfSSL `attr->value->value.asn1_string`, with `attr->value->type` set on success).
* [**raptor.DuplicateContainerInsert**](src/checkers/DuplicateContainerInsert.cpp). An existing object (a pointer to a struct, not one the function just allocated) is added to a long-lived container (a struct field or a variable) from several places in the file, and an add site has no membership guard: a state test is not one, so when two event paths both decide to add, the object is in the container twice and whoever drains it releases it twice, as in Apache httpd mod_http2 (CVE-2026-23918, `APR_ARRAY_PUSH(m->spurge, h2_stream *) = stream;` in `c1c2_stream_joined()` and in two branches of `m_stream_cleanup()`; an early RST_STREAM purges the stream twice) and Tor's KIST scheduler (CVE-2018-0491, `smartlist_pqueue_add(channels_pending, ..., chan)` in two state transitions, use after free). An add site is a call with a push/add/append/insert/enqueue/prepend name component (container first, object later) or an assignment through the slot such a call returns (`*(T *)apr_array_push(c) = x`); keyed containers (hash, map, table, tree...) and calls to helpers defined in the file are not. Guards: a condition, before the add in its function, that mentions the object and the container or a local read from it (`if (s == stream)`, `smartlist_contains(cp, x)`); a condition on the object's position field (the `offsetof` field the add passes, or a field named `*idx`/`*index`/`queued`/`in_*`); or the object removed or popped from the same container first.
* [**raptor.PostDecrementOffByOne**](src/checkers/PostDecrementOffByOne.cpp). A loop that writes or reads through a pointer stops on a post-decremented counter tested for going negative (`if (term-- < 0) break;`, `while (n-- >= 0)`): the test sees the value before the decrement, so the body runs one time more than the counter allows, one element past the end, as in HTSlib's CRAM `byte_array_stop` decoder (CVE-2026-31969). `--n < 0`, `n-- <= 0`, `n-- > 0` and loops that touch no memory are not reported.
* [**raptor.NegativeLengthUnchecked**](src/checkers/NegativeLengthUnchecked.cpp). A signed length read from the data (an out-parameter such as `readVarint32(p, &len, end)`, or a call result) is checked only from above, in a signed comparison (`if (len > end - p) throw`), then used as a size or a pointer advance: a negative value passes the check and becomes a huge `size_t`, as in Apache Thrift's `THeaderTransport::readString` (CVE-2026-58662). A comparison with 0 or 1, an unsigned comparison, a bound from below on the path that uses the length (`if (n >= need) use`, `while (i < n)`), lengths kept in fields, narrower unsigned values widened, string lengths (`(long)strlen(s)`) and out-parameters of calls that read no byte buffer (`key_sizes(ctx, &keyLen)`, a table lookup rather than a decoder) are not reported.
* [**raptor.UnboundedCopyToStackArray**](src/checkers/UnboundedCopyToStackArray.cpp). A string of unknown length is copied into a fixed-size local array, or a parameter declared as an array (`char ynot[]`, the caller's fixed buffer), (`strcpy`, `strcat`, `sprintf` with a `%s` that has no precision, `vsprintf`) and nothing in the function compares its length (`strlen(s)`, or a local set from it) with anything: a stack overflow, as in editorconfig-core-c's `ec_glob` (CVE-2026-40489) GPAC's NHML demuxer (CVE-2026-27821, an XML attribute copied into `szXmlHeaderEnd[1000]`), INDI's lilxml (CVE-2026-71979, unbounded tag names formatted into the caller's `char ynot[]`) and THC-Hydra's NTLM handlers (CVE-2026-56766, a base64 Type-3 response carrying the server's domain `sprintf`ed into `char buffer[...]` by the IMAP, POP3, NNTP and SMTP modules). Literals, tables of literals, locals only set to literals and source arrays that fit are not reported.
* [**raptor.SizeFieldIgnoresCapacity**](src/checkers/SizeFieldIgnoresCapacity.cpp). A (pointer, size) pair is set up in one block to describe another object's buffer (`entry->data = persistent->bmpData; entry->size = w * h * 4;`), but the size neither comes from that buffer's capacity field (`bmpSize`) nor is compared with it, so whoever uses the pair reads or writes past the end, as in FreeRDP's persistent cache v2 parser (CVE-2026-111381). Constant sizes, sizes derived from the capacity or from the field's own old value, fresh allocations, buffers built in the same function, buffers whose owner is passed to a call (regex captures), and functions that compare the capacity with anything are not reported. A size pairs only with the nearest assignment of its pointer.

#### integer overflows

* [**raptor.IntegerWraparound**](src/checkers/IntegerWraparound.cpp). Potential integer wraparound errors: an allocation size computed with `*` or `+`, and bounds checks like `x > MAX || x + n > MAX` that the wraparound defeats. Size arithmetic in `size_t` is reported as written (it wraps on 32-bit targets, or from a negative `int`); sums and products in `int` or narrower whose operands cannot overflow it (`xkb->max_key_code + 1` with an 8-bit key code, `min(count, 6) + 1`) are not. Nor are constants, including `static const` variables with constant initialisers (`malloc(kFileBufferSize * 2)`), or `size_t` sums of string lengths and constants (`strlen(a) + strlen(b) + 1`, or `size_t` locals set from `strlen()` and not changed after): strings in memory cannot add up past `SIZE_MAX`. The same sum in `int`, as in radare2's `r_str_append` (CVE-2026-14761), is reported.
* [**raptor.UncheckedAllocProduct**](src/checkers/UncheckedAllocProduct.cpp). An allocation sized by a 32-bit product of two run-time factors (`stride * height`, `w * h`), written in the call or reaching it through up to three assignments of locals, fields or array elements (`size[x] = stride[x] * h; ... recalloc(p, size[x], 1, 16)`), with no overflow guard on the factors (`a > INT_MAX / b`, `*_mul_overflow`, `av_size_mult`, or both factors bounded from above by constants whose product fits, before the allocation: an `if (w > 4096 || h > 4096) return`, a clamp or an enclosing `if (w < 4096 && h < 4096)`; a positivity check such as `if (w <= 0 || h <= 0) return` does not count): when the product wraps, whatever fills the buffer writes past it. Products of fields that the file validates where it sets them (a division check such as `if (cp->tw > 65535 / cp->th)`, or the same product computed in 64 bits, in the function that assigns the fields) are not reported either. Products computed in `size_t`, products of factors too narrow to wrap (8-bit by 16-bit) and constant factors do not match. As in FFmpeg's raw RGB reshuffle (CVE-2026-70628, CVE-2026-70632), OpenJPEG's `opj_image_create` (CVE-2016-9118), libtiff's RGBA strip reader on 32-bit builds (CVE-2019-17546) libsixel's high-color encoder (CVE-2026-44636, `(size_t)(width * height * 3)`) libde265's image planes (CVE-2026-49346, `ALLOC_ALIGNED_16(stride * height + MEMORY_PADDING)`) and libsmb2's DCE/RPC conformant arrays (CVE-2026-115505, `smb2_alloc_data(..., carray->max_count * elem_size)` with a count from the wire), GEGL's RGBE reader (CVE-2026-18300, `g_new (gfloat, x_axis.size * y_axis.size * RGBE_NUM_RGBE)` with the dimensions from the file header), FreeRDP's AVC444 buffers (CVE-2026-55191, `piDstSize[x] = piDstStride[x] * padDstHeight;` then two `winpr_aligned_recalloc`s) and KissFFT's `kiss_fftndr_alloc` (CVE-2026-41445, an `int` product inside `ntmp`, rounded into `memneeded`, passed to `malloc`).
* [**raptor.TruncatedProduct**](src/checkers/TruncatedProduct.cpp). A product of two run-time values, computed in `int` by the integer promotions, implicitly stored into or returned as a type narrower than `int` that cannot hold it (the operands' declared widths add up to more than the destination's): a count or size wraps to a small value while the code that uses it still counts to the full product, as in libmikmod's DSM and OKT loaders (CVE-2026-105837, CVE-2026-105839, `of.numtrk = of.numchn * of.numpat;` with a 16-bit `numtrk`, then `AllocTracks()`) and iccDEV's calculator (CVE-2026-21688, `return (data.select.v1+1)*(data.select.v2+1);` as an `icUInt16Number` stack depth). Explicit casts (the fixes check the wide value, then `(UWORD)numtrk`), products into `int` or wider, products that fit (`u8 * u8` into 16 bits) and constant factors are not reported.
* [**raptor.NarrowProductWidened**](src/checkers/NarrowProductWidened.cpp). A product computed in 32 bits or less and only then converted to a 64-bit type: by an explicit cast of the product itself (`(uint64_t)(w * 3)`, constant factors included) by storing a product of two run-time values into a 64-bit variable or field (`uint64_t n = a * b;`, a `size_t` field set from an `int` product), or by using a product of three run-time values or more as a pointer offset (`wavbuf += nx * ny * wcount;`; two-factor row addressing such as `base + y * stride` is left alone). The conversion says the full value is wanted, but the multiplication has already wrapped, so size checks and offsets built on it pass with a small number, as in OpenEXR's PXR24 decoder (CVE-2026-34380, `if (nDec + (uint64_t) (w * 3) > outSize)`) and PIZ decoder (CVE-2026-34588, `wavbuf += nx * ny * wcount;`) and image channels (CVE-2026-41142, `_numPixels = _pixelsPerRow * _pixelsPerColumn;`) and iccDEV's sparse matrix arrays (CVE-2026-21486, `icUInt64Number nNeededSize = nBytesPerMatrix * nNumMatrices;`). Products widened before multiplying (`(uint64_t) w * 3`), operands too narrow to wrap and products guarded by a division check or an overflow helper are not reported.
* [**raptor.UncheckedUnsignedSubtraction**](src/checkers/UncheckedUnsignedSubtraction.cpp). An unsigned length checked from below (`if (len < hdr + 6) return;`, or an enclosing `if (len >= 4)`) and then reduced by more than the check allows (`len - (hdr + 8)`, `len - 16 - 1`): when the value lies between the two, the difference wraps to a huge length or, promoted to `int`, a negative index, as in SWUpdate's multipart parser (CVE-2026-28525, `io->len - (mp_stream->boundary.len + 8)` after a check for `+ 6`) and Mongoose's TLS record reader (CVE-2026-73252, `msg[msgsz - 16 - 1]` after `if (msgsz < 16)`). Guards are read as linear relations (`desclen < cols - 2` bounds `cols - 3 - desclen`); the strongest one before the subtraction counts. Values never checked from below, signed values, other subtracted terms and values reassigned after the check are not reported.
* [**raptor.CapacityUpdatedBeforeRealloc**](src/checkers/CapacityUpdatedBeforeRealloc.cpp). A size or dimension field (a size field of the buffer, or `width`, `height`, `count`, `capacity`, ...) set before another field of the same object, the buffer, is reallocated (`*realloc*`, `*recalloc*`), on the same path, when the failure branch of the reallocation returns without restoring it: the object then claims a capacity its old buffer does not have, as in FreeRDP's ClearCodec vBar and glyph caches (CVE-2026-33984, `vBarEntry->size = vBarEntry->count;` before `winpr_aligned_recalloc(vBarEntry->pixels, ...)`; CVE-2026-33985, `glyphEntry->count = nWidth * nHeight;`) and H.264 YUV buffers (CVE-2026-33986, `h264->width`/`height` set before the planes). Fields restored on failure, assignments in another branch, unrelated fields and failure branches that end the program are not reported.
* [**raptor.LoopBoundIgnoresCapacityParam**](src/checkers/LoopBoundIgnoresCapacityParam.cpp). A function receiving an output buffer and its capacity (an integer parameter or an in/out count named like a size: `nVectorSize`, `*frame_cnt`, `dst_len`) fills the buffer in a loop (`D[i] = ...`, `D[i].f = ...`) bounded by something else that is never bounded by the capacity, as in iccDEV's `GetValues` (CVE-2026-25584, CVE-2026-30987: `if (nVectorSize > m_nSize) return false;`, a check in the wrong direction, then `for (i=0; i<m_nSize; i++) DstVector[i] = ...`) and pjsip's Opus parser (CVE-2026-29068: `num_frames` from the packet, `*frame_cnt` ignored). The capacity in the loop condition, an exit on it inside the loop, a check before the loop in the right direction, a clamp, a bound initialised from the capacity, a bound that only ever holds constants, a counter set to 0 and incremented at most once per iteration of a (non-nested) loop over the capacity, read-only buffers and functions without a capacity parameter are not reported. A pointer parameter that is subscripted (`count[bits]`) is an array, not a capacity.
* [**raptor.UnsafeStrlen**](src/checkers/UnsafeStrlen.cpp). Casting the return value of `strlen` to short might be dangerous.
* [**raptor.IntegerTruncation**](src/checkers/IntegerTruncation.cpp). Potential integer truncation errors.
* [**raptor.SignedUnsignedConversion**](src/checkers/SignedUnsignedConversion.cpp). Potential signed/unsigned conversion errors.
* [**raptor.IncorrectUnsignedComparison**](src/checkers/IncorrectUnsignedComparison.cpp). Checking if an unsigned variable is negative.

#### format strings

* [**raptor.FormatStringBugs**](src/checkers/FormatStringBugs.cpp). Potential format string bugs. A `const char` array initialized with a literal (`static const char usage[] = "..."`) and the format parameter of a wrapper with a `format(printf, ...)` attribute, whose callers' formats the compiler checks, are not reported; unannotated wrappers still are.

#### memory management

* [**raptor.InsecureApiAlloca**](src/checkers/InsecureApiAlloca.cpp). Use of the potentially insecure API function `alloca`.
* [**raptor.UseAfterFree**](src/checkers/UseAfterFree.cpp). A pointer used (`p->f`, `p[i]`, `*p`, returned, or passed to a call) after it was released with no reassignment in between. Releases are `free()` and its C relatives, allocator hooks called through a pointer, and library destructors defined in the translation unit whose body releases the argument. Lists walked by reassignment (`s = s->next`), out-parameters that may set the pointer again (`f(&p)`), paths that never return, the released argument of a second release (`raptor.DoubleFree`'s report) and releases nested in another call's arguments are not reported.
* [**raptor.DoubleFree**](src/checkers/DoubleFree.cpp). The same pointer released twice with no reassignment in between, on any path through the function (loops included). Releases are `free()` and its C relatives (`g_free`, `CRYPTO_free`/`OPENSSL_free`, `av_free`), library destructors named `*_free`/`*_FREE`/`*Free` with a single pointer argument (when defined in the translation unit, only if their body releases it), and allocator hooks called through a pointer named `*free` (libssh2's `SSH2_FREE(session, p)`, `session->free(p, &session->abstract)`). A call that receives `&p` and is defined here but can return without setting `*p` leaves `p` possibly freed until the code reads it or another out-parameter of that call. As in libssh2's `sftp_open` (CVE-2026-66032, `SSH2_FREE(session, data)` then a failed `sftp_packet_require(..., &data, ...)` and `SSH2_FREE(session, data)` again) and mongo-c-driver's OCSP responder loop (CVE-2026-84964, `retry: OCSP_REQUEST_free(req);` reached on the next URL before a new request is made). Releasers that clear the pointer (`av_freep(&p)`), destructors that also take an address (`Curl_req_free(&data->req, data)`) and non-blocking releases retried until done (`while (libssh2_channel_free(ch) == LIBSSH2_ERROR_EAGAIN)`) are not reported.
* [**raptor.IncorrectUseOfFree**](src/checkers/IncorrectUseOfFree.cpp). Calling `free` on memory not in the heap.
* [**raptor.UncheckedRetMalloc**](src/checkers/UncheckedRetMalloc.cpp). Unchecked return code of `malloc`, `calloc`, `realloc`, etc. An allocation passed to a helper whose body tests that parameter for NULL in an `if` (OpenVPN's `check_malloc_return(p)` and `ALLOC_OBJ`) counts as checked.
* [**raptor.PutenvStackVar**](src/checkers/PutenvStackVar.cpp). Call to `putenv` with a stack-allocated variable.
* [**raptor.RetStackAddress**](src/checkers/RetStackAddress.cpp). Potential return of the address of a stack-allocated variable.
* [**raptor.MismatchedMemoryManagement**](src/checkers/MismatchedMemoryManagement.cpp). `free()` of memory known not to come from `malloc()` and its relatives on the current path: a local or global variable, a string literal, `alloca()` or a compound literal. Memory of unknown origin (parameters, fields, call results: every teardown function) and pointers that are NULL on the path are not reported.
* [**raptor.MismatchedMemoryManagementCpp**](src/checkers/MismatchedMemoryManagementCpp.cpp). A release from the wrong family: `free()` of `new` memory, `delete` of `malloc()` or `new[]` memory, `delete[]` of scalar `new` memory, or any of them on memory that is never heap memory (a variable, a string literal). Memory of unknown origin (destructors' members, parameters) and NULL pointers are not reported.
* [**raptor.MemoryAddressExposure**](src/checkers/MemoryAddressExposure.cpp). Potential exposure of underlying memory addresses.

#### command injection

* [**raptor.CommandInjection**](src/checkers/CommandInjection.cpp). Potential OS command injection via `system` or `popen`.

#### race conditions

* [**raptor.InsecureApiAccessStat**](src/checkers/InsecureApiAccessStat.cpp). Use of insecure API functions `access`, `stat`, `lstat`, etc.
* [**raptor.InsecureApiMktempTmpnamTempnam**](src/checkers/InsecureApiMktempTmpnamTempnam.cpp). Use of insecure API functions `mktemp`, `tmpnam`, `tempnam`.
* [**raptor.InsecureApiSignal**](src/checkers/InsecureApiSignal.cpp). Use of insecure API function `signal`.

#### privilege management

* [**raptor.IncorrectOrderSetuidSetgid**](src/checkers/IncorrectOrderSetuidSetgid.cpp). Privilege management functions called in the wrong order.
* [**raptor.UncheckedRetSetuidSeteuid**](src/checkers/UncheckedRetSetuidSeteuid.cpp). Unchecked return code of `setuid` and `seteuid`. A call used as a condition (`if (setuid(uid)) fatal(...)`) counts as checked.

#### denial of service

* [**raptor.RegexDos**](src/checkers/RegexDos.cpp). Regular expression that may exhibit exponential runtime and lead to ReDoS.

#### miscellaneous

* [**raptor.IncorrectUseOfMemset**](src/checkers/IncorrectUseOfMemset.cpp). Wrong order of arguments to `memset`.
* [**raptor.InsecureApiRandSrand**](src/checkers/InsecureApiRandSrand.cpp). Use of potentially insecure API functions `rand` and `srand`.
* [**raptor.OverlappingSourceDestination**](src/checkers/OverlappingSourceDestination.cpp). Source and destination overlap in copy functions.
* [**raptor.SuspiciousAssert**](src/checkers/SuspiciousAssert.cpp). Potentially invalid size check due to use of assertion macros.
* [**raptor.InterestingApiCalls**](src/checkers/InterestingApiCalls.cpp). Calls to interesting and potentially insecure API functions.
* [**raptor.UncheckedRetScanf**](src/checkers/UncheckedRetScanf.cpp). Unchecked return code of functions in the `scanf` family.
* [**raptor.IgnoredStatusReturn**](src/checkers/IgnoredStatusReturn.cpp). Discarded result of a function defined in the same file that reports success or failure: either every `return` is a constant such as `BROTLI_TRUE`/`BROTLI_FALSE` (or forwards another status), as in Broccoli2Shell (CVE-2026-111497, Brotli <= 1.0.9 `DecodeLiteralBlockSwitch`), or its integer or pointer result is checked at most of its other call sites (`ret = f(); if (ret)`, `if ((p = f()) == NULL)`), as in Mbed TLS `mbedtls_lms_verify` (CVE-2025-49600) and libmicrodns `rr_decode` (CVE-2020-6072). Not reported when the file discards the result more often than it checks it, for teardown functions (close, cleanup, free, final...), or for cleanup on a path that is already failing (`f(); break;`, `f(); return result;`). A test only counts as a check when the `if` acts on it (leaves, assigns, or calls an error/log function): `if (wrapped(s)) reset(s);` uses a predicate. A result stored in a variable counts only if a condition reads it after the store. Code translators (every `return` inside one `switch` on an unmodified parameter, like brotli's `SaveErrorCode`) are not status functions. `(void)f()` opts out.
* [**raptor.InsecureApiAto**](src/checkers/InsecureApiAto.cpp). Use of potentially insecure API functions `atoi`, `atol`, `atof`.
* [**raptor.HighEntropyAssignment**](src/checkers/HighEntropyAssignment.cpp). Assignment of a high-entropy value that might be a secret. Mostly printable text with raw control bytes in it (length-prefixed tables like brotli's RFC 7932 transforms) is not reported; binary keys still are.
* [**raptor.ArgvEnvpAccess**](src/checkers/ArgvEnvpAccess.cpp). Command-line argument or environment variable access.
* [**raptor.MissingDefaultInSwitch**](src/checkers/MissingDefaultInSwitch.cpp). Missing default case in a switch statement.
* [**raptor.MissingBreakInSwitch**](src/checkers/MissingBreakInSwitch.cpp). Missing break or equivalent in a switch statement.
* [**raptor.MissingReturn**](src/checkers/MissingReturn.cpp). Missing return statement in non-void function.
* [**raptor.Typos**](src/checkers/Typos.cpp). Potential typos with security implications: `=` or a bitwise `&`/`|` in an `if` condition, `=+`, comparisons used as statements, `(E op E)`, empty `if`/`for` bodies, octal array sizes. Flag tests against a constant mask (`if (flags & (A | B))`) or a shifted bit (`mask & (1u << i)`), masked values compared on either side (`(a & m) != (b & m)`), masks built as call arguments, `|` chains and `?:` branches included (`if (lookup(t, A | B | C))`), flags handed to a macro whose own `if` tests them (OpenVPN `msg(M_WARN | M_ERRNO, ...)`), assignments in their own parentheses (`if ((p = next()))`, `!(bio = BIO_new(...))`) and operands spelled differently that expand to the same value (`IS_ENABLED(A) || IS_ENABLED(B)`) are not reported.

### Noisy

Potentially too noisy for general use. It is part of `raptor`; skip it with `-Xclang -analyzer-disable-checker=raptor.BadWords`.

#### generic

* [**raptor.BadWords**](src/checkers/BadWords.cpp). Keywords and comments that suggest the presence of bugs.

#### Audit lists

Some ports of generic semgrep rules report every instance of a pattern
rather than a bug, and on real projects they produce hundreds of findings per
file: `raptor.IntegerTruncation`, `raptor.SignedUnsignedConversion`,
`raptor.InterestingApiCalls`, `raptor.HighEntropyAssignment`,
`raptor.PointerSubtraction` and `raptor.ArgvEnvpAccess` (every use of `argv`
or `envp`). They are useful for reviewing code by hand; for
CVE hunting, disable them, e.g.
`-Xclang -analyzer-disable-checker=raptor.IntegerTruncation,raptor.SignedUnsignedConversion,raptor.InterestingApiCalls,raptor.HighEntropyAssignment,raptor.PointerSubtraction,raptor.ArgvEnvpAccess`.
The precise rules above (`raptor.TruncatedProduct`, `raptor.NarrowProductWidened`,
`raptor.UncheckedAllocProduct`, ...) cover the integer bug shapes behind real
CVEs.


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
