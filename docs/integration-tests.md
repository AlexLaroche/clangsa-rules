# Integration tests

One row per real vulnerability in `tests/integration/`; see the README ("Integration tests") for the JSON format and how to run `tools/run_integration.py`.

## Cases

| Case | CVE | Checker | Vulnerable → fixed commit |
|------|-----|---------|---------------------------|
| `heartbleed` | CVE-2014-0160 | `raptor.TaintedLengthInCopy` | openssl `0d7717f` → `96db902` (1.0.1g) |
| `heartbleed-source-size` | CVE-2014-0160 | `raptor.CopyIgnoresSourceSize` | openssl `0d7717f` → `96db902` (1.0.1g) |
| `openjpeg-image-create` | CVE-2016-9118 | `raptor.UncheckedAllocProduct` | OpenJPEG `83342f2` → `c22cbd8` (2.2.0) |
| `tor-kist-pending-double-add` | CVE-2018-0491 | `raptor.DuplicateContainerInsert` | Tor `df312b3` → `cb5654f` (0.3.3.2-alpha) |
| `libtiff-rgba-strip` | CVE-2019-17546 | `raptor.UncheckedAllocProduct` | libtiff `2218055` → `4bb584a` (4.1.0, 32-bit build) |
| `libexif-save-entry` | CVE-2020-0093 | `raptor.CopyIgnoresSourceSize` | libexif `154189b` → `5ae5973` (0.6.22) |
| `libmicrodns-rr-decode` | CVE-2020-6072 | `raptor.IgnoredStatusReturn` | libmicrodns `0103f40` → `89de67f` (0.1.2) |
| `libxml2-xinclude-uri-use-after-free` | CVE-2022-49043 | `raptor.UseAfterFree` | libxml2 `afc7e3a` → `5a19e21` |
| `webp-huffman` | CVE-2023-4863 | `raptor.UncheckedCursorWrite` | libwebp `7ba44f8` → `902bc91` (1.3.2) |
| `rlottie-gradient-opacity-size` | CVE-2025-0634 | `raptor.UncheckedLengthDifference` | rlottie `e3026b1` → `507ea02` |
| `netxduo-web-http-put-length-underflow` | CVE-2025-0727 | `raptor.UncheckedLengthDifference` | NetX Duo `1f75e3d` → `c78d650` |
| `netxduo-http-put-length-underflow` | CVE-2025-2259 | `raptor.UncheckedLengthDifference` | NetX Duo `bd5d12e` → `fb3195b` |
| `openssl-http-proxy-host-strncpy` | CVE-2025-9232 | `raptor.UnterminatedStringStrncpy` | openssl `ca3539e` → `bbf38c0` |
| `mupen64plus-is-viewer-sum-wrap` | CVE-2025-9688 | `raptor.SumBoundsCheckWraps` | mupen64plus-core `e170c40` → `3984137` |
| `ndpi-address-cache-fscanf` | CVE-2025-25066 | `raptor.InsecureApiScanf` | nDPI `e946f49` → `678697b` |
| `redis-check-aof-filepath-copy` | CVE-2025-27151 | `raptor.MemcpyLengthUnboundedByDest` | Redis `7f9212e` → `643b5db` |
| `kissfft-alloc-twiddle-size` | CVE-2025-34297 | `raptor.IntegerWraparound` | kissfft `7bce415` → `1b08316` |
| `libcoap-host-name-addrstr` | CVE-2025-34468 | `raptor.MemcpyLengthUnboundedByDest` | libcoap `1cae046` → `30db3ea` |
| `mbedtls-lms-verify` | CVE-2025-49600 | `raptor.IgnoredStatusReturn` | Mbed TLS `caaffc1` → `ae449bf` (3.6.4, with `MBEDTLS_LMS_PRIVATE`) |
| `mbedtls-lms-import-public-key-type` | CVE-2025-49601 | `raptor.FixedOffsetReadNoLengthCheck` | Mbed TLS `d9c1417` → `548e2db` (3.6.4) |
| `mbedtls-pem-padding-empty-input` | CVE-2025-52497 | `raptor.EmptyLengthDecrement` | Mbed TLS `9325883` → `6165e71` (3.6.4) |
| `riot-l2filter-add-assert-length` | CVE-2025-53888 | `raptor.AssertOnlyBound` | RIOT `41e2da1` → `f6f7de4` |
| `rathena-move-char-slot-index` | CVE-2025-58750 | `raptor.UncheckedInputIndex` | rAthena `0d89ae0` → `0cc348b` |
| `suricata-shorten-string-empty-output` | CVE-2025-59149 | `raptor.EmptyLengthDecrement` | Suricata `d590fdf` → `38a2cba` (8.0.1) |
| `cryptolib-kinit-system-command` | CVE-2025-59534 | `raptor.CommandInjection` | CryptoLib `b7ae4a9` → `3ccb1b3` |
| `fastdds-cdrmessage-read-data-sum-wrap` | CVE-2025-62601 | `raptor.SumBoundsCheckWraps` | Fast DDS `afc30f9` → `3542185` |
| `bacnet-npdu-expected-reply-offset` | CVE-2025-66624 | `raptor.FixedOffsetReadNoLengthCheck` | bacnet-stack `11efd69` → `9378f7d` |
| `capstone-skipdata-insn-bytes` | CVE-2025-67873 | `raptor.MemcpyLengthUnboundedByDest` | capstone `2c77971` → `cbef767` |
| `coturn-aes-key-rand` | CVE-2025-69217 | `raptor.InsecureApiRandSrand` | coturn `4e0d21e` → `88ced47` |
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
| `oiio-dpx-swap-rgba-index-overflow` | CVE-2026-43909 | `raptor.SignedLoopCounterOverflow` | OpenImageIO `50962c9` → `a250675` (3.0.18, 3.1.13) |
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
| `linux-io-edgeport-tx-credits` | CVE-2026-68365 | `raptor.UncappedCreditReplenish` | Linux `55645e4` → `faaddd8` (io_edgeport, stable backports) |
| `ffmpeg-raw-rgb` | CVE-2026-70628 | `raptor.UncheckedAllocProduct` | FFmpeg `3538578` → `d32b387` |
| `indi-lilxml-error-format` | CVE-2026-71979 | `raptor.UnboundedCopyToStackArray` | INDI `3220880` → `96bbd7f` |
| `mongoose-tls-record-size` | CVE-2026-73252 | `raptor.UncheckedUnsignedSubtraction` | Mongoose `7fa830f` → `758e301` |
| `mongo-c-driver-ocsp-request-double-free` | CVE-2026-84964 | `raptor.DoubleFree` | mongo-c-driver `aba7244` → `7e4c665` |
| `ndpi-json-string-escape` | CVE-2026-86098 | `raptor.LoopGuardOutpacedByWrites` | nDPI `d56ab36` → `94e82c1` |
| `xserver-xkb-doodad-text-free` | CVE-2026-88812 | `raptor.FreedFieldNotCleared` | X.Org xserver `effe0ba` → `0d1b1b0` |
| `dcmtk-concatenation` | CVE-2026-97059 | `raptor.UncheckedSourceOffset` | DCMTK `30cc153` → `18379d5` |
| `libexpat-realloc-assert-overflow` | CVE-2026-102633 | `raptor.AssertOnlyBound` | libexpat `cccede3` → `209801d` |
| `mikmod-dsm-numtrk-product` | CVE-2026-105837 | `raptor.TruncatedProduct` | libmikmod `08d7d21` → `a125eab` |
| `mikmod-okt-numtrk-product` | CVE-2026-105839 | `raptor.TruncatedProduct` | libmikmod `e7c6c9e` → `097b692` |
| `freerdp-persistent-cache-v2` | CVE-2026-111381 | `raptor.SizeFieldIgnoresCapacity` | FreeRDP `b99ed85` → `bb10797` (3.32.0) |
| `broccoli2shell` | CVE-2026-111497 | `raptor.IgnoredStatusReturn` | brotli `e61745a` (1.0.9) → `50a9b70` (1.0.10) |
| `libsmb2-dcerpc-carray-alloc` | CVE-2026-115505 | `raptor.UncheckedAllocProduct` | libsmb2 `312feca` → `a79f691` (6.3) |
| `freeimage-iff-pbm-rle` | CVE-2026-118752 | `raptor.UncheckedCursorWrite` | FreeImage `5af27d0` → `38fbe82` (3.19.22) |
| `nginx-quic-create-stream-drain` | CVE-2026-121810 | `raptor.ReusableConnectionWhileBusy` | nginx `1d1d861` → `b5252da` (1.31.9, 1.30.7) |
| `nginx-h2-send-window-refund` | CVE-2026-123007 | `raptor.UncappedCreditReplenish` | nginx `e39708e` → `e27f5fa` (1.31.9, 1.30.7) |
| `ruby-case-map-sharp-s` | GHSA-34m4-m9fh-gqp5 (no CVE yet) | `raptor.LoopGuardOutpacedByWrites` | Ruby `cdd499e` → `b841d6f` (3.4.13, 4.0.10, 3.3.14) |
| `ruby-bbuf-write-int-length` | GHSA-3p8q-wmhx-vm2w (no CVE yet) | `raptor.NarrowedCopyLength` | Ruby `8e6b79e` → `57c2469` (3.4.13, 4.0.10, 3.3.14) |
| `php-mcrypt-size-t-to-int` | PHP bugs #72551, #72552 (no CVE) | `raptor.NarrowedCopyLength` | php-src `2ca8d85` → `3810e7b` (7.0.9) |
| `ell-tls-secret-memset` | ell `a3f0cb5` (no CVE) | `raptor.ElidableSecretWipe` | ell `fb4e544` → `a3f0cb5` |
| `netatalk-afppasswd-key-memset` | Netatalk `043435c` (no CVE) | `raptor.ElidableSecretWipe` | Netatalk `33ed6f8` → `043435c` |
| `wine-comctl32-mbtowc-byte-count` | Wine `bd7ec9a` (no CVE) | `raptor.WideCountInBytes` | Wine `db62dde` → `bd7ec9a` (2005) |
| `freebsd-ncal-swprintf-byte-count` | FreeBSD r300005, Coverity CID 1007605/1007606 | `raptor.WideCountInBytes` | freebsd-src `e5d4b0f` → `b74e373` |
| `libdogecoin-urandom-assert-only` | libdogecoin `b7891cf`, CWE-330 (no CVE) | `raptor.UncheckedRandomRead` | libdogecoin `4cb1ccb` → `b7891cf` |
| `netatalk-uam-random-short-read` | Netatalk `2721b62` (no CVE) | `raptor.UncheckedRandomRead` | Netatalk `771913a` → `2721b62` |
| `nginx-h2-create-stream-reusable` | CVE-2026-123633 | `raptor.ReusableConnectionWhileBusy` | nginx `2a3a19c` → `2df48a5` (1.31.9, 1.30.7) |
| `nginx-resolver-cancel-free` | CVE-2026-123634 | `raptor.FreeAfterFailedUnlink` | nginx `8492a8b` → `e39708e` (1.31.9, 1.30.7) |

## Integration tests per rule

| Checker | Integration cases |
|---------|-------------------|
| `raptor.UncheckedAllocProduct` | 10 |
| `raptor.AssertOnlyBound` | 4 |
| `raptor.NarrowProductWidened` | 4 |
| `raptor.UnboundedCopyToStackArray` | 4 |
| `raptor.CapacityUpdatedBeforeRealloc` | 3 |
| `raptor.FreedFieldNotCleared` | 3 |
| `raptor.IgnoredStatusReturn` | 3 |
| `raptor.LoopBoundIgnoresCapacityParam` | 3 |
| `raptor.MemcpyLengthUnboundedByDest` | 3 |
| `raptor.TruncatedProduct` | 3 |
| `raptor.UncheckedCursorWrite` | 3 |
| `raptor.UncheckedLengthDifference` | 3 |
| `raptor.CopyIgnoresSourceSize` | 2 |
| `raptor.DoubleFree` | 2 |
| `raptor.DuplicateContainerInsert` | 2 |
| `raptor.ElidableSecretWipe` | 2 |
| `raptor.EmptyLengthDecrement` | 2 |
| `raptor.FixedOffsetReadNoLengthCheck` | 2 |
| `raptor.IntegerWraparound` | 2 |
| `raptor.LoopGuardOutpacedByWrites` | 2 |
| `raptor.NarrowedCopyLength` | 2 |
| `raptor.ReusableConnectionWhileBusy` | 2 |
| `raptor.SumBoundsCheckWraps` | 2 |
| `raptor.UncappedCreditReplenish` | 2 |
| `raptor.UncheckedRandomRead` | 2 |
| `raptor.UncheckedUnsignedSubtraction` | 2 |
| `raptor.UseOfSourceSizeInCopy` | 2 |
| `raptor.WideCountInBytes` | 2 |
| `raptor.CommandInjection` | 1 |
| `raptor.FreeAfterFailedUnlink` | 1 |
| `raptor.IncorrectUseOfSizeof` | 1 |
| `raptor.InsecureApiRandSrand` | 1 |
| `raptor.InsecureApiScanf` | 1 |
| `raptor.NegativeLengthUnchecked` | 1 |
| `raptor.PostDecrementOffByOne` | 1 |
| `raptor.SignedLoopCounterOverflow` | 1 |
| `raptor.SizeFieldIgnoresCapacity` | 1 |
| `raptor.TaintedLengthInCopy` | 1 |
| `raptor.UncheckedInputIndex` | 1 |
| `raptor.UncheckedSourceOffset` | 1 |
| `raptor.UnterminatedStringStrncpy` | 1 |
| `raptor.UseAfterFree` | 1 |
| `raptor.WStreamLengthUnsealed` | 1 |
| `raptor.WriteIntoStackBuffer` | 1 |
| `raptor.ArgvEnvpAccess` | 0 |
| `raptor.BadWords` | 0 |
| `raptor.FormatStringBugs` | 0 |
| `raptor.HighEntropyAssignment` | 0 |
| `raptor.IncorrectOrderSetuidSetgid` | 0 |
| `raptor.IncorrectUnsignedComparison` | 0 |
| `raptor.IncorrectUseOfFree` | 0 |
| `raptor.IncorrectUseOfMemset` | 0 |
| `raptor.IncorrectUseOfStrncat` | 0 |
| `raptor.InsecureApiAccessStat` | 0 |
| `raptor.InsecureApiAlloca` | 0 |
| `raptor.InsecureApiAto` | 0 |
| `raptor.InsecureApiGets` | 0 |
| `raptor.InsecureApiMktempTmpnamTempnam` | 0 |
| `raptor.InsecureApiSignal` | 0 |
| `raptor.InsecureApiSprintfVsprintf` | 0 |
| `raptor.InsecureApiStrcpyStrcat` | 0 |
| `raptor.IntegerTruncation` | 0 |
| `raptor.InterestingApiCalls` | 0 |
| `raptor.MemoryAddressExposure` | 0 |
| `raptor.MismatchedMemoryManagement` | 0 |
| `raptor.MismatchedMemoryManagementCpp` | 0 |
| `raptor.MissingBreakInSwitch` | 0 |
| `raptor.MissingDefaultInSwitch` | 0 |
| `raptor.MissingReturn` | 0 |
| `raptor.OffByOne` | 0 |
| `raptor.OverlappingSourceDestination` | 0 |
| `raptor.PointerSubtraction` | 0 |
| `raptor.PutenvStackVar` | 0 |
| `raptor.RegexDos` | 0 |
| `raptor.RetStackAddress` | 0 |
| `raptor.SignedUnsignedConversion` | 0 |
| `raptor.SuspiciousAssert` | 0 |
| `raptor.Typos` | 0 |
| `raptor.UncheckedRetMalloc` | 0 |
| `raptor.UncheckedRetScanf` | 0 |
| `raptor.UncheckedRetSetuidSeteuid` | 0 |
| `raptor.UnsafeRetSnprintfVsnprintf` | 0 |
| `raptor.UnsafeRetStrlcpyStrlcat` | 0 |
| `raptor.UnsafeStrlen` | 0 |

Counts are the number of `tests/integration/*.json` files whose top-level `checker` field names the rule (each file names exactly one). Rules with 0 are registered (`RAPTOR_CHECKER` in `src/checkers/*.cpp`) but have no integration case. To regenerate the counts:

```sh
python3 -c "import json,glob,collections as c;[print(n,k) for k,n in c.Counter(json.load(open(f))['checker'] for f in glob.glob('tests/integration/*.json')).most_common()]"
grep -ho 'RAPTOR_CHECKER([^,]*, *"[^"]*"' src/checkers/*.cpp   # registered rules
```
