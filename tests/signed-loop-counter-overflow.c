// raptor.SignedLoopCounterOverflow: a loop runs a signed 32-bit counter up to
// an int length parameter that nothing range-checks, and arithmetic on the
// counter overflows before the loop ends when the length is near INT_MAX:
// the loop guard `i + K < n` (with a step that jumps past n - K), or an
// index `i * M` into memory. The wrapped value is negative, so the guard
// stays true or the index points before the buffer, and the loop reads and
// writes out of bounds (CWE-190 -> CWE-787, CWE-125).
// Modelled on OpenSSL CVE-2026-121481 (evp_encodeblock_int: `for (i = 0;
// i + 2 < dlen; i += 3)`, encode_base64_avx2: `for (; i + 100 <= srclen; i +=
// 96)`, with dlen up to INT_MAX) and OpenImageIO CVE-2026-43909
// (SwapRGBABytes: `for (int i = 0; i < pixels; i++) output[i * 4 + 0] = ...`).
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// OpenSSL crypto/evp/enc_b64_scalar.c
size_t encodeblock(unsigned char *t, const unsigned char *f, int dlen) {
  int i;
  size_t ret = 0;
  // ruleid: raptor-signed-loop-counter-overflow
  for (i = 0; i + 2 < dlen; i += 3) {
    *(t++) = f[i];
    *(t++) = f[i + 1];
    *(t++) = f[i + 2];
    *(t++) = '=';
    ret += 4;
  }
  return ret;
}

// An earlier loop condition that compares the length with a counter does not
// bound it (evp_encodeblock_int's one-byte-per-line branch comes first).
size_t encodeblock_branches(unsigned char *t, const unsigned char *f, int dlen, int one) {
  int i = 0;
  if (one) {
    while (i < dlen) {
      *(t++) = f[i];
      i++;
    }
    return (size_t)i;
  }
  // ruleid: raptor-signed-loop-counter-overflow
  for (i = 0; i + 2 < dlen; i += 3)
    *(t++) = f[i];
  return (size_t)i;
}

// OpenSSL crypto/evp/enc_b64_avx2.c
size_t encode_avx2(unsigned char *out, const unsigned char *input, int srclen) {
  int i = 0;
  // ruleid: raptor-signed-loop-counter-overflow
  for (; i + 100 <= srclen; i += 96)
    memcpy(out + i, input + i, 96);
  return (size_t)i;
}

// The fix bounds the length first (EVP_EncodeBlock: `dlen > (INT_MAX / 4) * 3`).
size_t encodeblock_fixed(unsigned char *t, const unsigned char *f, int dlen) {
  int i;
  if (dlen < 0 || dlen > (INT_MAX / 4) * 3)
    return 0;
  // ok: raptor-signed-loop-counter-overflow
  for (i = 0; i + 2 < dlen; i += 3)
    *(t++) = f[i];
  return 0;
}

// OpenImageIO src/dpx.imageio/libdpx/DPXColorConverter.cpp
void swap_rgba(const uint16_t *input, uint16_t *output, int pixels) {
  uint16_t tmp[2];
  for (int i = 0; i < pixels; i++) {
    // ruleid: raptor-signed-loop-counter-overflow
    memcpy(tmp, &input[i * 4], sizeof(uint16_t) * 2);
    output[i * 4 + 0] = input[i * 4 + 3];
    output[i * 4 + 1] = input[i * 4 + 2];
    output[i * 4 + 2] = tmp[1];
    output[i * 4 + 3] = tmp[0];
  }
}

// The fix: size_t counter and length.
void swap_rgba_fixed(const uint16_t *input, uint16_t *output, size_t pixels) {
  for (size_t i = 0; i < pixels; i++) {
    // ok: raptor-signed-loop-counter-overflow
    output[i * 4 + 0] = input[i * 4 + 3];
  }
}

// Not this rule: a step that cannot jump past the guard, a constant or
// local bound, a narrow length, a bounded length, a product that is not
// used to reach memory, a length that is changed first.
void step_one(unsigned char *out, const unsigned char *in, int n) {
  // ok: raptor-signed-loop-counter-overflow
  for (int i = 0; i + 1 < n; i++)
    out[i] = in[i + 1];
}
void const_bound(unsigned char *out) {
  // ok: raptor-signed-loop-counter-overflow
  for (int i = 0; i < 16; i++)
    out[i * 4] = 0;
}
void narrow(unsigned char *out, uint16_t n) {
  // ok: raptor-signed-loop-counter-overflow
  for (int i = 0; i < n; i++)
    out[i * 4] = 0;
}
void bounded(unsigned char *out, int n) {
  if (n > 4096)
    return;
  // ok: raptor-signed-loop-counter-overflow
  for (int i = 0; i < n; i++)
    out[i * 4] = 0;
}
int sum_only(int n) {
  int s = 0;
  // ok: raptor-signed-loop-counter-overflow
  for (int i = 0; i < n; i++)
    s += i * 4;
  return s;
}
void halved(unsigned char *out, int n) {
  n /= 4;
  // ok: raptor-signed-loop-counter-overflow
  for (int i = 0; i < n; i++)
    out[i * 4] = 0;
}

// --- noise seen in wolfSSL ---

// A row pointer handed to a callee walks a matrix of k rows (ML-KEM's
// module rank, 2 to 4), not the elements of a flat buffer.
#define POLY_N 256
void ntt(int16_t *p);
void keygen(int16_t *s, int k) {
  // ok: raptor-signed-loop-counter-overflow
  for (int i = 0; i < k; ++i)
    ntt(s + i * POLY_N);
}
// Row i, column j of a matrix of k rows (ML-KEM `t[i * MLKEM_N + j]`).
void to_mont(int16_t *t, int k) {
  for (int i = 0; i < k; ++i)
    for (int j = 0; j < POLY_N; ++j)
      // ok: raptor-signed-loop-counter-overflow
      t[i * POLY_N + j] = (int16_t)(t[i * POLY_N + j] * 3);
}

// A guard before the loop bounds the length even when the same comparison is
// written again inside the loop or as some loop's condition (matched by
// position, not by text).
void guarded_repeat(unsigned char *t, const unsigned char *f, int dlen) {
  if (dlen > 4096)
    return;
  int i;
  // ok: raptor-signed-loop-counter-overflow
  for (i = 0; i + 2 < dlen; i += 3) {
    if (dlen > 4096)
      break;
    t[i] = f[i];
  }
}
void guarded_like_loop_cond(unsigned char *t, const unsigned char *f, int dlen) {
  if (dlen > 4096)
    return;
  int i;
  // ok: raptor-signed-loop-counter-overflow
  for (i = 0; i + 2 < dlen; i += 3)
    t[i] = f[i];
  int k = 0;
  while (dlen > 4096 && k < 2)
    k++;
}

// A comparison with a counter inside an earlier loop's body does not bound
// the length either: it only says how far that loop has got
// (evp_encodeblock_int: `if (ctx_length >= 4 && i + 2 < dlen)` in the
// line-wrapping loop, before the CVE loop).
size_t encodeblock_wrap(unsigned char *t, const unsigned char *f, int dlen, int wrap) {
  int i = 0;
  size_t ret = 0;
  if (wrap) {
    while (i + 2 < dlen) {
      if (wrap >= 4 && i + 2 < dlen) {
        *(t++) = f[i];
        i += 3;
      }
      ret += 4;
    }
    return ret;
  }
  // ruleid: raptor-signed-loop-counter-overflow
  for (i = 0; i + 2 < dlen; i += 3) {
    *(t++) = f[i];
    ret += 4;
  }
  return ret;
}
