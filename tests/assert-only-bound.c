// raptor.AssertOnlyBound: the only check on a length or offset is an
// assert() comparison (`assert(n <= sizeof(buf))`), and the value is then
// used as a size, an index or a pointer offset. Release builds define NDEBUG,
// the check disappears, and the value reaches the copy unchecked (CWE-617,
// CWE-787, CWE-125).
// Modelled on CVE-2026-66033 (libssh2 ssh2_cipher_crypt:
// `assert(blocksize <= sizeof(buf)); assert(cryptlen >= 0);` then
// `memcpy(block + aadlen, buf + aadlen, cryptlen)`) and CVE-2026-102633
// (libexpat expat_realloc: `assert(SIZE_MAX - sizeof(size_t) - PAD >= size);`
// then `realloc_fcn(p, sizeof(size_t) + PAD + size)`), both fixed by turning
// the assertion into an if.
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BLOCK 32
#define PAD 8

int cipher(void *ctx, unsigned char *out, const unsigned char *in, unsigned int inl);

// CVE-2026-66033
int cipher_crypt(void *ctx, unsigned char *block, size_t blocksize, int first, int last) {
  unsigned char buf[MAX_BLOCK];
  const int aadlen = first ? 4 : 0;
  const int tag = last ? 16 : 0;
  const int cryptlen = (unsigned int)blocksize - aadlen - tag;
  int ret;
  // ruleid: raptor-assert-only-bound
  assert(blocksize <= sizeof(buf));
  // ruleid: raptor-assert-only-bound
  assert(cryptlen >= 0);
  ret = cipher(ctx, NULL, block + blocksize - tag, 0);
  if (cryptlen > 0)
    ret = cipher(ctx, buf + aadlen, block + aadlen, cryptlen);
  memcpy(block + aadlen, buf + aadlen, cryptlen);
  return ret;
}

// The fix: the checks run in every build.
int cipher_crypt_fixed(void *ctx, unsigned char *block, size_t blocksize, int first, int last) {
  unsigned char buf[MAX_BLOCK];
  const int aadlen = first ? 4 : 0;
  const int tag = last ? 16 : 0;
  unsigned int cryptlen;
  if (blocksize > sizeof(buf) || blocksize < (size_t)(aadlen + tag))
    return 1;
  cryptlen = (unsigned int)blocksize - aadlen - tag;
  memcpy(block + aadlen, buf + aadlen, cryptlen);
  return 0;
}

// CVE-2026-102633: through a function pointer, after a comparison that only
// classifies the change.
typedef struct {
  void *(*realloc_fcn)(void *, size_t);
} Mem;
void *mem_realloc(Mem *m, void *ptr, size_t size) {
  if (size == 0)
    return NULL;
  size_t prev = *(size_t *)ptr;
  int increase = size > prev;
  size_t diff = (size > prev) ? (size - prev) : (prev - size);
  (void)increase;
  (void)diff;
  // ruleid: raptor-assert-only-bound
  assert(SIZE_MAX - sizeof(size_t) - PAD >= size);
  return m->realloc_fcn(ptr, sizeof(size_t) + PAD + size);
}

// Also checked at run time: the assertion documents it.
int copy_checked(unsigned char *dst, const unsigned char *src, size_t n) {
  if (n > 64)
    return -1;
  // ok: raptor-assert-only-bound
  assert(n <= 64);
  memcpy(dst, src, n);
  return 0;
}

// Clamped by a ?: at run time.
void copy_clamped(unsigned char *dst, const unsigned char *src, size_t n) {
  // ok: raptor-assert-only-bound
  assert(n <= 64);
  n = n > 64 ? 64 : n;
  memcpy(dst, src, n);
}

// Checked by a loop condition.
void fill(unsigned char *dst, size_t n, size_t cap) {
  // ok: raptor-assert-only-bound
  assert(n <= cap);
  for (size_t i = 0; i < n && i < cap; i++)
    dst[i] = 0;
}

// Not used as a size, an index or an offset afterwards.
int classify(int level) {
  // ok: raptor-assert-only-bound
  assert(level < 8);
  return level * 2;
}

// Used only before the assertion.
void before(unsigned char *dst, const unsigned char *src, size_t n) {
  memcpy(dst, src, n);
  // ok: raptor-assert-only-bound
  assert(n <= 64);
}

// No comparison in the assertion, or one on a pointer.
void not_bound(unsigned char *dst, const unsigned char *src, size_t n, const unsigned char *end) {
  // ok: raptor-assert-only-bound
  assert(dst != NULL);
  // ok: raptor-assert-only-bound
  assert(src < end);
  memcpy(dst, src, n);
}

// An index.
static const char *const names[4] = {"a", "b", "c", "d"};
const char *name_of(unsigned idx) {
  // ruleid: raptor-assert-only-bound
  assert(idx < 4);
  return names[idx];
}

// An invariant between two run-time values, not a limit.
int pick(const int *tab, size_t i, size_t n) {
  // ok: raptor-assert-only-bound
  assert(i < n);
  return tab[i];
}

// A limit spelled as a macro or a cast constant.
#define MAX_INPUT 8000000
void *dup_input(const void *p, size_t len) {
  // ruleid: raptor-assert-only-bound
  assert(len <= MAX_INPUT && len >= (size_t)1);
  void *q = malloc(len + 1);
  if (q)
    memcpy(q, p, len);
  return q;
}

// An assertion macro that reports and goes on runs in every build
// (libarchive's test harness: assertion_assert(__FILE__, __LINE__, e, ...)).
int assertion_assert(const char *file, int line, int value, const char *expr);
#define check_assert(e) assertion_assert(__FILE__, __LINE__, (e), #e)
void check_copy(unsigned char *dst, const unsigned char *src, size_t n) {
  // ok: raptor-assert-only-bound
  check_assert(n <= 16);
  memcpy(dst, src, n);
}

// Test-framework assertions run in every build.
void assert_true(int cond);
void test_copy(unsigned char *dst, const unsigned char *src, size_t n) {
  // ok: raptor-assert-only-bound
  assert_true(n <= 16);
  memcpy(dst, src, n);
}

// With NDEBUG the assertion is gone from the code, but not from the source.
#undef assert
#define assert(e) ((void)0)
void copy_release(unsigned char *dst, const unsigned char *src, size_t n) {
  // ruleid: raptor-assert-only-bound
  assert(n <= 64);
  memcpy(dst, src, n);
}
