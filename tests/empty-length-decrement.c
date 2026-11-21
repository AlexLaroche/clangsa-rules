// raptor.EmptyLengthDecrement: an unsigned length parameter is decremented
// (`len - 1`, `len - K`) with no earlier check that it is large enough. A
// length of 0 wraps to SIZE_MAX: `buf[len - 1]` reads before the buffer and
// `(size - 1) / 2` becomes a huge count (CWE-191, CWE-125, CWE-787).
// Modelled on Mbed TLS CVE-2025-52497 (pem_check_pkcs_padding:
// `input[input_len - 1]`, "input_len > 0 is guaranteed" was wrong) and
// Suricata CVE-2025-59149 (ShortenString: `(output_size - 1) / 2`).
#include <stddef.h>
#include <string.h>

#define ERR_INVALID (-1)

// Mbed TLS library/pem.c
int pem_check_pkcs_padding(unsigned char *input, size_t input_len, size_t *data_len) {
  /* input_len > 0 is guaranteed by mbedtls_pem_read_buffer(). */
  // ruleid: raptor-empty-length-decrement
  size_t pad_len = input[input_len - 1];
  size_t i;
  if (pad_len > input_len || pad_len == 0)
    return ERR_INVALID;
  *data_len = input_len - pad_len;
  for (i = *data_len; i < input_len; i++)
    if (input[i] != pad_len)
      return ERR_INVALID;
  return 0;
}

// The fix.
int pem_check_pkcs_padding_fixed(unsigned char *input, size_t input_len, size_t *data_len) {
  if (input_len < 1)
    return ERR_INVALID;
  // ok: raptor-empty-length-decrement
  size_t pad_len = input[input_len - 1];
  if (pad_len > input_len || pad_len == 0)
    return ERR_INVALID;
  *data_len = input_len - pad_len;
  return 0;
}

// Suricata src/util-misc.c
void ShortenString(const char *input, char *output, size_t output_size, char c) {
  const size_t str_len = strlen(input);
  // ruleid: raptor-empty-length-decrement
  size_t half = (output_size - 1) / 2;
  if (half * 2 == (output_size - 1))
    half = half - 1;
  // ok: raptor-empty-length-decrement
  size_t spaces = (output_size - 1) - (half * 2);
  memcpy(output, input, half);
  memset(output + half, c, spaces);
  memcpy(output + half + spaces, input + str_len - half, half);
  output[output_size - 1] = '\0';
}

// The fix.
void ShortenString_fixed(const char *input, char *output, size_t output_size, char c) {
  if (output_size == 0)
    return;
  // ok: raptor-empty-length-decrement
  size_t half = (output_size - 1) / 2;
  output[half] = c;
  (void)input;
}

// Other guards: truth value, !n, a loop condition, a larger lower bound.
char last(const char *s, size_t n) {
  if (!n)
    return 0;
  // ok: raptor-empty-length-decrement
  return s[n - 1];
}
char last2(const char *s, size_t n) {
  // ok: raptor-empty-length-decrement
  return n ? s[n - 1] : 0;
}
void trim(char *s, size_t n) {
  while (n > 0 && s[n - 1] == ' ') // ok: raptor-empty-length-decrement
    s[--n] = '\0';
}
unsigned tail4(const unsigned char *p, size_t n) {
  if (n < 4)
    return 0;
  // ok: raptor-empty-length-decrement
  return p[n - 4];
}

// A guard after the use does not help.
char last_late(const char *s, size_t n) {
  // ruleid: raptor-empty-length-decrement
  char c = s[n - 1];
  if (n == 0)
    return 0;
  return c;
}

// Loop bound that wraps.
void pairs(int *a, unsigned count) {
  // ruleid: raptor-empty-length-decrement
  for (unsigned i = 0; i < count - 1; i++)
    a[i] = a[i + 1];
}

// Not this rule: signed parameters (go negative, other rules), locals,
// constants, an increment.
int signed_len(const char *s, int n) {
  // ok: raptor-empty-length-decrement
  return s[n - 1];
}
char local_len(const char *s) {
  size_t n = strlen(s);
  // ok: raptor-empty-length-decrement
  return s[n - 1];
}
size_t plus_one(size_t n) {
  // ok: raptor-empty-length-decrement
  return n + 1;
}

// --- noise seen in OpenSSL ---

// Deliberate wraparound on values that are not lengths (constant_time.h,
// ML-DSA reductions).
unsigned constant_time_is_zero(unsigned a) {
  // ok: raptor-empty-length-decrement
  return ~a & (a - 1);
}
unsigned reduce(unsigned x) {
  // ok: raptor-empty-length-decrement
  unsigned subtracted = x - 8380417;
  return subtracted;
}

// Bit masks of a power of two.
size_t block_mask(size_t blocksize) {
  // ok: raptor-empty-length-decrement
  return ~(blocksize - 1);
}

// Decremented in a loop's init and guarded by that loop's condition.
void reverse(unsigned char *data, const unsigned char *src, size_t len) {
  // ok: raptor-empty-length-decrement
  for (data += len - 1; len > 0; len--)
    *data-- = *src++;
}

// Values only encoded or compared, never used to reach memory (brotli
// StoreVarLenUint8(num_types - 1), Log2Floor(alphabet_size - 1), OpenSSL
// `if (factornum - 2 < pnum)`).
void store_var_len(size_t n, size_t *ix);
size_t log2_floor(size_t v);
size_t encode_types(size_t num_types, size_t alphabet_size, size_t *ix) {
  // ok: raptor-empty-length-decrement
  store_var_len(num_types - 1, ix);
  // ok: raptor-empty-length-decrement
  return log2_floor(alphabet_size - 1);
}
int too_many(size_t factornum, size_t pnum) {
  // ok: raptor-empty-length-decrement
  if (factornum - 2 < pnum)
    return 1;
  return 0;
}

// Pointer arithmetic and a copy size reach memory (OpenSSL BUF_reverse-like,
// a local passed to memcpy).
void reverse_to(unsigned char *out, size_t size) {
  // ruleid: raptor-empty-length-decrement
  out += size - 1;
  *out = 0;
}
void copy_but_last(char *dst, const char *src, size_t src_len) {
  // ruleid: raptor-empty-length-decrement
  size_t n = src_len - 1;
  memcpy(dst, src, n);
}
