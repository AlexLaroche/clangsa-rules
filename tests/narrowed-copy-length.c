// raptor.NarrowedCopyLength: a copy length is narrowed (`(int)n`, `int used
// = pos + n`), the narrowed value decides how big the destination is (an
// allocation size, or a capacity comparison that decides whether to grow),
// and the copy then uses the full length (CWE-197, CWE-787).
// Modelled on Ruby GHSA-3p8q-wmhx-vm2w (Onigmo BBUF_WRITE: `int used = (pos)
// + (int)(n); if (alloc < (unsigned)used) expand; memcpy(p + pos, bytes,
// n);`) and PHP bugs #72551/#72552 (ext/mcrypt: `data_size = (int)data_len;
// emalloc(data_size + 1); memcpy(data_s, data, data_len);`).
#include <stddef.h>
#include <string.h>
#include <limits.h>

void *xrealloc(void *, size_t);
void *emalloc(size_t);
#define xmemcpy memcpy

typedef struct {
  unsigned char *p;
  unsigned int used;
  unsigned int alloc;
} BBuf;

#define BBUF_EXPAND(buf, low) do { \
  unsigned char *tmp; \
  do { (buf)->alloc *= 2; } while ((buf)->alloc < (unsigned int)low); \
  tmp = (unsigned char *)xrealloc((buf)->p, (buf)->alloc); \
  if (!tmp) return -5; \
  (buf)->p = tmp; \
} while (0)

#define BBUF_WRITE(buf, pos, bytes, n) do { \
  int used = (pos) + (int)(n); \
  if ((buf)->alloc < (unsigned int)used) BBUF_EXPAND((buf), used); \
  xmemcpy((buf)->p + (pos), (bytes), (n)); \
  if ((buf)->used < (unsigned int)used) (buf)->used = used; \
} while (0)

#define BBUF_ADD(buf, bytes, n) BBUF_WRITE((buf), (buf)->used, (bytes), (n))

// Ruby 3.4.12 regcomp.c
int add_bytes(BBuf *reg, unsigned char *bytes, size_t len) {
  // ruleid: raptor-narrowed-copy-length
  BBUF_ADD(reg, bytes, len);
  return 0;
}

// A constant length cannot be truncated.
int add_bitset(BBuf *reg, unsigned char *bs) {
  // ok: raptor-narrowed-copy-length
  BBUF_ADD(reg, bs, 32);
  return 0;
}

// Ruby 3.4.13: the size is computed in size_t and capped.
#define MAX_BBUF ((size_t)INT_MAX)
#define BBUF_WRITE_FIXED(buf, pos, bytes, n) do { \
  size_t used = (size_t)(pos) + (size_t)(n); \
  if (used > MAX_BBUF) return -5; \
  if ((size_t)(buf)->alloc < used) BBUF_EXPAND((buf), used); \
  xmemcpy((buf)->p + (pos), (bytes), (n)); \
  if ((buf)->used < used) (buf)->used = (unsigned int)used; \
} while (0)

int add_bytes_fixed(BBuf *reg, unsigned char *bytes, size_t len) {
  // ok: raptor-narrowed-copy-length
  BBUF_WRITE_FIXED(reg, reg->used, bytes, len);
  return 0;
}

// PHP 7.0.8 ext/mcrypt/mcrypt.c mdecrypt_generic
char *mdecrypt_generic(const char *data, size_t data_len) {
  int data_size;
  char *data_s;
  // ruleid: raptor-narrowed-copy-length
  data_size = (int)data_len;
  data_s = emalloc(data_size + 1);
  memset(data_s, 0, data_size);
  memcpy(data_s, data, data_len);
  return data_s;
}

// The PHP fix: refuse a length the cast changed.
char *mdecrypt_generic_fixed(const char *data, size_t data_len) {
  int data_size;
  char *data_s;
  // ok: raptor-narrowed-copy-length
  data_size = (int)data_len;
  if ((size_t)data_size < data_len)
    return 0;
  data_s = emalloc(data_size + 1);
  memcpy(data_s, data, data_len);
  return data_s;
}

// Implicit narrowing into the capacity check.
struct sbuf { char *p; int pos; int cap; };
int sbuf_append(struct sbuf *b, const char *src, size_t len) {
  // ruleid: raptor-narrowed-copy-length
  int need = b->pos + len;
  if (need > b->cap) {
    char *np = xrealloc(b->p, need);
    if (!np)
      return -1;
    b->p = np;
    b->cap = need;
  }
  memcpy(b->p + b->pos, src, len);
  b->pos = need;
  return 0;
}

// Checked against INT_MAX first.
int sbuf_append_checked(struct sbuf *b, const char *src, size_t len) {
  if (len > INT_MAX - (size_t)b->pos)
    return -1;
  // ok: raptor-narrowed-copy-length
  int need = b->pos + len;
  if (need > b->cap)
    return -1;
  memcpy(b->p + b->pos, src, len);
  return 0;
}

// The copy uses the narrowed length too: consistent.
char *copy_narrow(const char *data, size_t data_len) {
  // ok: raptor-narrowed-copy-length
  int n = (int)data_len;
  char *s = emalloc(n + 1);
  memcpy(s, data, n);
  return s;
}

// The narrowed value does not size anything.
int printf(const char *, ...);
void log_copy(char *dst, const char *src, size_t len) {
  // ok: raptor-narrowed-copy-length
  int shown = (int)len;
  printf("%d\n", shown);
  memcpy(dst, src, len);
}

// A narrowed value that only offsets a pointer does not size the buffer.
char *copy32(const char *data, unsigned int data_len) {
  // ok: raptor-narrowed-copy-length
  unsigned short n = (unsigned short)data_len;
  char *s = emalloc(data_len);
  memcpy(s, data, data_len);
  return s + n;
}

// Narrowed straight into the allocation size.
char *dup_bytes(const char *data, size_t len) {
  // ruleid: raptor-narrowed-copy-length
  char *s = emalloc((unsigned)len + 1);
  memcpy(s, data, len);
  return s;
}

// Every narrowing that sizes the buffer is reported (PHP mcrypt_generic: the
// block and the stream branch).
char *mcrypt_generic(const char *data, size_t data_len, int block_mode, int block_size) {
  int data_size;
  char *data_str;
  if (block_mode) {
    // ruleid: raptor-narrowed-copy-length
    data_size = ((((int)data_len - 1) / block_size) + 1) * block_size;
    data_str = emalloc(data_size);
    memcpy(data_str, data, data_len);
  } else {
    // ruleid: raptor-narrowed-copy-length
    data_size = (int)data_len;
    data_str = emalloc(data_size);
    memcpy(data_str, data, data_len);
  }
  return data_str;
}

// The narrowed length is an argument; the call's result is not it (OpenSSL
// tls_retry_write_records).
int bio_write(void *bio, const void *buf, unsigned int n);
int retry_write(void *bio, const char *src, size_t left, char *dst) {
  // ok: raptor-narrowed-copy-length
  int i = bio_write(bio, src, (unsigned int)left);
  if (i >= 0)
    return i;
  memcpy(dst, src, left);
  return 0;
}

// A round-trip check rejects a length the cast changed (OpenSSL
// dane_tlsa_add).
char *tlsa_add(const unsigned char *data, size_t dlen) {
  // ok: raptor-narrowed-copy-length
  int ilen = (int)dlen;
  if (ilen < 0 || dlen != (size_t)ilen)
    return 0;
  char *t = emalloc(dlen);
  memcpy(t, data, dlen);
  return t;
}

// The narrowed value provably fits (OpenSSL test/bad_dtls_test.c).
char *pad_record(const char *msg, size_t len) {
  // ok: raptor-narrowed-copy-length
  unsigned char pad = 15 - ((len + 20) % 16);
  char *enc = emalloc(len + 20 + 1 + pad);
  memcpy(enc, msg, len);
  return enc;
}

// A call's result is narrowed; the length is only one of its arguments
// (SymCrypt lms.c).
unsigned get_digit(const unsigned char *p, size_t n, unsigned i);
void lms_sign(unsigned char *dst, const unsigned char *src, size_t cb) {
  memcpy(dst, src, cb);
  // ok: raptor-narrowed-copy-length
  unsigned char coeff = (unsigned char)get_digit(src, cb + 2, 0);
  for (unsigned char j = 0; j < coeff; j++)
    dst[j] = 0;
}

// An allocator API whose count parameter is `unsigned` (talloc's
// _talloc_array): the implicit conversion at every call is the API's design,
// not a narrowing the code chose; FreeRADIUS talloc_bstrndup and 17 more.
void *_talloc_array(const void *ctx, size_t el_size, unsigned count, const char *name);
#define talloc_array(ctx, type, count) (type *)_talloc_array(ctx, sizeof(type), count, #type)
char *talloc_bstrndup(const void *ctx, const char *in, size_t inlen) {
  // ok: raptor-narrowed-copy-length
  char *p = talloc_array(ctx, char, inlen + 1);
  if (!p)
    return NULL;
  memcpy(p, in, inlen);
  p[inlen] = '\0';
  return p;
}
