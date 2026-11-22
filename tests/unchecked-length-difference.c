// raptor.UncheckedLengthDifference: an unsigned length A is reduced by a
// value B that comes from elsewhere (`size - colorPoints * 4`, `length -=
// consumed`) and nothing before the subtraction relates A and B: no
// comparison mentions both, and neither was computed from the other. When B
// is larger, A - B wraps to a huge value that then bounds a read, a copy or a
// loop (CWE-191 -> CWE-125, CWE-787, CWE-835).
// Modelled on rlottie CVE-2025-0634 (model::Gradient::populate: `size -
// colorPoints * 4` passed as the opacity array size) and NetX Duo
// CVE-2025-0727/CVE-2025-2259 (_nx_http_server_put_process: `length = length
// - (append_ptr - prepend_ptr)` on the remaining content length).
#include <stddef.h>
#include <string.h>

// rlottie src/lottie/lottiemodel.cpp
float opacity_at(const float *opacities, size_t n, float pos);
float populate(float *ptr, size_t size, int colorPoints, float stop) {
  if (colorPoints == -1)
    colorPoints = (int)(size / 4);
  // ruleid: raptor-unchecked-length-difference
  size_t opacityArraySize = size - colorPoints * 4;
  float *opacityPtr = ptr + colorPoints * 4;
  return opacity_at(opacityPtr, opacityArraySize, stop);
}

// The fix.
float populate_fixed(float *ptr, size_t size, int colorPoints, float stop) {
  size_t colorPointsSize = colorPoints * 4;
  if (colorPoints < 0 || colorPointsSize > size)
    colorPoints = (int)(size / 4);
  // ok: raptor-unchecked-length-difference
  size_t opacityArraySize = size - colorPointsSize;
  return opacity_at(ptr + colorPointsSize, opacityArraySize, stop);
}

// NetX Duo addons/http/nxd_http_server.c
struct packet {
  unsigned char *prepend_ptr, *append_ptr;
  struct packet *next;
};
int content_length(struct packet *p, unsigned long *len);
int write_file(const unsigned char *p, unsigned long n);
void put_process(struct packet *packet_ptr, unsigned long offset) {
  unsigned long length;
  if (content_length(packet_ptr, &length))
    return;
  if (length == 0)
    return;
  write_file(packet_ptr->prepend_ptr + offset,
             (unsigned long)(packet_ptr->append_ptr - packet_ptr->prepend_ptr) - offset);
  // ruleid: raptor-unchecked-length-difference
  length = length - ((unsigned long)(packet_ptr->append_ptr - packet_ptr->prepend_ptr) - offset);
  struct packet *next_packet_ptr = packet_ptr->next;
  while (length && next_packet_ptr) {
    write_file(next_packet_ptr->prepend_ptr,
               (unsigned long)(next_packet_ptr->append_ptr - next_packet_ptr->prepend_ptr));
    length = length - (unsigned long)(next_packet_ptr->append_ptr - next_packet_ptr->prepend_ptr);
    next_packet_ptr = next_packet_ptr->next;
  }
}

// The fix.
void put_process_fixed(struct packet *packet_ptr, unsigned long offset) {
  unsigned long length, consumed_length;
  if (content_length(packet_ptr, &length))
    return;
  consumed_length = (unsigned long)(packet_ptr->append_ptr - packet_ptr->prepend_ptr) - offset;
  if ((length - consumed_length) > length)
    return;
  // ok: raptor-unchecked-length-difference
  length -= consumed_length;
  while (length)
    length--;
}

// Guards: a comparison of both, a conditional, a min(), B derived from A,
// a loop that compares the index with A.
size_t tail_len(size_t len, size_t off) {
  if (off > len)
    return 0;
  // ok: raptor-unchecked-length-difference
  return len - off;
}
void copy_rest(char *dst, const char *src, size_t len, size_t off) {
  // ok: raptor-unchecked-length-difference
  memcpy(dst, src + off, off < len ? len - off : 0);
}
void copy_head(char *dst, const char *src, size_t len, size_t cap) {
  size_t n = len < cap ? len : cap;
  // ok: raptor-unchecked-length-difference
  memcpy(dst, src + n, len - n);
}
void scan(const char *p, size_t len) {
  for (size_t i = 0; i < len; i++)
    // ok: raptor-unchecked-length-difference
    memchr(p + i, 0, len - i);
}

// Unguarded copy size.
void copy_after_header(char *dst, const char *src, size_t len, size_t hdr) {
  // ruleid: raptor-unchecked-length-difference
  memcpy(dst, src + hdr, len - hdr);
}

// Not this rule: a constant (EmptyLengthDecrement), a value that never
// reaches memory or a loop, a name that is not a length, signed.
size_t minus_one(const char *s, size_t len) {
  // ok: raptor-unchecked-length-difference
  return s[len - 1];
}
size_t stat_diff(size_t total_size, size_t used) {
  // ok: raptor-unchecked-length-difference
  return total_size - used;
}
void index_diff(char *p, size_t a, size_t b) {
  // ok: raptor-unchecked-length-difference
  p[a - b] = 0;
}
void signed_diff(char *dst, const char *src, int len, int hdr) {
  // ok: raptor-unchecked-length-difference
  memcpy(dst, src, len - hdr);
}

// --- noise seen in curl, HAProxy, OpenSSL ---

// A count returned by a call that was given the length (write/read
// contracts), directly or through an out-parameter.
long do_write(const char *p, size_t len);
int do_read(char *p, size_t len, size_t *nread);
void write_all(const char *p, size_t blen) {
  while (blen) {
    long nwritten = do_write(p, blen);
    // ok: raptor-unchecked-length-difference
    blen -= nwritten;
  }
}
void read_all(char *p, size_t len) {
  size_t readbytes;
  while (len) {
    if (!do_read(p, len, &readbytes))
      return;
    // ok: raptor-unchecked-length-difference
    len -= readbytes;
  }
}

// Two cursor fields of one object (dlen >= w_offset is the object's
// invariant).
struct chunk {
  size_t dlen, w_offset;
  char *buf;
};
void flush(struct chunk *c, char *dst) {
  // ok: raptor-unchecked-length-difference
  memcpy(dst, c->buf + c->w_offset, c->dlen - c->w_offset);
}

// A step computed from the length inside the loop.
void drain(char *dst, const char *src, size_t len, size_t blk) {
  while (len) {
    size_t sz = len < blk ? len : blk;
    memcpy(dst, src, sz);
    // ok: raptor-unchecked-length-difference
    len -= sz;
  }
}

// --- noise seen in OpenSSH, curl, OpenSSL, HAProxy, libssh2 ---

// B assigned from A in the block that holds the subtraction, or in the
// condition that guards it (OpenSSH authfd `l = len`, curl bufq
// `n = chunk_append(.., len)`, OpenSSL gcm128 `if ((i = len & -16))`).
void read_n(char *p, size_t n);
void read_rest(char *buf, size_t bufsz, size_t len) {
  size_t l;
  while (len > 0) {
    l = len;
    if (l > bufsz)
      l = bufsz;
    read_n(buf, l);
    // ok: raptor-unchecked-length-difference
    len -= l;
  }
}
size_t chunk_append(char *dst, const char *src, size_t len);
void append_all(char *dst, const char *buf, size_t len) {
  size_t n;
  while (len) {
    n = chunk_append(dst, buf, len);
    if (!n)
      break;
    buf += n;
    // ok: raptor-unchecked-length-difference
    len -= n;
  }
}
void ghash(const unsigned char *aad, size_t len);
void aad_blocks(const unsigned char *aad, size_t len) {
  size_t i;
  if ((i = (len & (size_t)-16))) {
    ghash(aad, i);
    aad += i;
    // ok: raptor-unchecked-length-difference
    len -= i;
  }
  while (len) {
    ghash(aad++, 1);
    len--;
  }
}
// An assignment in another branch does not count.
void branch_def(char *dst, const char *src, size_t len, size_t hdr, int f) {
  size_t n = hdr;
  if (f) {
    n = len;
  }
  // ruleid: raptor-unchecked-length-difference
  memcpy(dst, src + n, len - n);
}

// A comparison later in the same loop guards the next pass (HAProxy
// print_cpu_set).
int snprintf(char *s, size_t n, const char *fmt, ...);
size_t print_list(char *out, size_t size, int count) {
  int len = 0;
  for (int i = 0; i < count; i++) {
    // ok: raptor-unchecked-length-difference
    len += snprintf(out + len, size - len, "%d,", i);
    if (len >= size)
      return len;
  }
  return len;
}

// printf-style arguments are printed, not used as sizes (HAProxy debug.c).
void chunk_appendf(char *buf, const char *fmt, ...);
void show_times(char *buf, size_t n, size_t p) {
  // ok: raptor-unchecked-length-difference
  chunk_appendf(buf, "diff=%zu\n", n - p);
}

// A whole function written as a macro (OpenSSL IMPLEMENT_CIPHER_HW_ECB):
// order inside the expansion is spelling order.
void enc_block(const unsigned char *in, unsigned char *out);
#define IMPLEMENT_ECB(NAME)                                                              \
  int NAME##_ecb(unsigned char *out, const unsigned char *in, size_t len, size_t bl) {   \
    size_t i;                                                                            \
    if (len < bl)                                                                        \
      return 1;                                                                          \
    for (i = 0, len -= bl; i <= len; i += bl)                                            \
      enc_block(in + i, out + i);                                                        \
    return 1;                                                                            \
  }
// ok: raptor-unchecked-length-difference
IMPLEMENT_ECB(bf)

// B computed from a position that a search bounded by A returned (curl
// ftp.c: `cp = memchr(buf, '\r', blen); chunk_len = cp - buf;`).
void *memchr(const void *s, int c, size_t n);
void put_line(const char *p, size_t n);
void strip_cr(const char *buf, size_t blen) {
  while (blen) {
    const char *cp = memchr(buf, '\r', blen);
    if (!cp)
      break;
    size_t chunk_len = cp - buf;
    put_line(buf, chunk_len);
    buf = cp + 1;
    // ok: raptor-unchecked-length-difference
    blen = blen - chunk_len - 1;
  }
  put_line(buf, blen);
}

// B is a remainder modulo A, so B < A (libssh2 transport.c `blocksize -
// (len % blocksize)`, wolfSSL asn.c `blockSz - (sz & (blockSz - 1))`).
void pad(unsigned char *out, size_t blocksize, size_t len) {
  // ok: raptor-unchecked-length-difference
  memset(out + len, 0, blocksize - (len % blocksize));
}
void pad_pow2(unsigned char *out, size_t blockSz, size_t sz) {
  // ok: raptor-unchecked-length-difference
  memset(out + sz, 0, blockSz - (sz & (blockSz - 1)));
}
