// raptor.CopyIgnoresSourceSize: memcpy/memmove reads from a buffer whose size
// is known (a sibling field such as `e->size` or `rec->length`), but the copy
// length neither comes from that size nor is compared with it anywhere in the
// function: a heap over-read (CWE-125, CWE-126).
// Modelled on CVE-2020-0093 (libexif < 0.6.22, exif_data_save_data_entry:
// copies format_size * components bytes from e->data, which holds e->size
// bytes) and CVE-2014-0160 (Heartbleed: copies `payload` bytes from the record
// without comparing it with s->s3->rrec.length).
#include <stddef.h>
#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef struct {
  unsigned char *data;
  unsigned int size;
  unsigned int components;
  int format;
} ExifEntry;
unsigned int format_size(int format);

// CVE-2020-0093
void save_entry(unsigned char *d, ExifEntry *e) {
  unsigned int s = format_size(e->format) * e->components;
  if (s > 4)
    d += 6;
  if (e->data) {
    // ruleid: raptor-copy-ignores-source-size
    memcpy(d, e->data, s);
  }
}

// The fix: the length is clamped to e->size.
void save_entry_fixed(unsigned char *d, ExifEntry *e) {
  unsigned int s = format_size(e->format) * e->components;
  if (e->data) {
    unsigned int len = s;
    if (e->size < s)
      len = e->size;
    // ok: raptor-copy-ignores-source-size
    memcpy(d, e->data, len);
  }
}

// Heartbleed.
typedef struct {
  int type;
  unsigned int length;
  unsigned char *data;
} Record;
typedef struct {
  Record rrec;
} S3;
typedef struct {
  S3 *s3;
} SSL;

#define n2s(c, s) ((s = (((unsigned int)(c[0])) << 8) | (((unsigned int)(c[1])))), c += 2)

int process_heartbeat(SSL *s, unsigned char *bp) {
  unsigned char *p = &s->s3->rrec.data[0], *pl;
  unsigned int payload;
  p++;
  n2s(p, payload);
  pl = p;
  // ruleid: raptor-copy-ignores-source-size
  memcpy(bp, pl, payload);
  return 0;
}

int process_heartbeat_fixed(SSL *s, unsigned char *bp) {
  unsigned char *p = &s->s3->rrec.data[0], *pl;
  unsigned int payload;
  if (1 + 2 + 16 > s->s3->rrec.length)
    return 0;
  p++;
  n2s(p, payload);
  if (1 + 2 + payload + 16 > s->s3->rrec.length)
    return 0;
  pl = p;
  // ok: raptor-copy-ignores-source-size
  memcpy(bp, pl, payload);
  return 0;
}

// The length is the source's own size.
void copy_whole(unsigned char *d, ExifEntry *e) {
  // ok: raptor-copy-ignores-source-size
  memcpy(d, e->data, e->size);
}

// Bounded with MIN().
void copy_min(unsigned char *d, ExifEntry *e, unsigned int n) {
  // ok: raptor-copy-ignores-source-size
  memcpy(d, e->data, MIN(n, e->size));
}

// A constant length is not this rule's business.
void copy_header(unsigned char *d, ExifEntry *e) {
  // ok: raptor-copy-ignores-source-size
  memcpy(d, e->data, 4);
}

// The source has no size field.
typedef struct {
  unsigned char *bytes;
  int kind;
} Blob;
void copy_blob(unsigned char *d, Blob *b, size_t n) {
  // ok: raptor-copy-ignores-source-size
  memcpy(d, b->bytes, n);
}

// Checked against the size before the copy.
typedef struct {
  const char *buf;
  size_t buf_len;
} Msg;
int copy_checked(char *d, const Msg *m, size_t off, size_t n) {
  if (off + n > m->buf_len)
    return -1;
  // ok: raptor-copy-ignores-source-size
  memcpy(d, m->buf + off, n);
  return 0;
}

// Same, unchecked: offset and length both come from the caller.
int copy_unchecked(char *d, const Msg *m, size_t off, size_t n) {
  // ruleid: raptor-copy-ignores-source-size
  memcpy(d, m->buf + off, n);
  return 0;
}

// The size field is set from the length: they agree (OpenSSL finish_md).
typedef struct {
  unsigned char finish_md[64];
  int finish_md_len;
} Tmp;
int compute_mac(unsigned char *out);
void send_finished(unsigned char *p, Tmp *t) {
  int i = compute_mac(t->finish_md);
  t->finish_md_len = i;
  // ok: raptor-copy-ignores-source-size
  memcpy(p, t->finish_md, i);
}

// The length is program state kept in a field (OpenSSL init_num), not a
// value computed or decoded here.
typedef struct {
  Msg *init_buf;
  size_t init_num;
} Conn;
void buffer_message(char *frag, Conn *s) {
  // ok: raptor-copy-ignores-source-size
  memcpy(frag, s->init_buf->buf, s->init_num);
}

// The size field belongs to another buffer (libssh2 session, libtiff LERC).
typedef struct {
  unsigned char *uncompressed_buffer;
  unsigned int compressed_size;
  unsigned int uncompressed_alloc;
} Lerc;
void copy_tile(unsigned char *d, Lerc *sp, unsigned int n) {
  // ok: raptor-copy-ignores-source-size
  memcpy(d, sp->uncompressed_buffer, n);
}

// Paired by name: uncompressed_buffer -> uncompressed_size.
typedef struct {
  unsigned char *uncompressed_buffer;
  unsigned int uncompressed_size;
} Lerc2;
void copy_tile2(unsigned char *d, Lerc2 *sp, unsigned int w, unsigned int h) {
  unsigned int n = w * h;
  // ruleid: raptor-copy-ignores-source-size
  memcpy(d, sp->uncompressed_buffer, n);
}

// Checked through a local copy of the size (libssh2 agent.c).
typedef struct {
  unsigned char *response;
  size_t response_len;
} Trans;
unsigned int ntohu32(const unsigned char *p);
int read_sig(Trans *t, unsigned char *sig) {
  unsigned char *s = t->response;
  size_t len = t->response_len;
  unsigned int sig_len = ntohu32(s);
  s += 4;
  len -= 4;
  if (len < sig_len)
    return -1;
  // ok: raptor-copy-ignores-source-size
  memcpy(sig, s, sig_len);
  return 0;
}

// The source offset is computed from the size (libssh2 sftp.c).
typedef struct {
  unsigned char *data;
  size_t data_len, data_left;
} Handle;
void drain(unsigned char *d, Handle *h, size_t want) {
  size_t copy = want < h->data_left ? want : h->data_left;
  // ok: raptor-copy-ignores-source-size
  memcpy(d, &h->data[h->data_len - h->data_left], copy);
}

// An in-place move within one buffer (libtiff tif_lerc.c).
void spread(Lerc2 *sp, unsigned int i, unsigned int src_stride, unsigned int dst_stride) {
  // ok: raptor-copy-ignores-source-size
  memmove(sp->uncompressed_buffer + i * dst_stride, sp->uncompressed_buffer + i * src_stride,
          src_stride);
}
