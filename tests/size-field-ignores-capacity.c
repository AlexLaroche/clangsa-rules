// raptor.SizeFieldIgnoresCapacity: a (pointer, size) pair is set up to
// describe another object's buffer (`e->data = p->bmpData; e->size = n;`),
// but the size neither comes from the buffer's capacity field (p->bmpSize)
// nor is compared with it: whoever uses the pair reads or writes past the
// end of the buffer (CWE-787, CWE-125).
// Modelled on CVE-2026-111381 (FreeRDP < 3.32.0, persistent cache v2 parser:
// `entry->size = entry2.width * entry2.height * 4; entry->data =
// persistent->bmpData;` with bmpData holding bmpSize = 0x4000 bytes).
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
  uint32_t width, height;
  uint8_t *data;
  uint32_t size;
} Entry;

typedef struct {
  void *fp;
  uint8_t *bmpData;
  uint32_t bmpSize;
} Cache;

typedef struct {
  uint16_t width, height;
} EntryV2;

int read_header(void *fp, EntryV2 *e);

// CVE-2026-111381
int read_entry_v2(Cache *persistent, Entry *entry) {
  EntryV2 entry2;
  if (read_header(persistent->fp, &entry2) != 0)
    return -1;
  entry->width = entry2.width;
  entry->height = entry2.height;
  // ruleid: raptor-size-field-ignores-capacity
  entry->size = entry2.width * entry2.height * 4;
  entry->data = persistent->bmpData;
  return 1;
}

// The fix: the buffer grows to the size first.
int get_data(Cache *persistent, Entry *entry) {
  const uint64_t expected = 4ull * entry->width * entry->height;
  const uint64_t allocated = expected > 0x4000 ? expected : 0x4000;
  if (expected > UINT32_MAX)
    return 0;
  if (allocated > persistent->bmpSize) {
    uint8_t *p = (uint8_t *)realloc(persistent->bmpData, allocated);
    if (!p)
      return 0;
    persistent->bmpSize = (uint32_t)allocated;
    persistent->bmpData = p;
  }
  entry->data = persistent->bmpData;
  // ok: raptor-size-field-ignores-capacity
  entry->size = (uint32_t)expected;
  return 1;
}

// Checked directly against the capacity.
int read_entry_checked(Cache *c, Entry *e, uint32_t w, uint32_t h) {
  uint32_t n = w * h * 4;
  if (n > c->bmpSize)
    return -1;
  e->data = c->bmpData;
  // ok: raptor-size-field-ignores-capacity
  e->size = n;
  return 0;
}

// The size is the capacity, or computed from it.
void share_all(Cache *c, Entry *e) {
  e->data = c->bmpData;
  // ok: raptor-size-field-ignores-capacity
  e->size = c->bmpSize;
}
void share_half(Cache *c, Entry *e) {
  uint32_t half = c->bmpSize / 2;
  e->data = c->bmpData;
  // ok: raptor-size-field-ignores-capacity
  e->size = half;
}

// A constant size: not this rule's business.
void share_header(Cache *c, Entry *e) {
  e->data = c->bmpData;
  // ok: raptor-size-field-ignores-capacity
  e->size = 16;
}

// The buffer has no capacity field.
typedef struct {
  uint8_t *pixels;
  int format;
} Image;
void wrap(Image *img, Entry *e, uint32_t w, uint32_t h) {
  e->data = img->pixels;
  // ok: raptor-size-field-ignores-capacity
  e->size = w * h;
}

// A fresh allocation of the size: data does not come from another object.
int alloc_entry(Entry *e, uint32_t w, uint32_t h) {
  e->size = w * h * 4;
  // ok: raptor-size-field-ignores-capacity
  e->data = (uint8_t *)malloc(e->size);
  return e->data ? 0 : -1;
}

// Paired by name: rec->buf / rec->buf_len, pool->block / pool->block_size.
typedef struct {
  char *buf;
  size_t buf_len;
} Slice;
typedef struct {
  char *block;
  size_t block_size;
  size_t used;
} Pool;
void slice_pool(Pool *pool, Slice *s, size_t off, size_t want) {
  s->buf = pool->block + off;
  // ruleid: raptor-size-field-ignores-capacity
  s->buf_len = want;
}
void slice_pool_checked(Pool *pool, Slice *s, size_t off, size_t want) {
  if (off + want > pool->block_size)
    return;
  s->buf = pool->block + off;
  // ok: raptor-size-field-ignores-capacity
  s->buf_len = want;
}

// Pointer and size set in different branches: not one pair (libssh2 kex.c).
typedef struct {
  uint8_t *s_packet;
  size_t s_packet_len;
} Exchange;
int parse_reply(Entry *buf, const Exchange *ex, uint8_t *data, uint32_t data_len) {
  if (data) {
    buf->data = data;
    // ok: raptor-size-field-ignores-capacity
    buf->size = data_len;
  } else {
    buf->data = ex->s_packet + 1;
    buf->size = (uint32_t)ex->s_packet_len - 1;
  }
  return 0;
}

// The size is updated from its own old value (c-ares ares_buf.c tag_rollback).
typedef struct {
  uint8_t *alloc_buf;
  size_t alloc_buf_len;
  const uint8_t *data;
  size_t data_len;
  size_t offset;
} Buf;
void reclaim(Buf *buf) {
  size_t prefix = buf->offset;
  size_t data_size = buf->data_len - prefix;
  buf->data = buf->alloc_buf;
  // ok: raptor-size-field-ignores-capacity
  buf->data_len = data_size;
}

// nginx ngx_str_t slices.
typedef struct {
  size_t len;
  uint8_t *data;
} Str;
uint8_t *pool_alloc(size_t n);

// A size pairs with the nearest assignment of its pointer: here a fresh
// allocation, not the buffer set further down (nginx ngx_http_script.c).
int complex_value(Str *value, size_t len, uint8_t *pos) {
  Str e;
  // ok: raptor-size-field-ignores-capacity
  value->len = len;
  value->data = pool_alloc(len);
  if (value->data == NULL)
    return -1;
  e = *value;
  value->data = e.data;
  // ok: raptor-size-field-ignores-capacity
  value->len = pos - e.data;
  return 0;
}

// The buffer is a slice built in this function (nginx ssl_session_cache).
int split_zone(const Str *value, Str *name, Str *size) {
  size_t j, len = 0;
  for (j = 7; j < value->len; j++) {
    if (value->data[j] == ':')
      break;
    len++;
  }
  if (len == 0 || j == value->len)
    return -1;
  name->len = len;
  name->data = value->data + 7;
  // ok: raptor-size-field-ignores-capacity
  size->len = value->len - j - 1;
  size->data = name->data + len + 1;
  return 0;
}

// A reference count is not a capacity (nginx r->count).
typedef struct {
  uint8_t *request_start;
  int method;
  unsigned count;
  Str request_line;
} Request;
void set_request_line(Request *r, uint8_t *end) {
  r->request_line.data = r->request_start;
  // ok: raptor-size-field-ignores-capacity
  r->request_line.len = end - r->request_start;
}

// The object holding the buffer and its capacity is handed to a call that
// bounds the result (nginx regex captures: ngx_regex_exec(re, s, captures)).
int regex_exec(const Str *s, int *captures);
void capture_var(const Str *s, Str *vv) {
  int caps[4];
  if (regex_exec(s, caps) < 0)
    return;
  vv->data = s->data + caps[0];
  // ok: raptor-size-field-ignores-capacity
  vv->len = caps[1] - caps[0];
}
