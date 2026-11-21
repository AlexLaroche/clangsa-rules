// raptor.SumBoundsCheckWraps: a bounds check `pos + n > LIMIT` on 32-bit
// unsigned values, where neither pos nor n is bounded on its own. A huge n
// wraps the sum below LIMIT, the check passes, and the copy at pos of n bytes
// (or the index pos + n) goes out of bounds (CWE-190 -> CWE-787, CWE-125).
// Modelled on mupen64plus CVE-2025-9688 (write_is_viewer: `buffer_pos + word
// > IS_BUFFER_SIZE`; the fix adds `buffer_pos > IS_BUFFER_SIZE || word >
// IS_BUFFER_SIZE ||`) and Fast DDS CVE-2025-62601 (CDRMessage::readData:
// `msg->pos + length > msg->length`).
#include <stdint.h>
#include <string.h>

#define IS_BUFFER_SIZE 0x1000
struct is_viewer {
  char data[IS_BUFFER_SIZE];
  char output_buffer[IS_BUFFER_SIZE];
  uint32_t buffer_pos;
};

// mupen64plus src/device/cart/is_viewer.c
void write_is_viewer(void *opaque, uint32_t address, uint32_t value, uint32_t mask) {
  struct is_viewer *is_viewer = (struct is_viewer *)opaque;
  uint32_t word = value & mask;
  if (address == 0x14) {
    if (word > 0) {
      // ruleid: raptor-sum-bounds-check-wraps
      if (is_viewer->buffer_pos + word > IS_BUFFER_SIZE) {
        is_viewer->buffer_pos = 0;
        return;
      }
      memcpy(&is_viewer->output_buffer[is_viewer->buffer_pos], &is_viewer->data[0x20], word);
      is_viewer->buffer_pos += word;
    }
  }
}

// The fix.
void write_is_viewer_fixed(void *opaque, uint32_t value, uint32_t mask) {
  struct is_viewer *is_viewer = (struct is_viewer *)opaque;
  uint32_t word = value & mask;
  if (word > 0) {
    // ok: raptor-sum-bounds-check-wraps
    if (is_viewer->buffer_pos > IS_BUFFER_SIZE || word > IS_BUFFER_SIZE ||
        is_viewer->buffer_pos + word > IS_BUFFER_SIZE) {
      is_viewer->buffer_pos = 0;
      return;
    }
    memcpy(&is_viewer->output_buffer[is_viewer->buffer_pos], &is_viewer->data[0x20], word);
  }
}

// Fast DDS include/fastdds/rtps/messages/CDRMessage.hpp
struct cdr_message {
  unsigned char *buffer;
  uint32_t pos, length;
};
int read_data(struct cdr_message *msg, unsigned char *o, uint32_t length) {
  if (msg == 0)
    return 0;
  // ruleid: raptor-sum-bounds-check-wraps
  if (msg->pos + length > msg->length)
    return 0;
  memcpy(o, &msg->buffer[msg->pos], length);
  msg->pos += length;
  return 1;
}

// The fix (subtract instead of add).
int read_data_fixed(struct cdr_message *msg, unsigned char *o, uint32_t length) {
  // ok: raptor-sum-bounds-check-wraps
  if (msg->pos > msg->length || length > msg->length - msg->pos)
    return 0;
  memcpy(o, &msg->buffer[msg->pos], length);
  return 1;
}

// An earlier bound on the length is enough (the position is ours).
int read_capped(struct cdr_message *msg, unsigned char *o, uint32_t length) {
  if (length > 65536)
    return 0;
  // ok: raptor-sum-bounds-check-wraps
  if (msg->pos + length > msg->length)
    return 0;
  memcpy(o, &msg->buffer[msg->pos], length);
  return 1;
}

// Not this rule: 64-bit sums, narrow operands (promoted to int), sums whose
// terms never reach memory, a constant term.
int read64(unsigned char *buf, uint64_t pos, uint64_t n, uint64_t size, unsigned char *o) {
  // ok: raptor-sum-bounds-check-wraps
  if (pos + n > size)
    return 0;
  memcpy(o, buf + pos, n);
  return 1;
}
int read16(unsigned char *buf, uint16_t pos, uint16_t n, unsigned char *o) {
  // ok: raptor-sum-bounds-check-wraps
  if (pos + n > 4096)
    return 0;
  memcpy(o, buf + pos, n);
  return 1;
}
int counts(uint32_t a, uint32_t b, uint32_t limit) {
  // ok: raptor-sum-bounds-check-wraps
  if (a + b > limit)
    return 0;
  return 1;
}
int plus_header(unsigned char *buf, uint32_t pos, unsigned char *o) {
  // ok: raptor-sum-bounds-check-wraps
  if (pos + 4 > 4096)
    return 0;
  memcpy(o, buf + pos, 4);
  return 1;
}

// --- noise seen in wolfSSL, HAProxy ---

// A 16-bit term cannot wrap a 32-bit sum (wolfSSL `offset + len16 >
// helloSz` with `word16 len16`).
int ext(const unsigned char *hello, uint32_t helloSz, uint32_t offset, unsigned char *o) {
  uint16_t len16 = (uint16_t)(hello[offset] << 8 | hello[offset + 1]);
  // ok: raptor-sum-bounds-check-wraps
  if (offset + len16 > helloSz)
    return 0;
  memcpy(o, hello + offset, len16);
  return 1;
}

// Assertions written as macros (HAProxy BUG_ON_HOT).
void abort(void);
#define BUG_ON(c) do { if (c) abort(); } while (0)
void put_at(char *buf, uint32_t size, uint32_t off, uint32_t len, const char *src) {
  // ok: raptor-sum-bounds-check-wraps
  BUG_ON(off + len > size);
  memcpy(buf + off, src, len);
}
