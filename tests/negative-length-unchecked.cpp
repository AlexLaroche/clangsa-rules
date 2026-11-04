// raptor.NegativeLengthUnchecked: a signed length read from the data is
// checked only from above (`len > end - p`), in a signed comparison, and
// then used as a size or a pointer advance. A negative value passes the
// check and becomes a huge size_t (CWE-839, CWE-195).
// Modelled on CVE-2026-58662 (Apache Thrift, THeaderTransport::readString:
// `if (strLen > headerBoundary - ptr) throw ...; str.assign(ptr, strLen);`,
// fixed by `strLen < 0 ||`).
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <string>

uint32_t readVarint32(const uint8_t *ptr, int32_t *out, const uint8_t *end);
int32_t read_i32(const uint8_t *p);
[[noreturn]] void fail(const char *why);

// CVE-2026-58662
void readString(uint8_t *&ptr, std::string &str, const uint8_t *headerBoundary) {
  int32_t strLen;
  uint32_t bytes = readVarint32(ptr, &strLen, headerBoundary);
  if (strLen > headerBoundary - ptr)
    fail("Info header length exceeds header size");
  ptr += bytes;
  // ruleid: raptor-negative-length-unchecked
  str.assign(reinterpret_cast<const char *>(ptr), strLen);
  // ruleid: raptor-negative-length-unchecked
  ptr += strLen;
}

// The fix: a negative length is rejected.
void readStringFixed(uint8_t *&ptr, std::string &str, const uint8_t *headerBoundary) {
  int32_t strLen;
  uint32_t bytes = readVarint32(ptr, &strLen, headerBoundary);
  uint8_t *strStart = ptr + bytes;
  if (strLen < 0 || strLen > headerBoundary - strStart)
    fail("Info header length exceeds header size");
  // ok: raptor-negative-length-unchecked
  str.assign(reinterpret_cast<const char *>(strStart), strLen);
  // ok: raptor-negative-length-unchecked
  ptr = strStart + strLen;
}

// A signed comparison with a signed bound, then memcpy.
int copy_record(uint8_t *dst, const uint8_t *p) {
  uint8_t buf[256];
  int len = read_i32(p);
  if (len > (int)sizeof(buf))
    return -1;
  // ruleid: raptor-negative-length-unchecked
  memcpy(buf, p + 4, len);
  // ok: raptor-negative-length-unchecked
  memcpy(dst, buf, 16);
  return 0;
}

// Lower bound checked first, in its own statement.
int copy_record_checked(uint8_t *dst, const uint8_t *p) {
  int len = read_i32(p);
  if (len <= 0)
    return -1;
  if (len > 256)
    return -1;
  // ok: raptor-negative-length-unchecked
  memcpy(dst, p + 4, len);
  return 0;
}

// An unsigned comparison catches a negative value too.
int copy_unsigned_compare(uint8_t *dst, const uint8_t *p, size_t room) {
  int len = read_i32(p);
  if ((size_t)len > room)
    return -1;
  // ok: raptor-negative-length-unchecked
  memcpy(dst, p + 4, len);
  return 0;
}

int copy_unsigned_bound(uint8_t *dst, const uint8_t *p, size_t room) {
  int len = read_i32(p);
  if (len > room)
    return -1;
  // ok: raptor-negative-length-unchecked
  memcpy(dst, p + 4, len);
  return 0;
}

// The length is unsigned.
int copy_u32(uint8_t *dst, const uint8_t *p) {
  uint32_t len;
  readVarint32(p, (int32_t *)&len, p + 8);
  if (len > 256)
    return -1;
  // ok: raptor-negative-length-unchecked
  memcpy(dst, p + 4, len);
  return 0;
}

// No upper check at all: another rule's business.
void copy_unchecked(uint8_t *dst, const uint8_t *p) {
  int len = read_i32(p);
  // ok: raptor-negative-length-unchecked
  memcpy(dst, p + 4, len);
}

// Not from the data: computed from parameters.
void copy_computed(uint8_t *dst, const uint8_t *p, int a, int b) {
  int n = a + b;
  if (n > 64)
    return;
  // ok: raptor-negative-length-unchecked
  memcpy(dst, p, n);
}

// Used only as a signed value after the check.
int lookup(const uint8_t *p, const int *table) {
  int idx = read_i32(p);
  if (idx > 15)
    return -1;
  // ok: raptor-negative-length-unchecked
  return table[0] + idx;
}

// Lower bound checked through `>= 0` in the same condition.
int copy_range(uint8_t *dst, const uint8_t *p, const uint8_t *end) {
  int len = read_i32(p);
  if (!(len >= 0 && len <= end - p))
    return -1;
  // ok: raptor-negative-length-unchecked
  memcpy(dst, p, len);
  return 0;
}

// `len >= need` on the path that uses len is a lower bound (libarchive cpio).
const uint8_t *read_ahead(size_t min, long *avail);
int find_header(uint8_t *dst) {
  long bytes;
  const uint8_t *h = read_ahead(76, &bytes);
  if (h == nullptr) {
    if (bytes >= 26)
      h = read_ahead(26, &bytes);
    if (h == nullptr)
      return -1;
  }
  // ok: raptor-negative-length-unchecked
  memcpy(dst, h, bytes);
  return 0;
}

// A loop bound: `i < n` keeps n positive on the path of the loop body.
void fill(uint8_t *dst, const uint8_t *p) {
  int n = read_i32(p);
  for (int i = 0; i < n; i++)
    dst[i] = 0;
  // ok: raptor-negative-length-unchecked
  memset(dst, 1, n);
}

// `if (len < max) use;`: an upper bound with no exit.
void copy_if_small(uint8_t *dst, const uint8_t *p) {
  int len = read_i32(p);
  if (len < 64)
    // ruleid: raptor-negative-length-unchecked
    memcpy(dst, p + 4, len);
}

// Program state kept in a field, not decoded here (libtiff fax3 lastx).
struct State {
  int rowpixels;
};
void fill_row(uint8_t *row, const State *sp, int limit) {
  int lastx = sp->rowpixels;
  if (lastx > limit)
    return;
  // ok: raptor-negative-length-unchecked
  memset(row, 0, lastx);
}

// Set from a narrower unsigned value: never negative (libarchive lha, 7zip).
uint32_t le32dec(const uint8_t *p);
int copy_name(uint8_t *dst, const uint8_t *p, const uint8_t *end) {
  int namelen = p[0];
  long offset = le32dec(p + 4);
  if (namelen > 221 || offset > end - p)
    return -1;
  // ok: raptor-negative-length-unchecked
  memcpy(dst, p + 8, namelen);
  // ok: raptor-negative-length-unchecked
  memcpy(dst, p + offset, 4);
  // A same-width conversion can wrap to negative.
  int32_t len = (int32_t)le32dec(p);
  if (len > end - p)
    return -1;
  // ruleid: raptor-negative-length-unchecked
  memcpy(dst, p, len);
  return 0;
}
