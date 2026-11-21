// raptor.FixedOffsetReadNoLengthCheck: a byte buffer that comes with its
// length is read at a fixed offset (`buf[3]`, `buf[off + 2]`, `buf + 9`
// passed to a reader) and nothing before the read compares the length with
// that offset. A short (truncated) input is read past its end (CWE-125).
// Modelled on Mbed TLS CVE-2025-49601 (mbedtls_lms_import_public_key reads
// the 4-byte type before checking key_size) and BACnet-stack CVE-2025-66624
// (npdu_is_expected_reply reads request_pdu[offset + 2] with only
// `request_pdu_len > 0` checked).
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BAD_INPUT (-1)
#define GET_UINT32_BE(b, i)                                                              \
  (((uint32_t)(b)[(i)] << 24) | ((uint32_t)(b)[(i) + 1] << 16) |                         \
   ((uint32_t)(b)[(i) + 2] << 8) | ((uint32_t)(b)[(i) + 3]))
#define TYPE_OFFSET 0
#define OTSTYPE_OFFSET 4
#define PUBLIC_KEY_LEN(t) (24 + 32 * (t))

struct lms_ctx {
  uint32_t type, otstype;
  unsigned char id[16];
};

// Mbed TLS library/lms.c (3.6.3)
int lms_import_public_key(struct lms_ctx *ctx, const unsigned char *key, size_t key_size) {
  uint32_t type;
  // ruleid: raptor-fixed-offset-read-no-length-check
  type = GET_UINT32_BE(key, TYPE_OFFSET);
  if (type != 6)
    return BAD_INPUT;
  ctx->type = type;
  if (key_size != PUBLIC_KEY_LEN(ctx->type))
    return BAD_INPUT;
  // ok: raptor-fixed-offset-read-no-length-check
  ctx->otstype = GET_UINT32_BE(key, OTSTYPE_OFFSET);
  return 0;
}

// The fix.
int lms_import_public_key_fixed(struct lms_ctx *ctx, const unsigned char *key,
                                size_t key_size) {
  if (key_size < 4)
    return BAD_INPUT;
  // ok: raptor-fixed-offset-read-no-length-check
  uint32_t type = GET_UINT32_BE(key, TYPE_OFFSET);
  if (type != 6)
    return BAD_INPUT;
  ctx->type = type;
  return 0;
}

// BACnet-stack src/bacnet/npdu.c
int npdu_decode(const uint8_t *pdu, uint16_t pdu_len);
int is_expected_reply(const uint8_t *request_pdu, uint16_t request_pdu_len,
                      const uint8_t *reply_pdu, uint16_t reply_pdu_len) {
  int offset;
  uint8_t invoke_id, service;
  if ((request_pdu_len > 0) && (request_pdu[0] != 1))
    return 0;
  offset = npdu_decode(request_pdu, request_pdu_len);
  if (offset <= 0)
    return 0;
  if ((request_pdu[offset] & 0xF0) != 0)
    return 0;
  // ruleid: raptor-fixed-offset-read-no-length-check
  invoke_id = request_pdu[offset + 2];
  if (request_pdu[offset] & 8)
    service = request_pdu[offset + 5];
  else
    service = request_pdu[offset + 3];
  (void)reply_pdu;
  (void)reply_pdu_len;
  return invoke_id + service;
}

// The fix.
int is_expected_reply_fixed(const uint8_t *request_pdu, uint16_t request_pdu_len) {
  int offset;
  uint8_t invoke_id;
  offset = npdu_decode(request_pdu, request_pdu_len);
  if (offset <= 0)
    return 0;
  if (request_pdu_len <= offset + 2)
    return 0;
  // ok: raptor-fixed-offset-read-no-length-check
  invoke_id = request_pdu[offset + 2];
  return invoke_id;
}

// A pointer at a fixed offset handed to a reader (libssh2 `_libssh2_ntohu32(data
// + 5)`), a dereference.
uint32_t ntohu32(const unsigned char *p);
uint32_t status_code(const unsigned char *data, size_t data_len) {
  // ruleid: raptor-fixed-offset-read-no-length-check
  uint32_t code = ntohu32(data + 5);
  if (data_len < 13)
    return 0;
  return code;
}
// A reader whose name gives its width reads 4 bytes even at offset 0
// (Mbed TLS 3.6 MBEDTLS_GET_UINT32_BE -> mbedtls_get_unaligned_uint32(key + 0)).
uint32_t get_unaligned_uint32(const void *p);
uint32_t read_type(const unsigned char *key, size_t key_size) {
  // ruleid: raptor-fixed-offset-read-no-length-check
  uint32_t t = get_unaligned_uint32(key + 0);
  return key_size == 24 ? t : 0;
}
uint32_t read_type_fixed(const unsigned char *key, size_t key_size) {
  if (key_size < 4)
    return 0;
  // ok: raptor-fixed-offset-read-no-length-check
  return get_unaligned_uint32(key);
}
int same_prefix(const unsigned char *buf, size_t len) {
  // ok: raptor-fixed-offset-read-no-length-check
  return memcmp(buf, "abc", 1);
}
unsigned char second(const unsigned char *buf, size_t len) {
  // ruleid: raptor-fixed-offset-read-no-length-check
  unsigned char c = *(buf + 1);
  return len > 8 ? c : 0;
}

// Checks that count: a minimum, an exact size, a check against a non-constant
// size, `len < sizeof(hdr)`, a size computed from the length.
struct hdr {
  uint8_t ver, type, flags, pad;
};
unsigned char flags_min(const unsigned char *buf, size_t len) {
  if (len < 4)
    return 0;
  // ok: raptor-fixed-offset-read-no-length-check
  return buf[2];
}
unsigned char flags_hdr(const unsigned char *buf, size_t len) {
  if (len < sizeof(struct hdr))
    return 0;
  // ok: raptor-fixed-offset-read-no-length-check
  return buf[2];
}
unsigned char flags_loop(const unsigned char *buf, size_t len) {
  unsigned s = 0;
  for (size_t i = 0; i + 1 < len; i += 2)
    // ok: raptor-fixed-offset-read-no-length-check
    s += buf[i + 1];
  return s;
}
unsigned char flags_ternary(const unsigned char *buf, size_t len) {
  // ok: raptor-fixed-offset-read-no-length-check
  return len > 2 ? buf[2] : 0;
}

// A check that is too small for the offset is no check.
unsigned char flags_nonempty(const unsigned char *buf, size_t len) {
  if (len == 0)
    return 0;
  // ruleid: raptor-fixed-offset-read-no-length-check
  return buf[2];
}

// Not this rule: no length comes with the buffer, offset 0, writes, a
// buffer of fixed size, a length that is not the buffer's.
unsigned char no_len(const unsigned char *buf) {
  // ok: raptor-fixed-offset-read-no-length-check
  return buf[3];
}
unsigned char first(const unsigned char *buf, size_t len) {
  // ok: raptor-fixed-offset-read-no-length-check
  return buf[0];
}
void put(unsigned char *out, size_t outlen) {
  // ok: raptor-fixed-offset-read-no-length-check
  out[1] = 0;
}
unsigned char fixed(const unsigned char buf[16], size_t len) {
  // ok: raptor-fixed-offset-read-no-length-check
  return buf[3];
}
unsigned char other_len(const unsigned char *buf, const char *name, size_t namelen) {
  // ok: raptor-fixed-offset-read-no-length-check
  return buf[3];
}

// --- noise seen in SymCrypt, nginx, libsodium, OpenSSH ---

// A function given `buf + 16` reads as many bytes as its own length says.
void encrypt_block(const unsigned char *in, size_t n, unsigned char *out);
void enc_tail(const unsigned char *buf, size_t len, unsigned char *out) {
  // ok: raptor-fixed-offset-read-no-length-check
  encrypt_block(buf + 16, len - 16, out);
}

// A switch on the length guards its cases (siphash tail).
uint64_t tail(const unsigned char *data, size_t size) {
  uint64_t m = 0;
  switch (size) {
  case 7:
    // ok: raptor-fixed-offset-read-no-length-check
    m |= (uint64_t)data[6] << 48;
  }
  return m;
}

// Primitives whose length is never compared with anything: the caller
// passes a fixed-size block (hash/cipher block loads).
uint32_t stream2word(const unsigned char *data, size_t databytes) {
  // ok: raptor-fixed-offset-read-no-length-check
  return data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
}
