// raptor.MemcpyLengthUnboundedByDest: memcpy()/memmove() into a fixed-size
// array (local, static, global, array parameter or struct field) with a
// length that nothing in the function bounds by that array: no comparison
// with a constant that fits, no MIN(), and a type wide enough to exceed it
// (CWE-120, CWE-787).
// Modelled on capstone CVE-2025-67873 (cs_disasm skipdata: the length is
// compared with the source size only), esp-usb CVE-2025-68622 (descriptor
// bLength copied into a 100-byte local), libcoap CVE-2025-34468 (host name
// into `static char addrstr[256]`) and GnuTLS CVE-2025-9820 (token label
// `memcpy(flabel, label, strlen(label))` into 32 bytes).
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

// capstone cs.c cs_disasm_iter
typedef struct {
  uint16_t size;
  uint8_t bytes[24];
} cs_insn;
typedef size_t (*skip_cb)(const uint8_t *, size_t, size_t, void *);
int skipdata(cs_insn *insn, const uint8_t *code, size_t size, skip_cb cb) {
  size_t skipdata_bytes = cb(code, size, 0, 0);
  if (skipdata_bytes > size)
    return 0;
  insn->size = (uint16_t)skipdata_bytes;
  // ruleid: raptor-memcpy-length-unbounded-by-dest
  memcpy(insn->bytes, code, skipdata_bytes);
  return 1;
}

// The fix: MIN(skipdata_bytes, sizeof(insn->bytes)).
int skipdata_fixed(cs_insn *insn, const uint8_t *code, size_t size, skip_cb cb) {
  size_t skipdata_bytes = cb(code, size, 0, 0);
  if (skipdata_bytes > size)
    return 0;
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(insn->bytes, code, MIN(skipdata_bytes, sizeof(insn->bytes)));
  return 1;
}

// esp-usb uvc_descriptor_printing.c print_vs_frame_mjpeg_desc
typedef struct {
  uint8_t bLength;
  uint8_t bDescriptorType;
} usb_standard_desc_t;
void print_frame_desc(const usb_standard_desc_t *_desc) {
  uint32_t raw_desc[25];
  uint32_t desc_size = _desc->bLength;
  // ruleid: raptor-memcpy-length-unbounded-by-dest
  memcpy(raw_desc, _desc, desc_size);
  (void)raw_desc;
}

// libcoap coap_address.c coap_resolve_address_info
typedef struct {
  size_t length;
  const uint8_t *s;
} coap_str_const_t;
int is_unix(const coap_str_const_t *);
const char *resolve(const coap_str_const_t *address) {
  static char addrstr[256];
  if (address && is_unix(address)) {
    // bounds the Unix socket path only, in a branch that returns
    if (address->length >= 108)
      return NULL;
    return "unix";
  }
  memset(addrstr, 0, sizeof(addrstr));
  if (address && address->length)
    // ruleid: raptor-memcpy-length-unbounded-by-dest
    memcpy(addrstr, address->s, address->length);
  else
    // ok: raptor-memcpy-length-unbounded-by-dest
    memcpy(addrstr, "localhost", 9);
  return addrstr;
}

// The fix.
const char *resolve_fixed(const coap_str_const_t *address) {
  static char addrstr[256];
  memset(addrstr, 0, sizeof(addrstr));
  if (address && address->length) {
    if (address->length >= sizeof(addrstr))
      return NULL;
    // ok: raptor-memcpy-length-unbounded-by-dest
    memcpy(addrstr, address->s, address->length);
  }
  return addrstr;
}

// GnuTLS pkcs11_write.c gnutls_pkcs11_token_init
int token_init(const char *label) {
  char flabel[32];
  memset(flabel, ' ', sizeof(flabel));
  // ruleid: raptor-memcpy-length-unbounded-by-dest
  memcpy(flabel, label, strlen(label));
  return flabel[0];
}

// The fix.
int token_init_fixed(const char *label) {
  char flabel[32];
  memset(flabel, ' ', sizeof(flabel));
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(flabel, label, MIN(sizeof(flabel), strlen(label)));
  return flabel[0];
}

// Bounded through a local holding the length, with a constant that fits.
int copy_checked(const uint8_t *p, size_t len) {
  uint8_t buf[64];
  size_t n = len + 1;
  if (len >= 64)
    return -1;
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(buf, p, n);
  return buf[0];
}

// A bound that does not fit the destination does not count.
int copy_wrong_bound(const uint8_t *p) {
  uint8_t buf[64];
  size_t len = (size_t)p[0] << 8 | p[1];
  if (len > 128)
    return -1;
  // ruleid: raptor-memcpy-length-unbounded-by-dest
  memmove(buf, p, len);
  return buf[0];
}

// Clamped with ?: against sizeof.
int copy_clamped(const uint8_t *p, size_t len) {
  uint8_t buf[64];
  size_t n = len < sizeof(buf) ? len : sizeof(buf);
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(buf, p, n);
  return buf[0];
}

// A length whose type cannot exceed the destination.
int copy_byte_len(const uint8_t *p, uint8_t len) {
  uint8_t buf[256];
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(buf, p, len);
  return buf[0];
}

// Constant lengths and sizeof.
struct hdr {
  uint8_t magic[4];
  uint8_t data[1]; // trailing-array idiom
  uint8_t tail[];
};
int constants(struct hdr *h, const uint8_t *p, size_t len) {
  uint8_t buf[16];
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(buf, p, sizeof(buf));
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(h->magic, p, 4);
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(h->data, p, len);
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(h->tail, p, len);
  return buf[0];
}

// Not a fixed array: a pointer destination.
int to_pointer(uint8_t *out, const uint8_t *p, size_t len) {
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(out, p, len);
  return out[0];
}

// The caller's fixed buffer: a parameter declared with a size.
void to_param_array(uint8_t out[16], const char *name) {
  // ruleid: raptor-memcpy-length-unbounded-by-dest
  memcpy(out, name, strlen(name));
}

// --- noise seen in OpenSSL ---

// A plain parameter as the length: the caller's contract (ffc seed_len,
// blake2 personal/salt len, slh_dsa n).
struct blake2_param {
  uint8_t salt[16];
};
void set_salt(struct blake2_param *P, const uint8_t *salt, size_t len) {
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(P->salt, salt, len);
}

// The source is a fixed array no larger than the destination (cmac copy).
struct cmac_ctx {
  uint8_t k1[32], tbl[32];
  int nlast_block;
};
void cmac_copy(struct cmac_ctx *out, const struct cmac_ctx *in, int bl) {
  int n = bl * 2;
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(out->k1, in->k1, n);
}

// The length is a field of the destination's own object (an invariant set
// where the field is validated: ctx->ivlen, ctx->aid_len).
struct cipher_ctx {
  uint8_t iv[16], oiv[16];
  size_t ivlen;
  uint8_t aid_buf[256];
  size_t aid_len;
  uint8_t tag[16];
  size_t taglen;
};
void reset_iv(struct cipher_ctx *ctx, const uint8_t *aid) {
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(ctx->iv, ctx->oiv, ctx->ivlen);
  // ok: raptor-memcpy-length-unbounded-by-dest
  memmove(ctx->aid_buf, aid, ctx->aid_len);
}

// Checked for equality with a field of the destination's object (OCB tag).
typedef struct {
  const uint8_t *data;
  size_t data_size;
} param_t;
int set_tag(struct cipher_ctx *ctx, const param_t *tag) {
  if (tag->data_size != ctx->taglen)
    return 0;
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(ctx->tag, tag->data, tag->data_size);
  // still reported: the (pointer, size) pair of another object
  if (tag->data_size > 0)
    // ruleid: raptor-memcpy-length-unbounded-by-dest
    memcpy(ctx->aid_buf, tag->data, tag->data_size);
  return 1;
}

// A remainder that fits (CTS residue = len % 16).
void cts_tail(const uint8_t *in, size_t total) {
  uint8_t tmp[16];
  size_t residue = total % 16;
  // ok: raptor-memcpy-length-unbounded-by-dest
  memcpy(tmp, in, residue);
  (void)tmp;
}
