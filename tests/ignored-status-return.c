// raptor.IgnoredStatusReturn: the result of a status-returning function
// defined in the same translation unit is discarded (CWE-252).
// Modelled on CVE-2026-111497 ("Broccoli2Shell"), google/brotli <= 1.0.9,
// c/dec/decode.c: the fast-path DecodeLiteralBlockSwitch() dropped the
// BROTLI_FALSE returned for an invalid block switch and decoding continued
// with a corrupt block type, leading to an out-of-bounds write.
#include <stddef.h>

#define BROTLI_BOOL int
#define BROTLI_TRUE 1
#define BROTLI_FALSE 0

typedef enum {
  DECODER_SUCCESS = 1,
  DECODER_NEEDS_MORE_INPUT = 2,
  DECODER_ERROR_FORMAT_BLOCK_SWITCH = -17
} DecoderErrorCode;

typedef struct {
  unsigned num_block_types[3];
  unsigned block_type_rb[6];
  unsigned char *context_map_slice;
  unsigned char context_map[64];
} State;

unsigned ReadSymbol(State *s);

static BROTLI_BOOL DecodeBlockTypeAndLength(int safe, State *s, int tree_type) {
  unsigned max_block_type = s->num_block_types[tree_type];
  unsigned block_type;
  if (max_block_type <= 1)
    return BROTLI_FALSE;
  block_type = ReadSymbol(s);
  if (safe && block_type == 0)
    return BROTLI_FALSE;
  s->block_type_rb[tree_type * 2 + 1] = block_type;
  return BROTLI_TRUE;
}

static void PrepareLiteralDecoding(State *s) {
  s->context_map_slice = s->context_map + (s->block_type_rb[1] << 6);
}

static BROTLI_BOOL DecodeLiteralBlockSwitchInternal(int safe, State *s) {
  // ok: raptor-ignored-status-return
  if (!DecodeBlockTypeAndLength(safe, s, 0))
    return BROTLI_FALSE;
  // ok: raptor-ignored-status-return
  PrepareLiteralDecoding(s);
  return BROTLI_TRUE;
}

// The Broccoli2Shell fast path.
static void DecodeLiteralBlockSwitch(State *s) {
  // ruleid: raptor-ignored-status-return
  DecodeLiteralBlockSwitchInternal(0, s);
}

static BROTLI_BOOL SafeDecodeLiteralBlockSwitch(State *s) {
  // ok: raptor-ignored-status-return
  return DecodeLiteralBlockSwitchInternal(1, s);
}

// Fixed upstream shape: an error code forwarded through the wrapper.
static DecoderErrorCode DecodeCommandBlockSwitchInternal(int safe, State *s) {
  if (s->num_block_types[1] <= 1)
    return DECODER_ERROR_FORMAT_BLOCK_SWITCH;
  if (safe)
    return DECODER_NEEDS_MORE_INPUT;
  return DECODER_SUCCESS;
}

static DecoderErrorCode DecodeCommandBlockSwitch(State *s) {
  // ok: raptor-ignored-status-return
  return DecodeCommandBlockSwitchInternal(0, s);
}

void ProcessCommands(State *s, int n) {
  int i;
  // ruleid: raptor-ignored-status-return
  DecodeCommandBlockSwitch(s);
  for (i = 0; i < n; i++)
    // ruleid: raptor-ignored-status-return
    DecodeCommandBlockSwitchInternal(1, s);
  if (n)
    // ruleid: raptor-ignored-status-return
    DecodeBlockTypeAndLength(0, s, 2);
  // ruleid: raptor-ignored-status-return
  i = 0, DecodeLiteralBlockSwitchInternal(0, s);
}

void ProcessChecked(State *s) {
  DecoderErrorCode r;
  // ok: raptor-ignored-status-return
  r = DecodeCommandBlockSwitch(s);
  if (r != DECODER_SUCCESS)
    return;
  // ok: raptor-ignored-status-return
  (void)DecodeCommandBlockSwitchInternal(0, s);
  // ok: raptor-ignored-status-return
  while (!DecodeLiteralBlockSwitchInternal(1, s)) {
  }
}

// Not status functions: a single constant, or computed values.
static int AlwaysZero(State *s) {
  s->block_type_rb[0] = 0;
  return 0;
}

static size_t CountTypes(State *s) {
  if (s->num_block_types[0] == 0)
    return 0;
  return s->num_block_types[0] + s->num_block_types[1];
}

int ReadOnly(State *s);

void NotStatus(State *s) {
  // ok: raptor-ignored-status-return
  AlwaysZero(s);
  // ok: raptor-ignored-status-return
  CountTypes(s);
  // ok: raptor-ignored-status-return
  ReadOnly(s);
}

// Mutual recursion must not hang the analysis.
static int Ping(int n);
static int Pong(int n) { return n ? Ping(n - 1) : 1; }
static int Ping(int n) { return n ? Pong(n - 1) : 0; }

void Recurse(void) {
  // ok: raptor-ignored-status-return
  Ping(3);
}

// Result checked by the other callers: a deviant discard.
// CVE-2025-49600 (Mbed TLS < 3.6.4, library/lms.c): mbedtls_lms_verify()
// ignored create_merkle_leaf_value(), which only forwards a PSA status, so an
// injected hash failure let a forged signature verify.
typedef int psa_status_t;
int psa_to_mbedtls(psa_status_t status);
psa_status_t psa_hash(const unsigned char *in, unsigned char *out);

static int create_leaf(const unsigned char *key, unsigned char *out) {
  psa_status_t status = psa_hash(key, out);
  return psa_to_mbedtls(status);
}

int lms_verify(const unsigned char *key, unsigned char *root) {
  // ruleid: raptor-ignored-status-return
  create_leaf(key, root);
  return root[0] == 0 ? 0 : -1;
}

int lms_build(const unsigned char *key, unsigned char *tree) {
  int ret;
  // ok: raptor-ignored-status-return
  ret = create_leaf(key, tree);
  if (ret != 0)
    return ret;
  return 0;
}

// A pointer result checked against NULL elsewhere.
// CVE-2020-6072 (libmicrodns 0.1.0, src/rr.c): the recursive rr_decode()
// call ignored a NULL (error) result and went on with a freed name.
static const unsigned char *rr_decode(const unsigned char *ptr, size_t *n, char **ss);

static const unsigned char *rr_read_srv(const unsigned char *ptr, size_t *n, char **target) {
  // ok: raptor-ignored-status-return
  if ((ptr = rr_decode(ptr, n, target)) == NULL)
    return NULL;
  return ptr;
}

static const unsigned char *rr_read_ptr(const unsigned char *ptr, size_t *n, char **domain) {
  // ok: raptor-ignored-status-return
  if ((ptr = rr_decode(ptr, n, domain)) == NULL)
    return NULL;
  return ptr;
}

static const unsigned char *rr_decode(const unsigned char *ptr, size_t *n, char **ss) {
  char *buf = NULL;
  size_t m = 0;
  if (*n == 0)
    return NULL;
  if (ptr[0] & 0xc0) {
    // ruleid: raptor-ignored-status-return
    rr_decode(ptr + 1, &m, &buf);
    *ss = buf;
  }
  return ptr + 1;
}

// Mostly discarded: discarding is the norm for this function.
int log_line(const char *msg);
static int emit(const char *msg) { return log_line(msg); }
void report_all(void) {
  // ok: raptor-ignored-status-return
  emit("a");
  // ok: raptor-ignored-status-return
  emit("b");
  // ok: raptor-ignored-status-return
  emit("c");
  if (emit("d") < 0)
    return;
}

// Used, but never checked, elsewhere (a count passed on).
static int count_items(const int *v) { return v[0] + v[1]; }
int total(const int *v);
int sum_twice(const int *v) {
  // ok: raptor-ignored-status-return
  count_items(v);
  return total(v) + count_items(v);
}

// A status function the file never checks (libtiff tiffcrop dump_byte):
// discarding is the norm here.
static int dump_byte(int fd, unsigned char b) {
  if (fd < 0)
    return 1;
  return b ? 0 : 2;
}
void dump_all(int fd, const unsigned char *p) {
  // ok: raptor-ignored-status-return
  dump_byte(fd, p[0]);
  // ok: raptor-ignored-status-return
  dump_byte(fd, p[1]);
}

// Ignored on a path that is already failing (curl content_encoding.c).
static int machine(State *s, int ev) { return ev > 0 ? 0 : -1; }
int on_data(State *s, int result) {
  if (machine(s, 1))
    return -1;
  if (result) {
    // ok: raptor-ignored-status-return
    machine(s, -1);
    return result;
  }
  // ruleid: raptor-ignored-status-return
  machine(s, 2);
  return 0;
}

// Teardown whose status nobody can act on (libarchive xar _checksum_final).
static int checksum_final(State *s) { return s->num_block_types[0] ? 0 : -1; }
int finish(State *s) {
  if (checksum_final(s) != 0)
    return -1;
  return 0;
}
void cleanup(State *s) {
  // ok: raptor-ignored-status-return
  checksum_final(s);
}

// A status kept in a variable (`err = CONST; ... return err;`) whose early
// failure exit skips filling the caller's buffer, and the only caller hands
// it an uninitialised local and ignores the status, then reads the buffer.
// microsoft/SymCrypt lib/tlsCbcVerify.c: SymCryptTlsCbcHmacVerifyCore
// returns SYMCRYPT_BUFFER_TOO_SMALL before wiping abMacValue, and
// SymCryptTlsCbcHmacVerify compares the uninitialised bytes (CWE-252 -> 457).
#define ERR_NONE 0
#define ERR_TOO_SMALL 0x8001
static int verify_core(const unsigned char *data, size_t len, unsigned char *mac,
                       unsigned *pad_err) {
  int err = ERR_NONE;
  unsigned bad = 0;
  if (len < 33) {
    err = ERR_TOO_SMALL;
    goto cleanup;
  }
  for (size_t i = 0; i < 32; i++)
    mac[i] = data[len - 33 + i];
  bad = data[len - 1] > len - 33;
cleanup:
  *pad_err = bad;
  return err;
}
int tls_cbc_verify(const unsigned char *data, size_t len, const unsigned char *expect) {
  unsigned char mac[32];
  unsigned pad_err;
  // ruleid: raptor-ignored-status-return
  verify_core(data, len, mac, &pad_err);
  for (int i = 0; i < 32; i++)
    pad_err |= mac[i] ^ expect[i];
  return pad_err == 0 ? 0 : -1;
}

// The same status-variable shape filling a struct through &local.
typedef struct { unsigned type, len; } Header;
static int parse_header(const unsigned char *p, size_t n, Header *h) {
  int rc = -1;
  if (n < 4)
    return rc;
  h->type = p[0];
  h->len = p[1] << 8 | p[2];
  rc = 0;
  return rc;
}
unsigned header_len(const unsigned char *p, size_t n) {
  Header h;
  // ruleid: raptor-ignored-status-return
  parse_header(p, n, &h);
  return h.len;
}

// ok: the buffer is initialised before the call, so ignoring the status
// cannot expose uninitialised memory.
unsigned header_len_default(const unsigned char *p, size_t n) {
  Header h = {0, 0};
  // ok: raptor-ignored-status-return
  parse_header(p, n, &h);
  return h.len;
}

// ok: the uninitialised local is not passed to the callee.
static int touch(const unsigned char *p, size_t n) {
  int rc = 0;
  if (n == 0)
    rc = -1;
  return rc;
}
unsigned first(const unsigned char *p, size_t n) {
  unsigned v;
  // ok: raptor-ignored-status-return
  touch(p, n);
  v = n ? p[0] : 0;
  return v;
}

// ok: the returned variable is not a status (a computed length).
static int fill_count(const unsigned char *p, size_t n, unsigned char *out) {
  int count = 0;
  for (size_t i = 0; i < n; i++)
    if (p[i])
      out[count++] = p[i];
  return count;
}
void copy_nonzero(const unsigned char *p, size_t n) {
  unsigned char tmp[64];
  // ok: raptor-ignored-status-return
  fill_count(p, n < 64 ? n : 64, tmp);
}

// ok: with these constant arguments the callee cannot fail: its failure
// returns are guarded by tests on parameters that the constants make false
// (SymCrypt SymCryptChaCha20Selftest / SymCryptRc4Selftest).
static const unsigned char test_key[32] = {1};
static int stream_init(unsigned char *st, const unsigned char *key, size_t cb_key,
                       size_t cb_nonce) {
  int err = ERR_NONE;
  if (cb_key != 32) {
    err = ERR_TOO_SMALL;
    goto out;
  }
  if (cb_nonce != 12) {
    err = -2;
    goto out;
  }
  st[0] = key[0];
out:
  return err;
}
int stream_selftest(void) {
  unsigned char st[16];
  // ok: raptor-ignored-status-return
  stream_init(st, test_key, sizeof(test_key), 12);
  return st[0];
}
// A constant that does trip a guard is still reported.
int stream_selftest_bad(void) {
  unsigned char st[16];
  // ruleid: raptor-ignored-status-return
  stream_init(st, test_key, 16, 12);
  return st[0];
}
// The non-constant case is reported as before.
int stream_use(const unsigned char *key, size_t n) {
  unsigned char st[16];
  // ruleid: raptor-ignored-status-return
  stream_init(st, key, n, 12);
  return st[0];
}

// ok: a function that only ever returns one value cannot fail, even if
// another caller checks it defensively (SymCrypt SymCryptKmac128ExpandKeyEx).
#define OK_STATUS 0
static int expand_key(unsigned char *k, const unsigned char *key) {
  k[0] = key[0];
  return OK_STATUS;
}
int derive(unsigned char *k, const unsigned char *key) {
  if (expand_key(k, key) != OK_STATUS)
    return -1;
  return 0;
}
void kmac_selftest(void) {
  unsigned char k[8];
  // ok: raptor-ignored-status-return
  expand_key(k, test_key);
}

// Known false positive: the caller has already rejected the values that make
// the callee fail (SymCrypt SymCryptXmsskeySetValue validates keyType before
// SymCryptXmssSizeofKeyBlobFromParams, whose `default:` returns an error).
static int blob_size(int type, size_t *cb) {
  int err = ERR_NONE;
  switch (type) {
  case 1: *cb = 64; break;
  case 2: *cb = 128; break;
  default: err = -1; break;
  }
  return err;
}
int set_value(const unsigned char *in, size_t n, int type) {
  size_t cb;
  if (type != 1 && type != 2)
    return -1;
  // todook: raptor-ignored-status-return
  blob_size(type, &cb);
  return n == cb ? in[0] : -1;
}
