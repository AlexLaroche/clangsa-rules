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
