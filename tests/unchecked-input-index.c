// raptor.UncheckedInputIndex: a value decoded from an input buffer
// (`*(uint16 *)(buf + 2)`, `p[0]`, `ntohs(...)`) is used as the index of a
// fixed-size array that is smaller than the value's range, and nothing
// before the access compares it with anything (CWE-129 -> CWE-125,
// CWE-787).
// Modelled on rAthena CVE-2025-58750 (chclif_parse_moveCharSlot: `from =
// RFIFOW(fd, 2)` then `sd->char_moves[from]` and `sd->found_char[from]`, with
// only `to` checked against char_slots).
#include <stddef.h>
#include <stdint.h>

#define MAX_CHARS 15
struct session {
  unsigned char *rdata;
  uint32_t rdata_pos;
};
extern struct session *session[];
#define RFIFOP(fd, pos) (session[fd]->rdata + session[fd]->rdata_pos + (pos))
#define RFIFOW(fd, pos) (*(uint16_t *)RFIFOP(fd, pos))

struct char_session_data {
  int32_t found_char[MAX_CHARS];
  uint32_t char_moves[MAX_CHARS];
  uint16_t char_slots;
};
void reply(int fd, struct char_session_data *sd, uint16_t slot, int err);

// rAthena src/char/char_clif.cpp
int parse_move_char_slot(int fd, struct char_session_data *sd, int unlimited) {
  uint16_t from, to;
  from = RFIFOW(fd, 2);
  to = RFIFOW(fd, 4);
  // ruleid: raptor-unchecked-input-index
  if (unlimited == 0 && sd->char_moves[from] <= 0) {
    reply(fd, sd, from, 1);
    return 1;
  }
  if (sd->found_char[from] <= 0 || to >= sd->char_slots) {
    reply(fd, sd, from, 1);
    return 1;
  }
  // ok: raptor-unchecked-input-index
  return sd->found_char[to];
}

// The fix.
int parse_move_char_slot_fixed(int fd, struct char_session_data *sd) {
  uint16_t from = RFIFOW(fd, 2), to = RFIFOW(fd, 4);
  if (from >= MAX_CHARS)
    return 1;
  // ok: raptor-unchecked-input-index
  if (sd->char_moves[from] <= 0)
    return 1;
  if (to >= MAX_CHARS)
    return 1;
  // ok: raptor-unchecked-input-index
  return sd->found_char[to];
}

// A byte from the input indexes a table of 16 entries.
static const char *const names[16] = {0};
uint8_t read_u8(const unsigned char *p);
const char *opcode_name(const unsigned char *p) {
  uint8_t op = read_u8(p);
  // ruleid: raptor-unchecked-input-index
  return names[op];
}
const char *opcode_name_masked(const unsigned char *p) {
  uint8_t op = read_u8(p) & 0x0f;
  // ok: raptor-unchecked-input-index
  return names[op];
}
const char *opcode_name_switch(const unsigned char *p) {
  uint8_t op = read_u8(p);
  switch (op) {
  case 1:
    // ok: raptor-unchecked-input-index
    return names[op];
  }
  return 0;
}

// Byte-order readers.
uint16_t ntohs(uint16_t);
int counters[100];
int bump(const uint16_t *wire) {
  uint16_t id = ntohs(wire[1]);
  // ruleid: raptor-unchecked-input-index
  return ++counters[id];
}
int bump_checked(const uint16_t *wire) {
  uint16_t id = ntohs(wire[1]);
  if (id >= 100)
    return -1;
  // ok: raptor-unchecked-input-index
  return ++counters[id];
}

// Not this rule: the array covers the whole range, the value is not from
// an input buffer, a validating call first.
static int all[256];
int whole_range(const unsigned char *p) {
  uint8_t v = read_u8(p);
  // ok: raptor-unchecked-input-index
  return all[v];
}
int from_param(unsigned idx) {
  // ok: raptor-unchecked-input-index
  return counters[idx];
}
int valid_id(uint16_t id);
int validated(const uint16_t *wire) {
  uint16_t id = ntohs(wire[1]);
  if (!valid_id(id))
    return -1;
  // ok: raptor-unchecked-input-index
  return counters[id];
}

// --- noise seen in brotli, httpd ---

// Reads of the program's own arrays are not input decoding (brotli
// code_length_bitdepth[], httpd's compiled regexp bytes).
static int histo[18];
void count_codes(const unsigned char *codes, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned char code = codes[i];
    // ok: raptor-unchecked-input-index
    ++histo[code];
  }
}
