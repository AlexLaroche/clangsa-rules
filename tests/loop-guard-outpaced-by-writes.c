// raptor.LoopGuardOutpacedByWrites: the loop condition checks a write cursor
// for room for N elements (`to < end` is room for one), but one pass of the
// body can write more than N through it (`*to++ = a; ... *to++ = b;`) before
// anything checks the cursor again (CWE-787, CWE-193).
// Modelled on Ruby GHSA-34m4-m9fh-gqp5 (enc/iso_8859_1.c case_map: sharp s
// upcases to "SS", fixed with `to_end - to > 1`) and nDPI CVE-2026-86098
// (ndpi_json_string_escape: `j < dst_max_len`, then `dst[j++] = '\\';
// dst[j++] = c;`, fixed with `if (j + 2 > safe_max_len) goto overflow;`).
#include <stddef.h>

#define SHARP_s 0xdf
#define UPCASE 1

// Ruby 3.4.12 enc/iso_8859_1.c
int case_map(int flags, const unsigned char **pp, const unsigned char *end,
             unsigned char *to, unsigned char *to_end) {
  unsigned char *to_start = to;
  while (*pp < end && to < to_end) {
    unsigned code = *(*pp)++;
    if (code == SHARP_s) {
      if (flags & UPCASE) {
        *to++ = 'S';
        code = 'S';
      }
    } else if (code >= 'a' && code <= 'z' && (flags & UPCASE)) {
      code -= 0x20;
    }
    // ruleid: raptor-loop-guard-outpaced-by-writes
    *to++ = code;
  }
  return (int)(to - to_start);
}

// Ruby 3.4.13: the guard now proves room for two.
int case_map_fixed(int flags, const unsigned char **pp, const unsigned char *end,
                   unsigned char *to, unsigned char *to_end) {
  unsigned char *to_start = to;
  // ok: raptor-loop-guard-outpaced-by-writes
  while (*pp < end && to_end - to > 1) {
    unsigned code = *(*pp)++;
    if (code == SHARP_s && (flags & UPCASE)) {
      *to++ = 'S';
      code = 'S';
    }
    // ok: raptor-loop-guard-outpaced-by-writes
    *to++ = code;
  }
  return (int)(to - to_start);
}

// nDPI before CVE-2026-86098
int json_string_escape(const char *src, int src_len, char *dst, int dst_max_len) {
  unsigned char c = 0;
  int i, j = 0;
  dst[j++] = '"';
  for (i = 0; i < src_len && j < dst_max_len; i++) {
    c = (unsigned char)src[i];
    if (c <= 0x7E) {
      switch (c) {
      case '\\':
      case '"':
      case '/':
        dst[j++] = '\\';
        // ruleid: raptor-loop-guard-outpaced-by-writes
        dst[j++] = c;
        break;
      case '\n':
        dst[j++] = '\\';
        dst[j++] = 'n';
        break;
      default:
        if (c >= 0x20)
          dst[j++] = c;
      }
    } else {
      dst[j++] = c;
    }
  }
  dst[j++] = '"';
  dst[j] = '\0';
  return j;
}

// The nDPI fix: each multi-byte write checks the room it needs first.
int json_string_escape_fixed(const char *src, int src_len, char *dst, int dst_max_len) {
  int i, j = 0;
  int safe_max_len = dst_max_len - 2;
  dst[j++] = '"';
  for (i = 0; i < src_len; i++) {
    unsigned char c = (unsigned char)src[i];
    if (c == '\\' || c == '"' || c == '/') {
      if (j + 2 > safe_max_len)
        goto overflow;
      dst[j++] = '\\';
      // ok: raptor-loop-guard-outpaced-by-writes
      dst[j++] = c;
    } else {
      if (j + 1 > safe_max_len)
        goto overflow;
      dst[j++] = c;
    }
  }
  dst[j++] = '"';
  dst[j] = '\0';
  return j;
overflow:
  return -1;
}

// `!=` proves no more room than `<`.
void hex_encode(const unsigned char *s, size_t n, char *o, char *oend) {
  static const char hx[] = "0123456789abcdef";
  for (size_t i = 0; i < n && o != oend; i++) {
    *o++ = hx[s[i] >> 4];
    // ruleid: raptor-loop-guard-outpaced-by-writes
    *o++ = hx[s[i] & 15];
  }
}

// UTF-8 encoding: up to two bytes a pass, guarded for one.
void utf8_encode(const unsigned short *s, size_t n, unsigned char *o, unsigned char *oend) {
  for (size_t i = 0; i < n && o < oend; i++) {
    if (s[i] < 0x80) {
      *o++ = (unsigned char)s[i];
    } else {
      *o++ = (unsigned char)(0xC0 | (s[i] >> 6));
      // ruleid: raptor-loop-guard-outpaced-by-writes
      *o++ = (unsigned char)(0x80 | (s[i] & 0x3F));
    }
  }
}

// The guard leaves room for two: `o < oend - 1`.
void hex_encode_room2(const unsigned char *s, size_t n, char *o, char *oend) {
  static const char hx[] = "0123456789abcdef";
  for (size_t i = 0; i < n && o < oend - 1; i++) {
    *o++ = hx[s[i] >> 4];
    // ok: raptor-loop-guard-outpaced-by-writes
    *o++ = hx[s[i] & 15];
  }
}

// `o + 1 < oend` is room for two as well.
void hex_encode_plus(const unsigned char *s, size_t n, char *o, char *oend) {
  static const char hx[] = "0123456789abcdef";
  for (size_t i = 0; i < n && o + 1 < oend; i++) {
    *o++ = hx[s[i] >> 4];
    // ok: raptor-loop-guard-outpaced-by-writes
    *o++ = hx[s[i] & 15];
  }
}

// A check inside the body before the second write.
void escape_checked(const char *s, char *o, char *oend) {
  while (*s && o < oend) {
    if (*s == '"') {
      if (oend - o < 2)
        break;
      *o++ = '\\';
    }
    // ok: raptor-loop-guard-outpaced-by-writes
    *o++ = *s++;
  }
}

// One write a pass.
void copy_one(const char *s, char *o, char *oend) {
  while (*s && o < oend)
    // ok: raptor-loop-guard-outpaced-by-writes
    *o++ = *s++;
}

// The cursor is not in the guard: the caller sized the buffer (2n).
void hex_encode_presized(const unsigned char *s, size_t n, char *o) {
  static const char hx[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    *o++ = hx[s[i] >> 4];
    // ok: raptor-loop-guard-outpaced-by-writes
    *o++ = hx[s[i] & 15];
  }
}

// Writes on different paths, one per pass.
void one_per_path(const char *s, char *o, char *oend) {
  while (*s && o < oend) {
    if (*s == '\n')
      *o++ = ' ';
    else
      // ok: raptor-loop-guard-outpaced-by-writes
      *o++ = *s;
    s++;
  }
}

// A helper that takes the cursor and its end decides the room itself.
int put_escaped(char **o, char *oend, char c);
void via_helper(const char *s, char *o, char *oend) {
  while (*s && o < oend) {
    *o++ = '\\';
    put_escaped(&o, oend, *s++);
    // ok: raptor-loop-guard-outpaced-by-writes
    *o++ = ' ';
  }
}

// A second write that leaves the loop is still a write past the end.
void trailer_then_break(const char *s, char *o, char *oend) {
  while (o < oend) {
    *o++ = *s;
    if (!*s++) {
      // ruleid: raptor-loop-guard-outpaced-by-writes
      *o++ = '\n';
      break;
    }
  }
}

// do-while: the body runs before the check, a different bug.
void do_while(const char *s, char *o, char *oend) {
  do {
    *o++ = '\\';
    // ok: raptor-loop-guard-outpaced-by-writes
    *o++ = *s++;
  } while (*s && o < oend);
}

// An inner loop with its own guard on the cursor.
void inner_loop(const char **words, size_t n, char *o, char *oend) {
  for (size_t i = 0; i < n && o < oend; i++) {
    const char *w = words[i];
    while (*w && o < oend)
      *o++ = *w++;
    if (o < oend)
      // ok: raptor-loop-guard-outpaced-by-writes
      *o++ = ' ';
  }
}

// A different cursor is written twice.
void other_cursor(const char *s, char *o, char *oend, char *log) {
  while (*s && o < oend) {
    *log++ = *s;
    *log++ = ',';
    // ok: raptor-loop-guard-outpaced-by-writes
    *o++ = *s++;
  }
}

// A for loop that steps the cursor by two declares two slots a pass: the
// range is laid out in pairs (Ruby regexec.c match_at stack init).
void init_pairs(long *p, long *end) {
  for (; p < end; p += 2) {
    p[0] = -1;
    // ok: raptor-loop-guard-outpaced-by-writes
    p[1] = -1;
  }
}

// The end pointer is the last element, not one past it: `ptr != end` leaves
// room for two (FreeRDP rfx_differential_decode).
void differential_decode(short *buffer, size_t size) {
  short *ptr = buffer;
  short *end = &buffer[size - 1];
  while (ptr != end) {
    int tmp = ptr[0] + ptr[1];
    // ok: raptor-loop-guard-outpaced-by-writes
    ptr[1] = (short)tmp;
    ptr++;
  }
}

void last_element_pointer(char *o, size_t n, const char *s) {
  char *last = o + n - 1;
  while (*s && o < last) {
    *o++ = *s++;
    // ok: raptor-loop-guard-outpaced-by-writes
    *o = 0;
  }
}

// A constant bound well inside a fixed array: padding to a column (haproxy
// cpu_topo.c).
void pad_column(int len) {
  char str[64];
  while (len < 10) {
    str[len++] = ' ';
    // ok: raptor-loop-guard-outpaced-by-writes
    str[len] = 0;
  }
}

// A constant bound equal to the array size is the real capacity.
void pad_to_size(int len) {
  char str[10];
  while (len < 10) {
    str[len++] = ' ';
    // ruleid: raptor-loop-guard-outpaced-by-writes
    str[len] = 0;
  }
}
