// raptor.PostDecrementOffByOne: a loop that copies or writes stops on
// `if (room-- < 0) break;`. The test reads room before the decrement, so the
// body runs room + 1 times: one element past the end (CWE-193, CWE-787).
// Modelled on CVE-2026-31969 (HTSlib cram_byte_array_stop_decode_char:
// `ssize_t term = MIN(*out_size, ...); while ((ch = *cp) != stop) { if
// (term-- < 0) break; *out++ = ch; cp++; }`, fixed with `--term >= 0`).
#include <stddef.h>
#include <sys/types.h>

// CVE-2026-31969
int decode_char(const char *cp, char *out, ssize_t out_size, ssize_t avail, char stop) {
  char ch;
  ssize_t term = out_size < avail ? out_size : avail;
  while ((ch = *cp) != stop) {
    // ruleid: raptor-post-decrement-off-by-one
    if (term-- < 0)
      break;
    *out++ = ch;
    cp++;
  }
  return ch == stop ? 0 : -1;
}

// The fix.
int decode_char_fixed(const char *cp, char *out, ssize_t out_size, ssize_t avail, char stop) {
  ssize_t term = out_size < avail ? out_size : avail;
  // ok: raptor-post-decrement-off-by-one
  while (--term >= 0 && *cp != stop)
    *out++ = *cp++;
  return 0;
}

// Pre-decrement, or a post-decrement compared with 0 the right way.
void copy_room(char *dst, const char *src, int room) {
  for (;;) {
    // ok: raptor-post-decrement-off-by-one
    if (--room < 0)
      break;
    *dst++ = *src++;
  }
  for (;;) {
    // ok: raptor-post-decrement-off-by-one
    if (room-- <= 0)
      break;
    *dst++ = *src++;
  }
  // ok: raptor-post-decrement-off-by-one
  while (room-- > 0)
    *dst++ = *src++;
}

// Written the other way round, through an index.
void fill(int *a, int n) {
  int i = 0;
  while (1) {
    // ruleid: raptor-post-decrement-off-by-one
    if (0 > n--)
      return;
    a[i++] = 0;
  }
}

// No write or read through a pointer in the loop: counting only.
int count_down(int n) {
  int steps = 0;
  for (;;) {
    // ok: raptor-post-decrement-off-by-one
    if (n-- < 0)
      break;
    steps++;
  }
  return steps;
}

// The same in a loop condition: runs n + 1 times.
void zero(char *p, int n) {
  // ruleid: raptor-post-decrement-off-by-one
  while (n-- >= 0)
    *p++ = 0;
}
