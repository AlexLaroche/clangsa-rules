// raptor.UncheckedCursorWrite: a buffer is passed to a function that writes
// through a cursor advanced by data-dependent steps without ever comparing it
// to a bound, and the caller does not check the buffer's capacity either
// (CWE-787).
// Modelled on CVE-2023-4863 (libwebp <= 1.3.1, src/utils/huffman_utils.c):
// BuildHuffmanTable() fills second-level tables at `table += table_size`, the
// sizes coming from code lengths in the image; VP8LBuildHuffmanTable() passed
// the caller's fixed-size buffer straight through. The fix computes the size
// first and compares it to the space left before writing.
#include <stddef.h>
#include <stdlib.h>

typedef struct {
  unsigned char bits;
  unsigned short value;
} HuffmanCode;

static void ReplicateValue(HuffmanCode *table, int step, int end, HuffmanCode code) {
  do {
    end -= step;
    table[end] = code;
  } while (end > 0);
}

static int NextTableBitSize(const int *count, int len, int root_bits) {
  int left = 1 << (len - root_bits);
  while (len < 15) {
    left -= count[len];
    if (left <= 0) break;
    ++len;
    left <<= 1;
  }
  return len - root_bits;
}

// The writer: data-dependent cursor steps, no bound anywhere.
static int BuildHuffmanTable(HuffmanCode *const root_table, int root_bits,
                             const int code_lengths[], int code_lengths_size) {
  HuffmanCode *table = root_table;
  int total_size = 1 << root_bits;
  int count[16] = {0};
  int len, symbol, key = 0, low = -1;
  int table_size = 1 << root_bits;
  for (symbol = 0; symbol < code_lengths_size; ++symbol)
    ++count[code_lengths[symbol]];
  for (len = root_bits + 1; len <= 15; ++len) {
    for (; count[len] > 0; --count[len]) {
      HuffmanCode code;
      if ((key & (total_size - 1)) != low) {
        table += table_size;
        table_size = 1 << NextTableBitSize(count, len, root_bits);
        total_size += table_size;
        low = key & (total_size - 1);
        if (root_table != NULL) {
          root_table[low].bits = (unsigned char)len;
          root_table[low].value = (unsigned short)(table - root_table - low);
        }
      }
      code.bits = (unsigned char)(len - root_bits);
      code.value = (unsigned short)symbol;
      if (root_table != NULL)
        ReplicateValue(&table[key >> root_bits], 2, table_size, code);
      ++key;
    }
  }
  return total_size;
}

// CVE-2023-4863: the caller's buffer, of a size estimated elsewhere, goes
// straight to the writer.
int VP8LBuildHuffmanTable(HuffmanCode *const root_table, int root_bits,
                          const int code_lengths[], int code_lengths_size) {
  if (root_table == NULL)
    // ok: raptor-unchecked-cursor-write
    return BuildHuffmanTable(NULL, root_bits, code_lengths, code_lengths_size);
  // ruleid: raptor-unchecked-cursor-write
  return BuildHuffmanTable(root_table, root_bits, code_lengths, code_lengths_size);
}

// The 1.3.2 fix: size first, compare with the room left, then write.
typedef struct {
  HuffmanCode *start, *curr_table;
  int size;
} Segment;

int VP8LBuildHuffmanTableFixed(Segment *const seg, int root_bits,
                               const int code_lengths[], int code_lengths_size) {
  // ok: raptor-unchecked-cursor-write
  const int total_size = BuildHuffmanTable(NULL, root_bits, code_lengths, code_lengths_size);
  if (total_size == 0)
    return 0;
  if (seg->curr_table + total_size >= seg->start + seg->size)
    return 0;
  // ok: raptor-unchecked-cursor-write
  BuildHuffmanTable(seg->curr_table, root_bits, code_lengths, code_lengths_size);
  return total_size;
}

// A local heap buffer of a guessed size, no check: reported at the call.
int DecodeTables(const int *lens, int n) {
  HuffmanCode *tables = malloc(2048 * sizeof(*tables));
  int size;
  if (tables == NULL)
    return 0;
  // ruleid: raptor-unchecked-cursor-write
  size = BuildHuffmanTable(tables, 8, lens, n);
  free(tables);
  return size;
}

// Not unbounded writers.

// The caller controls how far it writes: the loop is bounded by a parameter.
static void CopyRows(unsigned char *dst, const unsigned char *src, int rows, int stride) {
  int y;
  for (y = 0; y < rows; ++y) {
    *dst = *src;
    dst += stride;
    src += stride;
  }
}

// Same, through a local copy of the parameter (libwebp EmitRows).
static int EmitRows(const unsigned char *row_in, int in_stride, int mb_h,
                    unsigned char *const out, int out_stride) {
  int lines = mb_h;
  unsigned char *row_out = out;
  while (lines-- > 0) {
    *row_out = *row_in;
    row_in += in_stride;
    row_out += out_stride;
  }
  return mb_h;
}

// The cursor is compared with the end of the buffer.
static int PutRecords(unsigned char *out, unsigned char *end, const int *lens, int n) {
  unsigned char *p = out;
  int i = 0;
  while (lens[i] != 0) {
    if (p + lens[i] > end)
      return -1;
    *p = (unsigned char)lens[i];
    p += lens[i];
    ++i;
  }
  return (int)(p - out);
}

// Constant steps.
static void FillPairs(unsigned char *out, const int *lens) {
  int i = 0;
  while (lens[i] != 0) {
    out[0] = (unsigned char)lens[i];
    out[1] = 0;
    out += 2;
    ++i;
  }
}

void UseOthers(unsigned char *buf, unsigned char *end, const unsigned char *src,
               const int *lens) {
  // ok: raptor-unchecked-cursor-write
  CopyRows(buf, src, 4, 16);
  // ok: raptor-unchecked-cursor-write
  EmitRows(src, 16, 4, buf, 16);
  // ok: raptor-unchecked-cursor-write
  PutRecords(buf, end, lens, 4);
  // ok: raptor-unchecked-cursor-write
  FillPairs(buf, lens);
}

// Forwarding through a second function is still unbounded.
static int BuildTwice(HuffmanCode *dst, const int *lens, int n) {
  // ruleid: raptor-unchecked-cursor-write
  return BuildHuffmanTable(dst, 8, lens, n);
}

void UseForwarder(HuffmanCode *dst, const int *lens, int n) {
  // ruleid: raptor-unchecked-cursor-write
  BuildTwice(dst, lens, n);
}
