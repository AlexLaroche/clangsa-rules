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

// Writers that track the room they have (from curl, libtiff, OpenJPEG).
size_t produce(char *buf, size_t room);
void read_line(unsigned char *line);

// The room left shrinks as the cursor moves (curl mime.c).
static size_t fill_chunks(char *buf, size_t bufsize) {
  size_t total = 0, sz;
  for (;;) {
    sz = produce(buf, bufsize);
    if (!sz)
      return total;
    total += sz;
    buf += sz;
    bufsize -= sz;
  }
}

// The loop counter is set from a parameter by assignment (libtiff tif_ojpeg.c).
static int decode_lines(unsigned char *buf, long cc, int bpl) {
  unsigned char *m;
  long n;
  m = buf;
  n = cc;
  do {
    read_line(m);
    m += bpl;
    n -= bpl;
  } while (n > 0);
  return 1;
}

// A single data-dependent offset, not a cursor walk (OpenJPEG j2k.c).
static void write_marker(unsigned char *p, int comp_room) {
  p[0] = 0xff;
  p += comp_room;
  *p = 0x53;
}

void UseRoomTrackers(char *b, unsigned char *u, long cc) {
  // ok: raptor-unchecked-cursor-write
  fill_chunks(b, 64);
  // ok: raptor-unchecked-cursor-write
  decode_lines(u, cc, 16);
  // ok: raptor-unchecked-cursor-write
  write_marker(u, (int)cc);
}

// Run loops: an outer loop compares an index with the end of the buffer, but
// an inner loop whose count comes from the data moves that index and writes
// without checking it again.

// CVE-2026-118752 (FreeImage < 3.19.22, PluginIFF.cpp): IFF PBM ByteRun1.
typedef struct {
  int (*read)(unsigned char *b, int n, void *h);
} IO;

void iff_pbm(IO *io, void *h, unsigned char *bits, unsigned line) {
  unsigned written = 0;
  signed char rle_count;
  unsigned char byte;
  while (written < line) {
    io->read((unsigned char *)&rle_count, 1, h);
    if (rle_count < 128 && rle_count >= 0) {
      for (int k = 0; k < rle_count + 1; k++) {
        io->read(&byte, 1, h);
        // ruleid: raptor-unchecked-cursor-write
        bits[written++] += byte;
      }
    } else if (rle_count != -128) {
      io->read(&byte, 1, h);
      for (int k = 0; k < 1 - rle_count; k++) {
        // ruleid: raptor-unchecked-cursor-write
        bits[written++] += byte;
      }
    }
  }
}

void iff_pbm_fixed(IO *io, void *h, unsigned char *bits, unsigned line) {
  unsigned written = 0;
  signed char rle_count;
  unsigned char byte;
  while (written < line) {
    io->read((unsigned char *)&rle_count, 1, h);
    for (int k = 0; k < rle_count + 1; k++) {
      if (written >= line)
        break;
      io->read(&byte, 1, h);
      // ok: raptor-unchecked-cursor-write
      bits[written++] += byte;
    }
  }
}

// CVE-2026-40494 (SAIL, tga.c): the RLE packet is clamped, the raw one is not.
int strict_read(void *stream, void *buf, unsigned n);

int tga_load(void *stream, unsigned char *pixels, unsigned pixels_num, unsigned pixel_size) {
  for (unsigned i = 0; i < pixels_num;) {
    unsigned char marker;
    unsigned char pixel[4];
    strict_read(stream, &marker, 1);
    unsigned count = (marker & 0x7F) + 1;
    if (marker & 0x80) {
      strict_read(stream, pixel, pixel_size);
      count = (i + count) <= pixels_num ? count : (pixels_num - i);
      for (unsigned j = 0; j < count; j++, i++) {
        // ok: raptor-unchecked-cursor-write
        pixels[0] = pixel[0];
        pixels += pixel_size;
      }
    } else {
      for (unsigned j = 0; j < count; j++, i++) {
        // ruleid: raptor-unchecked-cursor-write
        strict_read(stream, pixels, pixel_size);
        pixels += pixel_size;
      }
    }
  }
  return 0;
}

int tga_load_fixed(void *stream, unsigned char *pixels, unsigned pixels_num,
                   unsigned pixel_size) {
  for (unsigned i = 0; i < pixels_num;) {
    unsigned char marker;
    strict_read(stream, &marker, 1);
    const unsigned packet_count = (marker & 0x7F) + 1;
    const unsigned remaining = pixels_num - i;
    const unsigned count = packet_count <= remaining ? packet_count : remaining;
    for (unsigned j = 0; j < count; j++, i++) {
      // ok: raptor-unchecked-cursor-write
      strict_read(stream, pixels, pixel_size);
      pixels += pixel_size;
    }
  }
  return 0;
}

// CVE-2026-43904 (OpenImageIO softimage): the run starts at the index and the
// index moves by the count afterwards.
int fread1(unsigned char *b);

int pic_run(unsigned char *line, unsigned width) {
  unsigned count_so_far = 0;
  unsigned char cur;
  while (count_so_far < width) {
    if (fread1(&cur) != 1)
      return 0;
    for (unsigned x = count_so_far; x < count_so_far + cur; x++)
      // ruleid: raptor-unchecked-cursor-write
      line[x] = 0;
    count_so_far += cur;
  }
  return 1;
}

int pic_run_fixed(unsigned char *line, unsigned width) {
  unsigned count_so_far = 0;
  unsigned char cur;
  while (count_so_far < width) {
    if (fread1(&cur) != 1)
      return 0;
    if (count_so_far + cur > width)
      cur = (unsigned char)(width - count_so_far);
    for (unsigned x = count_so_far; x < count_so_far + cur; x++)
      // ok: raptor-unchecked-cursor-write
      line[x] = 0;
    count_so_far += cur;
  }
  return 1;
}

// Pointer cursor against an end pointer.
void unpack(unsigned char *out, unsigned char *end, const unsigned char *in) {
  while (out < end) {
    unsigned n = *in++;
    unsigned char v = *in++;
    while (n--)
      // ruleid: raptor-unchecked-cursor-write
      *out++ = v;
  }
}

int unpack_checked(unsigned char *out, unsigned char *end, const unsigned char *in) {
  while (out < end) {
    unsigned n = *in++;
    unsigned char v = *in++;
    if (n > (unsigned)(end - out))
      return -1;
    while (n--)
      // ok: raptor-unchecked-cursor-write
      *out++ = v;
  }
  return 0;
}

// Not runs: a constant count, an input cursor, a nested 2-D loop.
void quads(unsigned char *out, unsigned n) {
  unsigned i = 0;
  while (i < n) {
    for (int k = 0; k < 4; k++)
      // ok: raptor-unchecked-cursor-write
      out[i++] = 0;
  }
}

void literals(unsigned char *out, const unsigned char *in, unsigned len) {
  unsigned i = 0;
  while (i < len) {
    unsigned n = in[i++];
    for (unsigned k = 0; k < n; k++)
      // ok: raptor-unchecked-cursor-write
      out[k] = in[i++];
  }
}

void clear(unsigned char *dst, unsigned w, unsigned h) {
  for (unsigned y = 0; y < h; y++)
    for (unsigned x = 0; x < w; x++)
      // ok: raptor-unchecked-cursor-write
      dst[y * w + x] = 0;
}

// The run tests the position itself (OpenJPEG convertbmp.c RLE8).
void bmp_rle8(unsigned char *pix, unsigned char *beyond, unsigned width, unsigned height,
              int (*next)(void)) {
  unsigned x = 0, y = 0;
  while (y < height) {
    int c = next();
    int j;
    for (j = 0; (j < c) && (x < width) && (pix < beyond); j++, x++, pix++)
      // ok: raptor-unchecked-cursor-write
      *pix = (unsigned char)next();
    if (c == 0)
      y += (unsigned)next();
  }
}

// The index only selects the run's length (libarchive 7zip read_SubStreamsInfo).
typedef struct {
  unsigned numUnpackStreams;
} Folder;
int parse_int(unsigned long *v);
int sub_streams(const Folder *f, unsigned numFolders, unsigned long *usizes) {
  for (unsigned i = 0; i < numFolders; i++) {
    for (unsigned pack = 1; pack < f[i].numUnpackStreams; pack++)
      // ok: raptor-unchecked-cursor-write
      if (parse_int(usizes++) < 0)
        return -1;
  }
  return 0;
}

// Not a counted run: the inner loop drains a list (c-ares ares_htable.c).
void *first(void *bucket);
void rehash(void **buckets, void **old, unsigned n, void **out) {
  for (unsigned i = 0; i < n; i++) {
    void *node;
    while ((node = first(old[i])) != NULL)
      // ok: raptor-unchecked-cursor-write
      *out++ = node;
  }
}

// The room is handed to the callee that writes (in: room left, out: bytes
// used), and the cursor moves by what it used (wolfSSL GetEchConfigsEx:
// `GetEchConfig(cfg, output, &workingOutputLen); output += workingOutputLen;`).
typedef struct Cfg {
  struct Cfg *next;
  int n;
  const unsigned char *item[4];
  unsigned int itemLen[4];
} Cfg;
// The callee adds up what it will write and checks it against the room it
// was given, through its in/out length, before writing (GetEchConfig).
static int put_config(const Cfg *c, unsigned char *out, unsigned int *len) {
  unsigned int total = 0;
  for (int i = 0; i < c->n; i++)
    total += c->itemLen[i];
  if (total > *len) {
    *len = total;
    return -1;
  }
  for (int i = 0; i < c->n; i++) {
    for (unsigned int j = 0; j < c->itemLen[i]; j++)
      out[j] = c->item[i][j];
    out += c->itemLen[i];
  }
  *len = total;
  return 0;
}
static int put_configs(const Cfg *cfgs, unsigned char *output, unsigned int *outputLen) {
  unsigned char *start = output;
  const Cfg *c = NULL;
  unsigned int total = 2, room = *outputLen - 2;
  output += 2;
  c = cfgs;
  while (c != NULL) {
    put_config(c, output, &room);
    output += room;
    total += room;
    room = total > *outputLen ? 0 : *outputLen - total;
    c = c->next;
  }
  start[0] = (unsigned char)(total >> 8);
  start[1] = (unsigned char)total;
  return 0;
}

int get_configs(const Cfg *cfgs, unsigned char *output, unsigned int *outputLen) {
  // ok: raptor-unchecked-cursor-write
  return put_configs(cfgs, output, outputLen);
}
