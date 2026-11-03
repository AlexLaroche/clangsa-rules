// raptor.UncheckedAllocProduct: a buffer is allocated with a 32-bit product
// of two run-time factors (rows * stride) and then filled row by row in a loop
// bounded by one factor, with no overflow guard on the factors. When the
// product wraps, the allocation is small while the loop still writes
// rows * stride bytes (CWE-190 -> CWE-787, heap overflow).
// Modelled on CVE-2026-70628 / CVE-2026-70632 (FFmpeg < 9.0,
// libavformat/rawutils.c ff_reshuffle_raw_rgb):
//   av_new_packet(new_pkt, expected_stride * par->height);
//   for (y = 0; y < par->height; y++) memcpy(new_pkt->data + y*expected_stride, ...);
// The fix rejects `expected_stride > (INT_MAX - PADDING) / par->height`.
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  unsigned char *data;
  int size;
} Packet;
typedef struct {
  int width, height, bits;
} Params;

int av_new_packet(Packet *pkt, int size);
int av_size_mult(size_t a, size_t b, size_t *r);

// CVE-2026-70628: height and stride come from the container header.
int reshuffle(Packet *pkt, Packet *new_pkt, Params *par, int expected_stride) {
  int stride = pkt->size / par->height;
  int y;
  // ruleid: raptor-unchecked-alloc-product
  int ret = av_new_packet(new_pkt, expected_stride * par->height);
  if (ret < 0)
    return ret;
  for (y = 0; y < par->height; y++)
    memcpy(new_pkt->data + y * expected_stride, pkt->data + y * stride, stride);
  return 1;
}

// The fix: the product is checked before the allocation.
int reshuffle_fixed(Packet *pkt, Packet *new_pkt, Params *par, int expected_stride) {
  int stride, y, ret;
  if (par->height <= 0 || expected_stride <= 0 ||
      expected_stride > (INT_MAX - 64) / par->height)
    return -1;
  stride = pkt->size / par->height;
  // ok: raptor-unchecked-alloc-product
  ret = av_new_packet(new_pkt, expected_stride * par->height);
  if (ret < 0)
    return ret;
  for (y = 0; y < par->height; y++)
    memcpy(new_pkt->data + y * expected_stride, pkt->data + y * stride, stride);
  return 1;
}

// malloc of rows * cols ints, filled by index.
int *grid(int rows, int cols) {
  // ruleid: raptor-unchecked-alloc-product
  int *g = malloc(rows * cols);
  for (int r = 0; r < rows; r++)
    for (int c = 0; c < cols; c++)
      g[r * cols + c] = 0;
  return g;
}

// Checked with an overflow helper.
unsigned char *rows_checked(int rows, int stride, const unsigned char *src) {
  size_t total;
  if (av_size_mult(rows, stride, &total))
    return NULL;
  // ok: raptor-unchecked-alloc-product
  unsigned char *b = malloc(rows * stride);
  for (int r = 0; r < rows; r++)
    memcpy(b + r * stride, src, stride);
  return b;
}

// Product computed in size_t (64-bit): no 32-bit wraparound.
unsigned char *rows_wide(size_t rows, size_t stride, const unsigned char *src) {
  // ok: raptor-unchecked-alloc-product
  unsigned char *b = malloc(rows * stride);
  for (size_t r = 0; r < rows; r++)
    memcpy(b + r * stride, src, stride);
  return b;
}

// A constant factor: n * 4 is the IntegerWraparound rule's business.
int *ints(int n) {
  // ok: raptor-unchecked-alloc-product
  int *v = malloc(n * 4);
  for (int i = 0; i < n; i++)
    v[i] = i;
  return v;
}

// No loop writes the buffer.
void *blob(int a, int b) {
  // ok: raptor-unchecked-alloc-product
  return malloc(a * b);
}

// Product checked with __builtin_mul_overflow.
unsigned char *rows_builtin(int rows, int stride, const unsigned char *src) {
  int total;
  if (__builtin_mul_overflow(rows, stride, &total))
    return NULL;
  // ok: raptor-unchecked-alloc-product
  unsigned char *b = malloc(rows * stride);
  for (int r = 0; r < rows; r++)
    memcpy(b + r * stride, src, stride);
  return b;
}
