// raptor.UncheckedAllocProduct: a buffer is allocated with a 32-bit product
// of two run-time factors (rows * stride, w * h), with no overflow guard on
// the factors. When the product wraps, the allocation is small while the code
// filling it (a loop here, or the caller) still writes rows * stride
// elements (CWE-190 -> CWE-787, heap overflow).
// Modelled on CVE-2026-70628 / CVE-2026-70632 (FFmpeg < 9.0,
// libavformat/rawutils.c ff_reshuffle_raw_rgb):
//   av_new_packet(new_pkt, expected_stride * par->height);
//   for (y = 0; y < par->height; y++) memcpy(new_pkt->data + y*expected_stride, ...);
// The fix rejects `expected_stride > (INT_MAX - PADDING) / par->height`.
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
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

// The product spans several lines (GEGL rgbe_read_pixels, CVE-2026-18300:
// `g_new (gfloat, file->header.x_axis.size *\n file->header.y_axis.size *
// RGBE_NUM_RGBE)`): the report stays on one line.
typedef struct { unsigned short width, height; } Header;
float *pixels(const Header *h) {
  // ruleid: raptor-unchecked-alloc-product
  return malloc(h->width *
                h->height *
                3 * sizeof(float));
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

// Filled elsewhere: still a wrapped allocation.
void *blob(int a, int b) {
  // ruleid: raptor-unchecked-alloc-product
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

// CVE-2016-9118 (OpenJPEG < 2.2.0, opj_image_create): w and h come from the
// image header; the caller fills w * h samples.
typedef struct {
  unsigned int w, h;
  int *data;
} Comp;
void *opj_calloc(size_t n, size_t size);

int image_create(Comp *comps, unsigned int numcmpts) {
  for (unsigned int compno = 0; compno < numcmpts; compno++) {
    Comp *comp = &comps[compno];
    // ruleid: raptor-unchecked-alloc-product
    comp->data = (int *)opj_calloc(comp->w * comp->h, sizeof(int));
    if (!comp->data)
      return 0;
  }
  return 1;
}

// The fix: guard, and multiply in size_t.
int image_create_fixed(Comp *comps, unsigned int numcmpts) {
  for (unsigned int compno = 0; compno < numcmpts; compno++) {
    Comp *comp = &comps[compno];
    if (comp->h != 0 && (size_t)comp->w > SIZE_MAX / comp->h)
      return 0;
    // ok: raptor-unchecked-alloc-product
    comp->data = (int *)opj_calloc((size_t)comp->w * comp->h, sizeof(int));
    if (!comp->data)
      return 0;
  }
  return 1;
}

// The size computed into a local first.
unsigned char *frame(int width, int height) {
  int size = width * height;
  // ruleid: raptor-unchecked-alloc-product
  return malloc(size);
}

// Both factors bounded by constants: the product cannot wrap.
unsigned char *thumb(int width, int height) {
  if (width <= 0 || width > 4096 || height <= 0 || height > 4096)
    return NULL;
  // ok: raptor-unchecked-alloc-product
  return malloc(width * height);
}

// Guard on the size variable's factors.
unsigned char *frame_checked(int width, int height) {
  if (height > 0 && width > INT_MAX / height)
    return NULL;
  int size = width * height;
  // ok: raptor-unchecked-alloc-product
  return malloc(size);
}

// A factor held in a local that is only ever a constant (OpenJPEG pi.c).
int *strides(int numcomps) {
  int stride;
  stride = 4 * 33;
  // ok: raptor-unchecked-alloc-product
  return malloc(stride * numcomps);
}

// Only a positivity check: the product still wraps (the common sanity check
// on image dimensions before the allocation).
unsigned char *positive_only(int w, int h) {
  if (w <= 0 || h <= 0)
    return NULL;
  // ruleid: raptor-unchecked-alloc-product
  return malloc(w * h);
}

// Upper bounds too large for the product to fit.
unsigned char *loose_bound(unsigned w, unsigned h) {
  if (w > 0x7fffffff || h > 0x7fffffff)
    return NULL;
  // ruleid: raptor-unchecked-alloc-product
  return malloc(w * h);
}

// Upper bounds that keep the product in range.
unsigned char *tight_bound(unsigned w, unsigned h) {
  if (w > 4096 || h > 4096)
    return NULL;
  // ok: raptor-unchecked-alloc-product
  return malloc(w * h);
}

// Inside the range test.
unsigned char *inside_bound(unsigned w, unsigned h) {
  if (w < 4096 && h <= 4096)
    // ok: raptor-unchecked-alloc-product
    return malloc(w * h);
  return NULL;
}

// Clamped before the allocation.
unsigned char *clamped(unsigned w, unsigned h) {
  if (w > 1024)
    w = 1024;
  if (h > 1024)
    h = 1024;
  // ok: raptor-unchecked-alloc-product
  return malloc(w * h);
}

// The check comes after the allocation.
unsigned char *late_check(unsigned w, unsigned h) {
  // ruleid: raptor-unchecked-alloc-product
  unsigned char *p = malloc(w * h);
  if (w > 4096 || h > 4096) {
    free(p);
    return NULL;
  }
  return p;
}

// A bound that does not stop the allocation.
unsigned char *warn_only(unsigned w, unsigned h, int *big) {
  if (w > 4096 || h > 4096)
    *big = 1;
  // ruleid: raptor-unchecked-alloc-product
  return malloc(w * h);
}

// Narrow factors: an 8-bit by 16-bit product always fits.
unsigned char *small_factors(uint8_t depth, uint16_t width) {
  // ok: raptor-unchecked-alloc-product
  return malloc(depth * width);
}

// The size stored in an array element first (FreeRDP CVE-2026-55191,
// planar decoder: `piDstSize[x] = piDstStride[x] * h;` then
// `winpr_aligned_recalloc(pDstData[x], piDstSize[x], 1, 16)`).
void *aligned_recalloc(void *p, size_t n, size_t s, size_t a);
int planes(unsigned char **dst, uint32_t *size, uint32_t *stride, uint32_t w, uint32_t h) {
  for (uint32_t x = 0; x < 3; x++) {
    stride[x] = w;
    size[x] = stride[x] * h;
    if (size[x] == 0)
      return 0;
    // ruleid: raptor-unchecked-alloc-product
    dst[x] = aligned_recalloc(dst[x], size[x], 1, 16);
  }
  return 1;
}

// Through two locals and a rounding macro (kissfft CVE-2026-41445,
// kiss_fftndr_alloc: `dimOther*(dimReal+2)*sizeof(kiss_fft_scalar)` in
// nrbufs, then `memneeded = ... + KISS_FFT_ALIGN_SIZE_UP(nrbufs)`).
#define ALIGN_UP(s) (((s) + 15) & ~(size_t)15)
void *fftndr(int dimOther, int dimReal) {
  size_t nrbufs = dimOther * (dimReal + 2) * sizeof(float);
  size_t memneeded = ALIGN_UP(64) + ALIGN_UP(nrbufs);
  // ruleid: raptor-unchecked-alloc-product
  return malloc(memneeded);
}

// The fix: the product is computed in size_t.
void *fftndr_fixed(int dimOther, int dimReal) {
  size_t nrbufs = (size_t)dimOther * (dimReal + 2) * sizeof(float);
  size_t memneeded = ALIGN_UP(64) + ALIGN_UP(nrbufs);
  // ok: raptor-unchecked-alloc-product
  return malloc(memneeded);
}

// The check is on the variable holding the product (OpenJPEG
// opj_pi_create_decode: `if (l_step_l <= (UINT_MAX / (numlayers + 1U)))`).
short *include_array(unsigned max_res, unsigned step_r, unsigned layers) {
  unsigned step_l = max_res * step_r;
  if (step_l <= UINT_MAX / (layers + 1U))
    // ok: raptor-unchecked-alloc-product
    return calloc((layers + 1U) * step_l, sizeof(short));
  return NULL;
}

// Bounded by assertions (OpenJPEG opj_t1_allocate_buffers).
#include <assert.h>
int *block_buffer(unsigned w, unsigned h) {
  assert(w <= 1024);
  assert(h <= 1024);
  unsigned datasize = w * h;
  // ok: raptor-unchecked-alloc-product
  return malloc(datasize * sizeof(int));
}

// The bound holds after an if whose else exits.
int *else_exit(unsigned w, unsigned h) {
  if (w < 1024 && h < 1024)
    ;
  else
    return NULL;
  // ok: raptor-unchecked-alloc-product
  return malloc(w * h);
}

// The allocation multiplies in size_t: a per-line size computed in 32 bits
// is a factor, not the total (libde265 de265_image_get_buffer after the
// fix: `luma_bpl = luma_stride * bytes;` then
// `ALLOC_ALIGNED_16((size_t)luma_height * luma_bpl + PADDING)`).
unsigned char *plane(uint32_t width, uint32_t height, int depth) {
  uint32_t bpl = width * ((depth + 7) / 8);
  // ok: raptor-unchecked-alloc-product
  return malloc((size_t)height * bpl + 64);
}

// Fields validated elsewhere in the file: a division check when the header is
// parsed (OpenJPEG opj_j2k_read_siz `if (l_cp->tw > 65535 / l_cp->th)`), or
// the same product computed in 64 bits and checked (libtiff LERC
// SetupBuffers `(uint64_t)sp->segment_width * sp->segment_height`), in the
// function that sets them. A check in a function that only reads them does
// not count (CVE-2016-9118 above: the fix's check does not cover the
// vulnerable function).
typedef struct {
	uint32_t tw, th;
	uint32_t seg_w, seg_h;
	uint32_t other_w, other_h;
} Cp;
int read_header(Cp *cp, const uint32_t *hdr)
{
	cp->tw = hdr[0];
	cp->th = hdr[1];
	cp->seg_w = hdr[2];
	cp->seg_h = hdr[3];
	if (cp->tw == 0 || cp->th == 0 || cp->tw > 65535 / cp->th)
		return 0;
	uint64_t full = (uint64_t)cp->seg_w * cp->seg_h;
	if ((uint32_t)full != full)
		return 0;
	return 1;
}
void *alloc_tiles(Cp *cp)
{
	// ok: raptor-unchecked-alloc-product
	return calloc(cp->tw * cp->th, 16);
}
void *alloc_segment(Cp *cp)
{
	// ok: raptor-unchecked-alloc-product
	return malloc(cp->seg_w * cp->seg_h);
}
void *alloc_other(Cp *cp)
{
	// ruleid: raptor-unchecked-alloc-product
	return malloc(cp->other_w * cp->other_h);
}

// The product of the factors, widened, compared to a limit (FFmpeg lafdec
// laf_read_header: `if ((int64_t)bpp * st_count * (int64_t)sample_rate >=
// INT32_MAX) return error; av_calloc(st_count * sample_rate, bpp)`).
void *laf_alloc(int st_count, int sample_rate, int bpp)
{
	if ((int64_t)bpp * st_count * (int64_t)sample_rate >= INT32_MAX)
		return 0;
	// ok: raptor-unchecked-alloc-product
	return calloc(st_count * sample_rate, bpp);
}

// A widened product of other values does not check these.
void *laf_alloc_other(int st_count, int sample_rate, int bpp, int other)
{
	if ((int64_t)bpp * other >= INT32_MAX)
		return 0;
	// ruleid: raptor-unchecked-alloc-product
	return calloc(st_count * sample_rate, bpp);
}

// Factors just read as 16-bit values: their product fits 32 bits unsigned
// (FFmpeg sierravmd vmd_read_header: `vmd->frame_count = AV_RL16(..);
// vmd->frames_per_block = AV_RL16(..); av_malloc_array(vmd->frame_count *
// vmd->frames_per_block + sound_buffers, ..)`).
typedef struct { unsigned frame_count, frames_per_block; } Vmd;
static uint16_t rl16(const uint8_t *p) { return p[0] | p[1] << 8; }
void *vmd_table(Vmd *vmd, const uint8_t *hdr)
{
	vmd->frame_count = rl16(hdr + 6);
	vmd->frames_per_block = rl16(hdr + 18);
	// ok: raptor-unchecked-alloc-product
	return malloc(vmd->frame_count * vmd->frames_per_block);
}

// Read narrow on one path only: the other keeps whatever it held.
void *vmd_table_maybe(Vmd *vmd, const uint8_t *hdr, int fresh)
{
	if (fresh) {
		vmd->frame_count = rl16(hdr + 6);
		vmd->frames_per_block = rl16(hdr + 18);
	}
	// ruleid: raptor-unchecked-alloc-product
	return malloc(vmd->frame_count * vmd->frames_per_block);
}
