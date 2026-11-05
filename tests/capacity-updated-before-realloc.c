// raptor.CapacityUpdatedBeforeRealloc: an object's size or dimension field
// is set to the new value before the buffer it describes is reallocated, and
// the failure branch of the reallocation leaves without restoring it: the
// object now claims a capacity its (old, smaller) buffer does not have, and
// the next use writes past it (CWE-131, CWE-787).
// Modelled on CVE-2026-33984 (FreeRDP clear.c resize_vbar_entry:
// `vBarEntry->size = vBarEntry->count;` then
// `tmp = winpr_aligned_recalloc(vBarEntry->pixels, ...); if (!tmp) return FALSE;`)
// and CVE-2026-33986 (FreeRDP h264.c yuv_ensure_buffer: `h264->width = width;
// h264->height = height;` before recallocating each h264->pYUVData[x]); both
// fixed by setting the fields after the reallocation succeeded.
#include <stddef.h>
#include <stdint.h>

typedef int BOOL;
void *winpr_aligned_recalloc(void *p, size_t n, size_t size, size_t align);
void *realloc(void *p, size_t n);

typedef struct {
	uint32_t size;
	uint32_t count;
	uint8_t *pixels;
} VBarEntry;

// CVE-2026-33984
BOOL resize_vbar_entry(VBarEntry *vBarEntry, uint32_t bpp)
{
	if (vBarEntry->count > vBarEntry->size) {
		// ruleid: raptor-capacity-updated-before-realloc
		vBarEntry->size = vBarEntry->count;
		uint8_t *tmp = winpr_aligned_recalloc(vBarEntry->pixels, vBarEntry->count, bpp, 32);
		if (!tmp)
			return 0;
		vBarEntry->pixels = tmp;
	}
	return 1;
}
// The fix: the size follows the successful reallocation.
BOOL resize_vbar_entry_fixed(VBarEntry *vBarEntry, uint32_t bpp)
{
	if (vBarEntry->count > vBarEntry->size) {
		uint8_t *tmp = winpr_aligned_recalloc(vBarEntry->pixels, vBarEntry->count, bpp, 32);
		if (!tmp)
			return 0;
		vBarEntry->pixels = tmp;
		// ok: raptor-capacity-updated-before-realloc
		vBarEntry->size = vBarEntry->count;
	}
	return 1;
}

// CVE-2026-33986: dimensions, several planes.
typedef struct {
	uint32_t width, height;
	uint32_t iStride[3];
	uint8_t *pYUVData[3];
} H264;
BOOL yuv_ensure_buffer(H264 *h264, uint32_t stride, uint32_t width, uint32_t height)
{
	if (width != h264->width || height != h264->height) {
		h264->iStride[0] = stride;
		// ruleid: raptor-capacity-updated-before-realloc
		h264->width = width;
		// ruleid: raptor-capacity-updated-before-realloc
		h264->height = height;
		for (size_t x = 0; x < 3; x++) {
			uint8_t *tmp = winpr_aligned_recalloc(h264->pYUVData[x], h264->iStride[x], height, 16);
			if (!tmp)
				return 0;
			h264->pYUVData[x] = tmp;
		}
	}
	return 1;
}

// Restored on the failure branch.
typedef struct {
	size_t len;
	char *buf;
} Buf;
int grow_restored(Buf *b, size_t n)
{
	size_t old = b->len;
	// ok: raptor-capacity-updated-before-realloc
	b->len = n;
	char *p = realloc(b->buf, n);
	if (!p) {
		b->len = old;
		return -1;
	}
	b->buf = p;
	return 0;
}

// A field unrelated to the buffer.
typedef struct {
	int state;
	size_t len;
	char *buf;
} Conn;
int grow_state(Conn *c, size_t n)
{
	// ok: raptor-capacity-updated-before-realloc
	c->state = 2;
	char *p = realloc(c->buf, n);
	if (!p)
		return -1;
	c->buf = p;
	c->len = n;
	return 0;
}

// The failure branch does not leave: the object is freed or reset later.
int grow_no_exit(Buf *b, size_t n, int *err)
{
	// ok: raptor-capacity-updated-before-realloc
	b->len = n;
	char *p = realloc(b->buf, n);
	if (!p)
		*err = 1;
	else
		b->buf = p;
	return 0;
}

// Set in another branch, with its own allocation (libarchive
// standard_lookup: `if (cache->buff_size == 0) { cache->buff_size = 256;
// cache->buff = malloc(cache->buff_size); }`, a realloc later in a loop).
void *malloc(size_t n);
int lookup(Buf *b, int (*get)(char *, size_t))
{
	if (b->len == 0) {
		// ok: raptor-capacity-updated-before-realloc
		b->len = 256;
		b->buf = malloc(b->len);
	}
	if (b->buf == NULL)
		return -1;
	while (get(b->buf, b->len) != 0) {
		size_t n = b->len * 2;
		char *p = realloc(b->buf, n);
		if (p == NULL)
			return -1;
		b->buf = p;
		b->len = n;
	}
	return 0;
}

// The failure branch ends the program (libarchive line_reader: lafe_errc).
_Noreturn void fatal(int code, const char *msg);
void grow_or_die(Buf *b, size_t n)
{
	// ok: raptor-capacity-updated-before-realloc
	b->len = n;
	char *p = realloc(b->buf, n + 1);
	if (p == NULL)
		fatal(1, "out of memory");
	b->buf = p;
}
