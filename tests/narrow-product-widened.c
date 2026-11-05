// raptor.NarrowProductWidened: a product computed in 32 bits is converted to
// a 64-bit type afterwards (`(uint64_t)(w * 3)`, `uint64_t n = a * b;`, a
// size_t field set from an int product): the program wants the full value,
// but the multiplication has already wrapped. Size checks and offsets built
// on it pass with a small number (CWE-190, CWE-681, CWE-787).
// Modelled on CVE-2026-34588 (OpenEXR internal_pxr24.c undo_pxr24:
// `if (nDec + (uint64_t) (w * 3) > outSize)`, fixed as `(uint64_t) w * 3`),
// CVE-2026-41142 (OpenEXR ImageChannel::resize: `_numPixels = _pixelsPerRow *
// _pixelsPerColumn;` with int factors and a size_t field) and CVE-2026-21486
// (iccDEV CIccTagSparseMatrixArray::Read: `icUInt64Number nNeededSize =
// nBytesPerMatrix * nNumMatrices;` with 32-bit factors).
#include <stddef.h>
#include <stdint.h>

// CVE-2026-34588: an explicit cast of the product, a constant factor.
int undo_pxr24(uint64_t nDec, uint64_t outSize, int w)
{
	// ruleid: raptor-narrow-product-widened
	if (nDec + (uint64_t)(w * 3) > outSize)
		return -1;
	return 0;
}
// The fix: widen before multiplying.
int undo_pxr24_fixed(uint64_t nDec, uint64_t outSize, int w)
{
	// ok: raptor-narrow-product-widened
	if (nDec + (uint64_t)w * 3 > outSize)
		return -1;
	return 0;
}

// CVE-2026-41142: a size_t field from an int product.
struct channel {
	int pixelsPerRow, pixelsPerColumn;
	size_t numPixels;
};
void resize(struct channel *c)
{
	// ruleid: raptor-narrow-product-widened
	c->numPixels = c->pixelsPerRow * c->pixelsPerColumn;
}
void resize_fixed(struct channel *c)
{
	const uint64_t w64 = (uint64_t)c->pixelsPerRow;
	const uint64_t h64 = (uint64_t)c->pixelsPerColumn;
	if (w64 != 0 && h64 > SIZE_MAX / w64)
		return;
	// ok: raptor-narrow-product-widened
	c->numPixels = (size_t)(w64 * h64);
}

// CVE-2026-21486: a 64-bit local from 32-bit factors.
int read_sparse(uint32_t nBytesPerMatrix, uint32_t nNumMatrices, uint64_t nSizeLeft)
{
	// ruleid: raptor-narrow-product-widened
	uint64_t nNeededSize = nBytesPerMatrix * nNumMatrices;
	if (nNeededSize > nSizeLeft)
		return 0;
	return 1;
}
int read_sparse_fixed(uint64_t nBytesPerMatrix, uint32_t nNumMatrices, uint64_t nSizeLeft)
{
	// ok: raptor-narrow-product-widened
	uint64_t nNeededSize = nBytesPerMatrix * nNumMatrices;
	return nNeededSize <= nSizeLeft;
}

// Checked against overflow first.
uint64_t checked(uint32_t a, uint32_t b)
{
	if (b && a > UINT32_MAX / b)
		return 0;
	// ok: raptor-narrow-product-widened
	uint64_t n = a * b;
	return n;
}

// Too narrow to wrap, or one constant factor in an implicit widening (a
// stride: IntegerWraparound's business).
uint64_t narrow(uint8_t a, uint16_t b, uint32_t c)
{
	// ok: raptor-narrow-product-widened
	uint64_t n = a * b;
	// ok: raptor-narrow-product-widened
	uint64_t m = c * 4;
	return n + m;
}

// Stored in 32 bits: not widened.
uint32_t same_width(uint32_t a, uint32_t b)
{
	// ok: raptor-narrow-product-widened
	uint32_t n = a * b;
	return n;
}
