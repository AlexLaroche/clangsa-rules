// raptor.TruncatedProduct: a product of two run-time values is computed in
// int (integer promotion) and implicitly stored into, or returned as, a type
// narrower than int that cannot hold it: a count or size wraps to a small
// value, the buffer sized from it is too small for the loops that use the
// real product (CWE-190, CWE-681, CWE-787).
// Modelled on CVE-2026-105837 / CVE-2026-105839 (libmikmod DSM_Load and
// OKT_doPBOD: `of.numtrk = of.numchn * of.numpat;` with a UWORD numtrk, a
// UBYTE numchn and a UWORD numpat; AllocTracks() allocates numtrk tracks,
// the loaders index numchn * numpat of them) and CVE-2026-21688 (iccDEV
// SIccCalcOp::ArgsUsed returning `(v1+1)*(v2+1)` as an icUInt16Number).
#include <stdint.h>

typedef unsigned char UBYTE;
typedef unsigned short UWORD;
typedef struct {
  UBYTE numchn;
  UWORD numpat;
  UWORD numtrk;
} Module;
Module of;
int alloc_tracks(void);

// CVE-2026-105837
int dsm_load(UBYTE chn, UWORD pat) {
  of.numchn = chn;
  of.numpat = pat;
  // ruleid: raptor-truncated-product
  of.numtrk = of.numchn * of.numpat;
  return alloc_tracks();
}

// The fix: computed wide, checked, narrowed explicitly.
int dsm_load_fixed(UBYTE chn, UWORD pat) {
  unsigned int numtrk;
  of.numchn = chn;
  of.numpat = pat;
  // ok: raptor-truncated-product
  numtrk = of.numchn * of.numpat;
  if (numtrk > 65535)
    return 0;
  // ok: raptor-truncated-product
  of.numtrk = (UWORD)numtrk;
  return alloc_tracks();
}

// CVE-2026-21688: returned, with each operand one past a 16-bit value.
typedef unsigned short icUInt16Number;
typedef struct {
  struct {
    icUInt16Number v1, v2;
  } select;
} CalcOp;
icUInt16Number args_used(const CalcOp *op) {
  // ruleid: raptor-truncated-product
  return (op->select.v1 + 1) * (op->select.v2 + 1);
}

// The fix: 64-bit product, clamped, explicit cast.
icUInt16Number args_used_fixed(const CalcOp *op) {
  uint64_t full = ((uint64_t)op->select.v1 + 1) * ((uint64_t)op->select.v2 + 1);
  if (full > 1024)
    full = 1024;
  // ok: raptor-truncated-product
  return (icUInt16Number)full;
}

// Initialisation of a local.
UWORD cells(UBYTE rows, UBYTE cols, UWORD depth) {
  // ruleid: raptor-truncated-product
  UWORD n = rows * depth;
  // ok: raptor-truncated-product
  UWORD m = rows * cols;
  return n + m;
}

// Products that fit: 4-bit * 4-bit values into a byte, a constant factor,
// a scaled-down product.
UBYTE blend(UBYTE a, UBYTE b, UWORD w) {
  UBYTE lo = a & 0x0f, hi = b & 0x0f;
  // ok: raptor-truncated-product
  UBYTE x = lo * 3;
  // ok: raptor-truncated-product
  UBYTE y = (a * b) / 255;
  // ok: raptor-truncated-product
  UWORD z = w * 2;
  return x + y + (UBYTE)z + hi;
}

// Into int or wider: other rules' business (UncheckedAllocProduct).
int area(int w, int h) {
  // ok: raptor-truncated-product
  int a = w * h;
  return a;
}
