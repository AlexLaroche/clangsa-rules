// raptor.UncheckedSourceOffset: a copy reads from a buffer obtained from a
// call at an offset scaled by a loop counter, and nothing compares the loop
// bound (or a size computed from it) with anything (CWE-125, heap over-read).
// Modelled on CVE-2026-97059 (DCMTK <= 3.7.0, dcmfg/libsrc/concatenationloader.cc):
// extractFrames() copied NumberOfFrames frames out of the Pixel Data element
// without checking that it holds that many bytes.
#include <cstddef>
#include <cstring>

typedef unsigned char Uint8;
typedef unsigned short Uint16;
typedef unsigned int Uint32;

struct Item {
  bool findAndGetUint8Array(int tag, const Uint8 *&value, unsigned long *count = nullptr);
  bool findAndGetUint16Array(int tag, const Uint16 *&value, unsigned long *count = nullptr);
};
struct Frame {
  Uint8 *data;
  size_t len;
};
bool safeMult(size_t a, size_t b, size_t &out);
Frame *newFrame(size_t len);

// CVE-2026-97059: numFrames from the file, Pixel Data length never fetched.
int extractFrames(Item &item, int bitsAlloc, size_t bytesPerFrame, const Uint32 numFrames) {
  const Uint8 *pixData8 = nullptr;
  const Uint16 *pixData16 = nullptr;
  if (bitsAlloc <= 8)
    item.findAndGetUint8Array(0x7fe00010, pixData8);
  else
    item.findAndGetUint16Array(0x7fe00010, pixData16);
  for (Uint32 f = 0; f < numFrames; f++) {
    Frame *frame = newFrame(bytesPerFrame);
    if (bitsAlloc <= 8) {
      const Uint8 *ptr = pixData8 + f * frame->len;
      // ruleid: raptor-unchecked-source-offset
      memcpy(frame->data, ptr, frame->len);
    } else {
      const Uint16 *ptr = pixData16 + f * frame->len / 2;
      // ruleid: raptor-unchecked-source-offset
      memcpy(frame->data, ptr, frame->len);
    }
  }
  return 0;
}

// The fix: fetch the length, compare it with bytesPerFrame * numFrames.
int extractFramesFixed(Item &item, size_t bytesPerFrame, const Uint32 numFrames) {
  const Uint8 *pixData8 = nullptr;
  unsigned long count = 0;
  item.findAndGetUint8Array(0x7fe00010, pixData8, &count);
  size_t bytesRequired = 0;
  if (!safeMult(bytesPerFrame, numFrames, bytesRequired) || bytesRequired > count)
    return -1;
  for (Uint32 f = 0; f < numFrames; f++) {
    Frame *frame = newFrame(bytesPerFrame);
    const Uint8 *ptr = pixData8 + f * frame->len;
    // ok: raptor-unchecked-source-offset
    memcpy(frame->data, ptr, frame->len);
  }
  return 0;
}

// The bound is compared directly.
void copyChecked(Item &item, Uint8 *out, size_t k, Uint32 n) {
  const Uint8 *src = nullptr;
  unsigned long count = 0;
  item.findAndGetUint8Array(1, src, &count);
  if (n * k > count)
    return;
  for (Uint32 i = 0; i < n; ++i)
    // ok: raptor-unchecked-source-offset
    memcpy(out + i * k, src + i * k, k);
}

// The buffer comes from the caller, who sized it.
void copyFromParam(const Uint8 *src, Uint8 *out, size_t k, Uint32 n) {
  for (Uint32 i = 0; i < n; ++i)
    // ok: raptor-unchecked-source-offset
    memcpy(out + i * k, src + i * k, k);
}

// Constant bound.
void copyFixedCount(Item &item, Uint8 *out) {
  const Uint8 *src = nullptr;
  item.findAndGetUint8Array(1, src);
  for (int i = 0; i < 4; ++i)
    // ok: raptor-unchecked-source-offset
    memcpy(out + i * 16, src + i * 16, 16);
}

// The source offset does not depend on the loop counter.
void copySameBlock(Item &item, Uint8 *out, Uint32 n) {
  const Uint8 *src = nullptr;
  item.findAndGetUint8Array(1, src);
  for (Uint32 i = 0; i < n; ++i)
    // ok: raptor-unchecked-source-offset
    memcpy(out + i * 16, src, 16);
}

// Index form, no check.
void copyIndexed(Item &item, Uint8 *out, size_t k, Uint32 n) {
  const Uint8 *src = nullptr;
  item.findAndGetUint8Array(1, src);
  for (Uint32 i = 0; i < n; ++i)
    // ruleid: raptor-unchecked-source-offset
    memcpy(out, &src[i * k], k);
}
