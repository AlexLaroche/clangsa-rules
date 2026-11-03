// raptor.WStreamLengthUnsealed: Stream_Length() of a WinPR wStream that is
// filled by position (Stream_Write*, Stream_Seek...) and never sealed
// (Stream_SealLength/Stream_SetLength) returns the buffer's capacity, not the
// amount of data written; sending that many bytes discloses stale memory
// (CWE-130, CWE-201).
// Modelled on CVE-2026-67292 (FreeRDP < 3.29.0,
// libfreerdp/core/gateway/websocket.c): the Pong reply was sent with
// Stream_Length() of a 1024-byte response stream.
#include <stddef.h>

typedef unsigned char BYTE;
typedef int BOOL;
typedef struct s_wStream {
  BYTE *buffer, *pointer;
  size_t length, capacity;
} wStream;

wStream *Stream_New(BYTE *buffer, size_t size);
void Stream_StaticConstInit(wStream *s, const BYTE *buffer, size_t size);
size_t Stream_Length(const wStream *s);
size_t Stream_GetPosition(const wStream *s);
BYTE *Stream_Buffer(wStream *s);
BYTE *Stream_Pointer(wStream *s);
void Stream_SealLength(wStream *s);
void Stream_SetLength(wStream *s, size_t len);
BOOL Stream_SafeSeek(wStream *s, size_t n);
void Stream_Write_UINT16(wStream *s, unsigned short v);
void Stream_ResetPosition(wStream *s);
size_t Stream_GetRemainingLength(const wStream *s);
int bio_write(void *bio, const BYTE *data, size_t len);
int read_data(void *bio, BYTE *out, size_t n);

typedef struct {
  wStream *responseStreamBuffer;
  wStream *requestStream;
} websocket_context;

// The sender: trusts Stream_Length().
static BOOL write_wstream(void *bio, wStream *sPacket) {
  // ruleid: raptor-w-stream-length-unsealed
  const size_t len = Stream_Length(sPacket);
  return bio_write(bio, Stream_Buffer(sPacket), len) >= 0;
}

static BOOL reply_pong(void *bio, wStream *s) {
  if (Stream_GetPosition(s) != 0)
    return write_wstream(bio, s);
  return 0;
}

// The response stream is filled by seeking past received bytes.
static int read_wstream(void *bio, websocket_context *ctx) {
  wStream *s = ctx->responseStreamBuffer;
  int status = read_data(bio, Stream_Pointer(s), 125);
  if (status < 0 || !Stream_SafeSeek(s, (size_t)status))
    return -1;
  return status;
}

int handle_ping(void *bio, websocket_context *ctx) {
  if (read_wstream(bio, ctx) < 0)
    return -1;
  reply_pong(bio, ctx->responseStreamBuffer);
  Stream_ResetPosition(ctx->responseStreamBuffer);
  return 0;
}

void context_new(websocket_context *ctx) {
  ctx->responseStreamBuffer = Stream_New(NULL, 1024);
  ctx->requestStream = Stream_New(NULL, 64);
}

// The fix: seal before taking the length.
static BOOL write_request(void *bio, wStream *sPacket) {
  Stream_SealLength(sPacket);
  // ok: raptor-w-stream-length-unsealed
  const size_t len = Stream_Length(sPacket);
  return bio_write(bio, Stream_Buffer(sPacket), len) >= 0;
}

int send_request(void *bio, websocket_context *ctx) {
  Stream_Write_UINT16(ctx->requestStream, 0x1234);
  return write_request(bio, ctx->requestStream);
}

// A stream wrapping received data: never written by position.
size_t parse_frame(const BYTE *data, size_t size) {
  wStream sbuffer;
  wStream *s = &sbuffer;
  Stream_StaticConstInit(s, data, size);
  // ok: raptor-w-stream-length-unsealed
  return Stream_Length(s);
}

// A local stream written and measured without sealing.
int send_local(void *bio) {
  wStream *s = Stream_New(NULL, 256);
  Stream_Write_UINT16(s, 7);
  // ruleid: raptor-w-stream-length-unsealed
  return bio_write(bio, Stream_Buffer(s), Stream_Length(s));
}

// Written, then sealed by the writer before it is passed on.
static size_t measure(wStream *s) {
  // ok: raptor-w-stream-length-unsealed
  return Stream_Length(s);
}

size_t send_sealed(void) {
  wStream *s = Stream_New(NULL, 256);
  Stream_Write_UINT16(s, 7);
  Stream_SealLength(s);
  return measure(s);
}
