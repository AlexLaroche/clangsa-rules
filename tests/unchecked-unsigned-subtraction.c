// raptor.UncheckedUnsignedSubtraction: an unsigned length is checked from
// below (`if (len < hdr + 6) return;`), then reduced by more than that check
// allows (`len - (hdr + 8)`): when the length lies between the two, the
// difference wraps to a huge size or, promoted to int, a negative index
// (CWE-191, CWE-787, CWE-125).
// Modelled on CVE-2026-28525 (swupdate mg_http_multipart_continue_wait_for_chunk:
// `if ((int) io->len < mp_stream->boundary.len + 6) return 0;` then
// `size_t data_len = io->len - (mp_stream->boundary.len + 8);`) and
// CVE-2026-73252 (mongoose mg_tls_recv_record: `if (msgsz < 16) return -1;`
// then `msg[msgsz - 16 - 1]`, fixed by checking `msgsz < 17`).
#include <stddef.h>
#include <stdint.h>

struct str {
	const char *buf;
	size_t len;
};
struct iobuf {
	unsigned char *buf;
	size_t len;
};
size_t handler(const unsigned char *p, size_t n);

// CVE-2026-28525
int wait_for_chunk(struct iobuf *io, const struct str *boundary, int found)
{
	if ((int)io->len < boundary->len + 6)
		return 0;
	if (!found) {
		// ok: raptor-unchecked-unsigned-subtraction
		size_t data_len = io->len - (boundary->len + 6);
		return (int)handler(io->buf, data_len);
	}
	// ruleid: raptor-unchecked-unsigned-subtraction
	size_t data_len = io->len - (boundary->len + 8);
	return (int)handler(io->buf, data_len);
}

// CVE-2026-73252: a chain of constants.
int recv_record(uint8_t *msg, uint16_t msgsz, uint8_t *type)
{
	if (msgsz < 16)
		return -1;
	// ok: raptor-unchecked-unsigned-subtraction
	handler(msg, msgsz - 16);
	// ruleid: raptor-unchecked-unsigned-subtraction
	*type = msg[msgsz - 16 - 1];
	return 0;
}

// The fix: the check covers the subtraction.
int recv_record_fixed(uint8_t *msg, uint16_t msgsz, uint8_t *type)
{
	if (msgsz < 17)
		return -1;
	// ok: raptor-unchecked-unsigned-subtraction
	*type = msg[msgsz - 16 - 1];
	return 0;
}

// Inside an enclosing check.
size_t payload(const struct iobuf *io)
{
	if (io->len >= 4)
		// ruleid: raptor-unchecked-unsigned-subtraction
		return io->len - 5;
	return 0;
}
size_t payload_ok(const struct iobuf *io)
{
	if (io->len > 4)
		// ok: raptor-unchecked-unsigned-subtraction
		return io->len - 5;
	return 0;
}

// A second, stronger check before the use.
size_t two_checks(const struct iobuf *io)
{
	if (io->len < 2)
		return 0;
	if (io->len < 10)
		return 1;
	// ok: raptor-unchecked-unsigned-subtraction
	return io->len - 8;
}

// Reassigned in between.
size_t reassigned(struct iobuf *io, size_t more)
{
	if (io->len < 2)
		return 0;
	io->len = more + 64;
	// ok: raptor-unchecked-unsigned-subtraction
	return io->len - 8;
}

// No lower-bound check at all: not this rule's form.
size_t unchecked(const struct iobuf *io)
{
	// ok: raptor-unchecked-unsigned-subtraction
	return io->len - 8;
}

// Signed values are not unsigned lengths.
int signed_len(int len)
{
	if (len < 2)
		return 0;
	// ok: raptor-unchecked-unsigned-subtraction
	return len - 8;
}

// A different subtracted term than the checked one.
size_t other_term(const struct iobuf *io, size_t hdr, size_t tag)
{
	if (io->len < hdr + 2)
		return 0;
	// ok: raptor-unchecked-unsigned-subtraction
	return io->len - (tag + 8);
}

// The bound is carried by a comparison of another value with X minus a
// constant (curl tool_help.c: `if (desclen < (cols - 2)) opt = (cols - 3) -
// desclen;`).
size_t column(size_t cols, size_t desclen)
{
	if (cols >= 2 && desclen < (cols - 2))
		// ok: raptor-unchecked-unsigned-subtraction
		return (cols - 3) - desclen;
	return 0;
}
