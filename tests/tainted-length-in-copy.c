#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* OpenSSL's 2-byte and 4-byte big-endian decoders */
#define n2s(c,s)	((s=(((unsigned int)(c[0]))<< 8)| \
			    (((unsigned int)(c[1]))    )),c+=2)
#define n2l(c,l)	(l =((unsigned long)(*((c)++)))<<24, \
			 l|=((unsigned long)(*((c)++)))<<16, \
			 l|=((unsigned long)(*((c)++)))<< 8, \
			 l|=((unsigned long)(*((c)++))))

struct record { unsigned char *data; unsigned int length; };

/* CVE-2014-0160, OpenSSL 1.0.1f tls1_process_heartbeat() */
int heartbleed(struct record *rec)
{
	unsigned char *p = rec->data, *pl, *buffer, *bp;
	unsigned int payload, padding = 16;

	p++;
	n2s(p, payload);
	pl = p;
	buffer = malloc(1 + 2 + payload + padding);
	bp = buffer + 3;
	// ruleid: raptor-tainted-length-in-copy
	memcpy(bp, pl, payload);
	free(buffer);
	return 0;
}

/* the 1.0.1g fix */
int heartbleed_fixed(struct record *rec)
{
	unsigned char *p = rec->data, *pl, *buffer, *bp;
	unsigned int payload, padding = 16;

	p++;
	n2s(p, payload);
	if (1 + 2 + payload + 16 > rec->length)
		return 0;
	pl = p;
	buffer = malloc(1 + 2 + payload + padding);
	bp = buffer + 3;
	// ok: raptor-tainted-length-in-copy
	memcpy(bp, pl, payload);
	free(buffer);
	return 0;
}

/* hand-written little-endian decoding, length used with an offset */
void manual_decode(unsigned char *msg, unsigned char *out)
{
	unsigned int len = msg[0] | (msg[1] << 8);
	// ruleid: raptor-tainted-length-in-copy
	memmove(out, msg + 2, len - 2);
}

/* 4-byte decoder written with |= */
void decode_n2l(unsigned char *p, unsigned char *out)
{
	unsigned long l;
	n2l(p, l);
	// ruleid: raptor-tainted-length-in-copy
	memcpy(out, p, l);
}

/* byte-order conversion functions */
void from_network(const unsigned char *pkt, char *out, size_t outlen)
{
	unsigned short n;
	memcpy(&n, pkt, sizeof(n));
	n = ntohs(n);
	// ruleid: raptor-tainted-length-in-copy
	strncpy(out, (const char *)pkt + 2, n);
	if (n < outlen)
		// ok: raptor-tainted-length-in-copy
		memcpy(out, pkt + 2, n);
}

/* the length is checked on one path only */
void checked_on_one_path(unsigned char *p, unsigned char *out, int strict)
{
	unsigned int len = (p[0] << 8) | p[1];
	if (strict && len > 64)
		return;
	// ruleid: raptor-tainted-length-in-copy
	memcpy(out, p + 2, len);
}

/* the decoding happens in a helper defined in the same file */
static unsigned int get_u16(const unsigned char *p)
{
	return (p[0] << 8) | p[1];
}

void helper_decode(unsigned char *p, unsigned char *out)
{
	unsigned int len = get_u16(p);
	// ruleid: raptor-tainted-length-in-copy
	memcmp(out, p + 2, len);
}

/* clamped */
#define MIN(a, b) ((a) < (b) ? (a) : (b))

void clamped(unsigned char *p, unsigned char out[64])
{
	unsigned int len = (p[0] << 8) | p[1];
	// ok: raptor-tainted-length-in-copy
	memcpy(out, p + 2, MIN(len, 64));
}

/* lengths that do not come from decoded bytes */
void not_decoded(unsigned char *p, unsigned char *out, unsigned int n)
{
	unsigned int k = n << 8;
	// ok: raptor-tainted-length-in-copy
	memcpy(out, p, n);
	// ok: raptor-tainted-length-in-copy
	memcpy(out, p, k);
	// ok: raptor-tainted-length-in-copy
	memcpy(out, p, p[0]);
}

/* OpenSSL 1.0.1f ssl3_get_new_session_ticket(): an exact length check */
void exact_length(unsigned char *p, unsigned char *out, long n)
{
	unsigned int ticklen;
	if (n < 6)
		return;
	p += 4;
	n2s(p, ticklen);
	if (ticklen + 6 != n)
		return;
	// ok: raptor-tainted-length-in-copy
	memcpy(out, p, ticklen);
}

void nonzero_is_not_a_check(unsigned char *p, unsigned char *out)
{
	unsigned int len = (p[0] << 8) | p[1];
	if (len != 0)
		// ruleid: raptor-tainted-length-in-copy
		memcpy(out, p + 2, len);
}

/* CVE-2018-16890, curl 7.63.0 ntlm_decode_type2_target(): the check wraps */
unsigned short Curl_read16_le(const unsigned char *buf);
unsigned int Curl_read32_le(const unsigned char *buf);

void ntlm_target(unsigned char *buffer, size_t size, unsigned char *out)
{
	unsigned short target_info_len = Curl_read16_le(&buffer[40]);
	unsigned int target_info_offset = Curl_read32_le(&buffer[44]);
	if (target_info_len > 0) {
		if (((target_info_offset + target_info_len) > size) ||
		    (target_info_offset < 48))
			return;
		// ruleid: raptor-tainted-length-in-copy
		memcpy(out, &buffer[target_info_offset], target_info_len);
	}
}

/* the 7.64.0 fix: the offset is checked on its own first */
void ntlm_target_fixed(unsigned char *buffer, size_t size, unsigned char *out)
{
	unsigned short target_info_len = Curl_read16_le(&buffer[40]);
	unsigned int target_info_offset = Curl_read32_le(&buffer[44]);
	if (target_info_len > 0) {
		if ((target_info_offset >= size) ||
		    (target_info_offset + target_info_len) > size ||
		    (target_info_offset < 48))
			return;
		// ok: raptor-tainted-length-in-copy
		memcpy(out, &buffer[target_info_offset], target_info_len);
	}
}

/* a lower bound is not a check (libssh2 1.8.0: packet_length < 1) */
void lower_bound(unsigned char *p, unsigned char *out)
{
	unsigned int len = (p[0] << 8) | p[1];
	if (len < 1)
		return;
	// ruleid: raptor-tainted-length-in-copy
	memcpy(out, p + 2, len);
}

/* libssh2 agent.c: len -= blob_len; if (len < 0) bounds blob_len */
unsigned int _libssh2_ntohu32(const unsigned char *buf);

void remaining_length(unsigned char *s, long len, unsigned char *out)
{
	unsigned int blob_len = _libssh2_ntohu32(s);
	len -= blob_len;
	if (len < 0)
		return;
	// ok: raptor-tainted-length-in-copy
	memcpy(out, s + 4, blob_len);
}
