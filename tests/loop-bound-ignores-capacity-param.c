// raptor.LoopBoundIgnoresCapacityParam: a function receives an output
// buffer and its capacity (`float *Dst, unsigned nVectorSize`, or an in/out
// count `unsigned *frame_cnt`), then fills the buffer in a loop bounded by
// something else (the object's own size, a count read from the data) that
// is never bounded by the capacity: the caller's buffer overflows (CWE-787,
// CWE-120).
// Modelled on CVE-2026-25584 / CVE-2026-30987 (iccDEV CIccTagFloatNum /
// CIccTagNum GetValues: `if (nVectorSize > m_nSize) return false;` - a check in
// the wrong direction - then `for (i=0; i<m_nSize; i++) DstVector[i] = ...;`)
// and CVE-2026-29068 (pjsip opus codec_parse: `num_frames` from the packet,
// `for (i = 0; i < num_frames; ++i) frames[i].buf = ...;`, the caller's
// `*frame_cnt` ignored; fixed by clamping num_frames to *frame_cnt).
#include <stddef.h>

typedef struct {
	float *m_Num;
	unsigned m_nSize;
} Tag;

// CVE-2026-25584
int get_values(const Tag *t, float *DstVector, unsigned nStart, unsigned nVectorSize)
{
	if (nVectorSize > t->m_nSize)
		return 0;
	for (unsigned i = 0; i < t->m_nSize; i++)
		// ruleid: raptor-loop-bound-ignores-capacity-param
		DstVector[i] = t->m_Num[i + nStart];
	return 1;
}
// The fix: loop to the caller's size.
int get_values_fixed(const Tag *t, float *DstVector, unsigned nStart, unsigned nVectorSize)
{
	if (nVectorSize > t->m_nSize)
		return 0;
	for (unsigned i = 0; i < nVectorSize; i++)
		// ok: raptor-loop-bound-ignores-capacity-param
		DstVector[i] = t->m_Num[i + nStart];
	return 1;
}

// CVE-2026-29068: an in/out count, fields of each element written.
typedef struct {
	int type;
	void *buf;
	size_t size;
} frame_t;
int get_nb_frames(const void *pkt);
int parse(const void *pkt, unsigned *frame_cnt, frame_t frames[])
{
	int num_frames = get_nb_frames(pkt);
	for (int i = 0; i < num_frames; ++i) {
		// ruleid: raptor-loop-bound-ignores-capacity-param
		frames[i].type = 1;
		frames[i].buf = (void *)pkt;
	}
	*frame_cnt = num_frames;
	return 0;
}
// The fix: clamped first.
int parse_fixed(const void *pkt, unsigned *frame_cnt, frame_t frames[])
{
	int num_frames = get_nb_frames(pkt);
	if (num_frames > (int)*frame_cnt)
		num_frames = (int)*frame_cnt;
	for (int i = 0; i < num_frames; ++i)
		// ok: raptor-loop-bound-ignores-capacity-param
		frames[i].type = 1;
	*frame_cnt = num_frames;
	return 0;
}

// Bounded by an exiting check in the right direction.
int checked(const Tag *t, float *dst, unsigned dst_len)
{
	if (t->m_nSize > dst_len)
		return -1;
	for (unsigned i = 0; i < t->m_nSize; i++)
		// ok: raptor-loop-bound-ignores-capacity-param
		dst[i] = t->m_Num[i];
	return 0;
}

// The capacity in the loop condition, or a break on it.
void both(const Tag *t, float *dst, unsigned dst_len)
{
	for (unsigned i = 0; i < t->m_nSize && i < dst_len; i++)
		// ok: raptor-loop-bound-ignores-capacity-param
		dst[i] = t->m_Num[i];
	for (unsigned i = 0; i < t->m_nSize; i++) {
		if (i >= dst_len)
			break;
		// ok: raptor-loop-bound-ignores-capacity-param
		dst[i] = t->m_Num[i];
	}
}

// No capacity parameter: nothing to compare with.
void no_capacity(const Tag *t, float *dst)
{
	for (unsigned i = 0; i < t->m_nSize; i++)
		// ok: raptor-loop-bound-ignores-capacity-param
		dst[i] = t->m_Num[i];
}

// A read-only buffer is not an output.
float sum(const Tag *t, const float *weights, unsigned nweights)
{
	float s = 0;
	for (unsigned i = 0; i < t->m_nSize; i++)
		// ok: raptor-loop-bound-ignores-capacity-param
		s += weights[i] * t->m_Num[i];
	return s;
}

// The bound initialised from the capacity (libarchive aes_ctr_update:
// `size_t max = (in_len < *out_len) ? in_len : *out_len;`).
int ctr_update(const unsigned char *in, size_t in_len, unsigned char *out, size_t *out_len)
{
	size_t max = (in_len < *out_len) ? in_len : *out_len;
	size_t i;
	for (i = 0; i < max; i++)
		// ok: raptor-loop-bound-ignores-capacity-param
		out[i] = in[i] ^ 0x5a;
	*out_len = i;
	return 0;
}

// The bound is the buffer's own count parameter (HAProxy
// `regex_exec_match2(..., int length, size_t nmatch, regmatch_t pmatch[], ...)`,
// BIND 9 `ns_listenelt_create_http(..., char **endpoints, size_t nendpoints,
// const uint32_t max_clients, ...)`): the other size parameter describes
// something else.
typedef struct { int rm_so, rm_eo; } Match;
int exec_match(const char *subject, int length, unsigned long nmatch,
	       Match pmatch[], const int *found)
{
	unsigned long i;
	for (i = 0; i < nmatch; i++)
		// ok: raptor-loop-bound-ignores-capacity-param
		pmatch[i].rm_so = found[i];
	return length;
}
void release_endpoints(char **endpoints, unsigned long nendpoints,
		       unsigned max_clients)
{
	unsigned long i;
	for (i = 0; i < nendpoints; i++)
		// ok: raptor-loop-bound-ignores-capacity-param
		endpoints[i] = 0;
	(void)max_clients;
}
// Another buffer's count is not this one's capacity.
void copy_items(int *dst, unsigned long dst_len, const int *src,
		unsigned long nsrc)
{
	unsigned long i;
	for (i = 0; i < nsrc; i++)
		// ruleid: raptor-loop-bound-ignores-capacity-param
		dst[i] = src[i];
}
// A line size is the distance between rows, not the room in the buffer
// (FFmpeg vf_hue apply_luma_lut10(ldst, dst_linesize, lsrc, src_linesize,
// w, h), utvideodsp restore_rgb_planes, screenpresso sum_delta_flipped).
void apply_lut(unsigned short *ldst, const int dst_linesize,
	       const unsigned short *lsrc, const int src_linesize,
	       const unsigned short *lut, int w, int h)
{
	int i;
	while (h--) {
		for (i = 0; i < w; i++)
			// ok: raptor-loop-bound-ignores-capacity-param
			ldst[i] = lut[lsrc[i]];
		lsrc += src_linesize;
		ldst += dst_linesize;
	}
}
// A value limit named max_* is not the buffer's room (FFmpeg lpc.c
// quantize_lpc_coefs(lpc_in, order, precision, lpc_out, shift, min_shift,
// max_shift, zero_shift)).
void quantize(const double *in, int order, int *out, int min_shift, int max_shift)
{
	int i;
	for (i = 0; i < order; i++)
		// ok: raptor-loop-bound-ignores-capacity-param
		out[i] = (int)in[i] << (max_shift - min_shift);
}
// A parameter named just `max` is a capacity.
void fill_max(int *out, unsigned max, unsigned n)
{
	unsigned i;
	for (i = 0; i < n; i++)
		// ruleid: raptor-loop-bound-ignores-capacity-param
		out[i] = 0;
}
