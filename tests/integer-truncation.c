#include <stdio.h>

void assign_int(int int_var)
{
	// ruleid: raptor-integer-truncation
	char char_var = int_var;
	short short_var;
	int int_var2;

	// ruleid: raptor-integer-truncation
	short_var = int_var;

	// ok: raptor-integer-truncation
	int_var2 = int_var + 1;
}

void assign_long(long long_var)
{
	short short_var;
	// ruleid: raptor-integer-truncation
	int int_var = long_var + 1;

	// ruleid: raptor-integer-truncation
	short_var = long_var;

	// ok: raptor-integer-truncation
	long long_var2 = long_var + 1;
}

void test_func()
{
	int intPrimitive;
	short shortPrimitive;
	intPrimitive = (int)(~((int)0) ^ (1 << (sizeof(int) * 8 - 1)));
	// ruleid: raptor-integer-truncation
	shortPrimitive = intPrimitive;
	printf("Int MAXINT: %d\nShort MAXINT: %d\n", intPrimitive, shortPrimitive);
}

// ruleid: raptor-integer-truncation
char func(void)
{
	int a = 42;
	return a;
}

int main()
{
	printf("Hello, World!");
	return 0;
}

// --- The value provably fits the destination (SymCrypt triage, 2026-11-09).
#include <stdint.h>
#include <stddef.h>
#define MASK32_LT(a, b) ((uint32_t)(((uint64_t)(a) - (b)) >> 32))
#define MASK32_NONZERO(v) ((uint32_t)(((uint64_t)0 - (v)) >> 32))
#define MASK32_ZERO(v) (~MASK32_NONZERO(v))

void value_fits(uint64_t offset, size_t cb, uint64_t idx, uint32_t a32, uint32_t b32,
                uint32_t cpu, unsigned char *buf, uint32_t tmp, uint32_t carry)
{
	uint32_t block, part, leaf, mask;
	unsigned char b;
	unsigned family;
	// ok: raptor-integer-truncation
	block = offset & 0x3f;                     // chacha20.c: masked low bits
	// ok: raptor-integer-truncation
	part = cb % 16;                            // chacha20_poly1305.c: modulo
	// ok: raptor-integer-truncation
	leaf = (uint32_t)(idx & 0xfffff);          // xmss.c: masked with a constant
	// ok: raptor-integer-truncation
	b = (unsigned char)(idx >> 61);            // shake.c: top bits
	// ok: raptor-integer-truncation
	buf[0] = ((tmp << 1) | carry) & 0xff;      // aescmac.c
	// ok: raptor-integer-truncation
	mask = MASK32_LT(a32, b32);                // constant-time mask macros
	// ok: raptor-integer-truncation
	mask = MASK32_ZERO(idx);
	// ok: raptor-integer-truncation
	family = (cpu >> 20) & 0xff;               // cpuid.c
	(void)block; (void)part; (void)leaf; (void)b; (void)mask; (void)family;
}

void value_does_not_fit(uint64_t offset, size_t cb, uint32_t x, int i)
{
	uint16_t h;
	unsigned char b;
	signed char c;
	// ruleid: raptor-integer-truncation
	h = offset & 0x1ffff;                      // 17 bits into 16
	// ruleid: raptor-integer-truncation
	b = x >> 4;                                // 28 bits left
	// ruleid: raptor-integer-truncation
	c = i % 200;                               // signed: -199..199
	// ruleid: raptor-integer-truncation
	h = cb % 70000;
	(void)h; (void)b; (void)c;
}

// --- A wide value deliberately split into limbs/bytes: the same function
// shifts it right by a multiple of the destination width.
void limbs(uint32_t *dst, const uint32_t *a, const uint32_t *b, int n)
{
	uint64_t t = 0;
	for (int i = 0; i < n; i++) {
		t += (uint64_t)a[i] * b[i];
		// ok: raptor-integer-truncation
		dst[i] = (uint32_t)t;                    // fdef_int.c
		t >>= 32;
	}
}
void halves(uint32_t *dst, uint64_t v)
{
	// ok: raptor-integer-truncation
	dst[0] = (uint32_t)v;                      // fdef_general.c / ghash.c
	// ok: raptor-integer-truncation
	dst[1] = (uint32_t)(v >> 32);
}
void be16(unsigned char *p, size_t count)
{
	// ok: raptor-integer-truncation
	p[0] = (unsigned char)(count >> 8);        // dlgroup.c
	// ok: raptor-integer-truncation
	p[1] = (unsigned char)count;
}
void le_bytes(unsigned char *p, uint64_t src, int n)
{
	while (n--) {
		// ok: raptor-integer-truncation
		*p++ = (unsigned char)src;               // libmain.c
		src >>= 8;
	}
}
// Without the shift it is a plain truncation, explicit cast or not.
uint16_t len16(size_t len)
{
	uint16_t l;
	// ruleid: raptor-integer-truncation
	l = (uint16_t)len;
	return l;
}
// A shift by something that is not a multiple of the width is no split.
void odd_shift(unsigned char *p, uint32_t v)
{
	// ruleid: raptor-integer-truncation
	p[0] = (unsigned char)v;
	p[1] = v >> 3 & 1;
}
// The split value may be a struct field or array element (ghash.c).
struct gstate { uint64_t ull[2]; };
void halves_of_field(uint32_t *s32, const struct gstate *st)
{
	// ok: raptor-integer-truncation
	s32[0] = (uint32_t)st->ull[0];
	// ok: raptor-integer-truncation
	s32[1] = (uint32_t)(st->ull[0] >> 32);
	// ruleid: raptor-integer-truncation
	s32[2] = (uint32_t)st->ull[1];             // ull[1] is never shifted
}
