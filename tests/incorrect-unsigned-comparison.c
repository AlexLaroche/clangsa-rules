#include <stdio.h>

int bad1()
{
	size_t uvar;

	// ruleid: raptor-incorrect-unsigned-comparison
	if (uvar < 0)
		return 1;

	return 0;
}

int bad2()
{
	size_t uvar;

	// ruleid: raptor-incorrect-unsigned-comparison
	if (uvar <= 0)
		return 1;

	return 0;
}

int good1()
{
	size_t uvar;

	// ok: raptor-incorrect-unsigned-comparison
	if (uvar > 0)
		return 1;

	return 0;
}

int main()
{
	printf("Hello, World!");
	return 0;
}

/* A type-generic macro comparing its argument with 0: the comparison is
 * meaningful for the signed types it is also used with (FreeRDP
 * `WINPR_ASSERTING_INT_CAST(UINT32, gdi->height)`). */
#define NON_NEGATIVE(v) ((v) >= 0)
int generic_macro(size_t uvar, int svar)
{
	// ok: raptor-incorrect-unsigned-comparison
	int a = NON_NEGATIVE(uvar);
	int b = NON_NEGATIVE(svar);
	// ruleid: raptor-incorrect-unsigned-comparison
	return a + b + (uvar >= 0);
}
