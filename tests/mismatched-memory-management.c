#include <stdio.h>
#include <stdlib.h>

void bad1()
{
	int localArray[2] = {11, 22};
	int *p = localArray;

	// ruleid: raptor-mismatched-memory-management
	free(p);
}

void good1()
{
	int *ptr;
	ptr = (int *)malloc(sizeof(int));

	// ok: raptor-mismatched-memory-management
	free(ptr);
}

// Regression tests for bugs found on dotnet/runtime: free(NULL) is a no-op,
// so freeing a pointer known to be NULL on this path (e.g. after a failed
// allocation) is not a mismatch.
static int *g_ints;
static char *g_flags;

void good_free_after_failed_alloc(int n)
{
	int *p = (int *)calloc((size_t)n, sizeof(int));
	if (p == NULL) {
		// ok: raptor-mismatched-memory-management
		free(p);
		return;
	}
	// ok: raptor-mismatched-memory-management
	free(p);
}

void good_free_globals_on_partial_failure(int n)
{
	g_ints = (int *)calloc(sizeof(int), (size_t)n);
	g_flags = (char *)calloc(sizeof(char), (size_t)n);
	if (g_ints == NULL || g_flags == NULL) {
		// ok: raptor-mismatched-memory-management
		free(g_ints);
		// ok: raptor-mismatched-memory-management
		free((void *)(size_t)g_flags);
	}
}

void good_free_null_literal(void)
{
	// ok: raptor-mismatched-memory-management
	free(NULL);
}

void bad_free_stack_through_int_cast(void)
{
	char buf[16];
	// ruleid: raptor-mismatched-memory-management
	free((void *)(size_t)buf);
}

int main()
{
	printf("Hello, World!");
	return 0;
}
