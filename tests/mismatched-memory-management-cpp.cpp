#include <stdio.h>
#include <stdlib.h>
#include <new>

class BarObj {};

void bad1()
{
	BarObj *ptr = new BarObj();

		// ruleid: raptor-mismatched-memory-management-cpp
		free(ptr);
}

void good1()
{
	BarObj *ptr = new BarObj();

		// ok: raptor-mismatched-memory-management-cpp
		delete ptr;
}

class A
{
	void bad2();
	void good2();
};

void A::bad2()
{
	int *ptr;
	ptr = (int *)malloc(sizeof(int));

	// ruleid: raptor-mismatched-memory-management-cpp
	delete ptr;
}

void A::good2()
{
	int *ptr;
	ptr = (int *)malloc(sizeof(int));

	// ok: raptor-mismatched-memory-management-cpp
	free(ptr);
}

class B
{
	void bad3(bool);
	void good3();
};

void B::bad3(bool heap)
{
	int localArray[2] = {11, 22};
	int *p = localArray;

	if (heap)
	{
		p = new int[2];
	}

	// ruleid: raptor-mismatched-memory-management-cpp
	delete[] p;
}

void B::good3()
{
	int localArray[2] = {11, 22};
	int *p = localArray;

	p = new (std::nothrow) int[2];

	// ok: raptor-mismatched-memory-management-cpp
	delete[] p;
}

// Regression tests for false positives found on dotnet/runtime (zstd
// dictBuilder): free(NULL), delete nullptr and delete[] nullptr are no-ops,
// so releasing a pointer known to be NULL on this path is not a mismatch.
void good_release_after_failed_alloc(size_t n)
{
	int *p = (int *)malloc(n * sizeof(int));
	if (p == NULL) {
		// ok: raptor-mismatched-memory-management-cpp
		free(p);
		return;
	}
	// ok: raptor-mismatched-memory-management-cpp
	free(p);
}

void good_release_null(void)
{
	int *a = nullptr;
	int *b = nullptr;
	// ok: raptor-mismatched-memory-management-cpp
	free(NULL);
	// ok: raptor-mismatched-memory-management-cpp
	delete a;
	// ok: raptor-mismatched-memory-management-cpp
	delete[] b;
}

void good_free_through_int_cast(size_t n)
{
	char *p = (char *)malloc(n);
	// ok: raptor-mismatched-memory-management-cpp
	free((void *)(size_t)p);
}

// Memory of unknown origin: destructors and teardown functions.
struct Holder {
	int *a;
	~Holder()
	{
		// ok: raptor-mismatched-memory-management-cpp
		delete[] a;
	}
};
void destroy(BarObj *t)
{
	// ok: raptor-mismatched-memory-management-cpp
	delete t;
}
void release_array(int *p)
{
	// ok: raptor-mismatched-memory-management-cpp
	delete[] p;
}

// new[] released with free(), scalar new with delete[].
void bad_families(void)
{
	int *p = new int[3];
	// ruleid: raptor-mismatched-memory-management-cpp
	free(p);
}
void bad_families2(void)
{
	BarObj *o = new BarObj();
	// ruleid: raptor-mismatched-memory-management-cpp
	delete[] o;
}

int main()
{
	printf("Hello, World!");
	return 0;
}
