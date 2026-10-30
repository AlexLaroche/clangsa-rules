int get_nmbr_obj_from_db(void);

#include <stdio.h>
#include <stdlib.h>

#define MEMSIZE 256

void allocate_memory1()
{
	// ruleid: raptor-insecure-api-alloca
	char *buf = alloca(MEMSIZE);

	// ...
}

void allocate_memory2()
{
	// ok: raptor-insecure-api-alloca
	char *buf = malloc(MEMSIZE);

	// ...
}

void allocate_memory3()
{
	int end_limit = get_nmbr_obj_from_db();
	int i;
	void **base = NULL;
	void **p = base;
	for (i = 0; i < end_limit; i++)
	{
		// ruleid: raptor-insecure-api-alloca
		*p = alloca(sizeof(int *));
		p = *p;
	}
}

int main()
{
	printf("Hello, World!");
	return 0;
}
