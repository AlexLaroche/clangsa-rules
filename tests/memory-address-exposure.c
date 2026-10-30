#include <stdio.h>

#define BUFSIZE 256
#define FMT "whatever"

/* stubs added for the clang port (not part of the original semgrep test) */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef struct Node Node;
uint32_t drand(void);

void print_address(char *string)
{
	char buf[BUFSIZE];
	char fmt[] = "whatever";

	// ruleid: raptor-memory-address-exposure
	printf("address: %p\n", buf);

	// ruleid: raptor-memory-address-exposure
	sprintf(buf, "address: %x\n", string);

	// ok: raptor-memory-address-exposure
	sprintf(buf, FMT, string);

	// ok: raptor-memory-address-exposure
	sprintf(buf, fmt, string);

	// ok: raptor-memory-address-exposure
	sprintf(buf, string);
}

char *genUniqueVal(Node *n)
{
	char *buf = (char *)malloc(32);
	if (!buf)
		return NULL;

	memset(buf, 0x0, 32);
	uint32_t uval = (uintptr_t)&buf; /* cast added for the clang port */

	if (uval == 0)
	{
		uval = drand();
	}
	// ruleid: raptor-memory-address-exposure
	snprintf(buf, 32, "%x", uval);
	return buf;
}

int main()
{
	printf("Hello, World!");
	return 0;
}
