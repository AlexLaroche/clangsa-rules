#include <stdio.h> /* stub so that the test compiles */

int hush_hush()
{
	// ruleid: raptor-high-entropy-assignment
	char *secret = "d3a447630194bd4b";

	// ok: raptor-high-entropy-assignment
	char *public = "Hello, world!";

	// ...

	return 0;
}

int main()
{
	printf("Hello, World!");
	return 0;
}

// ruleid: raptor-high-entropy-assignment
static const char *file_scope_secret = "d3a447630194bd4b";
// ok: raptor-high-entropy-assignment
static const char *file_scope_name = "hello world";
#define VERSION_PTEXT " part of OpenSSL 1.0.1f 6 Jan 2014"
// ok: raptor-high-entropy-assignment
static const char version[] = "AES" VERSION_PTEXT;
