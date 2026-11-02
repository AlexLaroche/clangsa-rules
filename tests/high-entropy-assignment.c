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

// Regression test for a crash found on dotnet/runtime (EventPipe): a
// block-scope extern redeclaration of an initialized variable matches
// hasInitializer() (which looks at any redeclaration), but has no
// initializer of its own (getInit() is NULL).
const char *redeclared_secret = "x";
int uses_block_scope_extern(void)
{
	// ok: raptor-high-entropy-assignment
	extern const char *redeclared_secret;
	return redeclared_secret != 0;
}
