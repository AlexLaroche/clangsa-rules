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

// google/brotli common/transform.c: a table of length-prefixed fragments.
// Raw control bytes (other than whitespace) mark binary data, not a secret.
// ok: raptor-high-entropy-assignment
static const char kPrefixSuffix[] = "\1 \2, \10 of the \4 of \2s \1.\5 and \4 in \1\"\4 to \2\">\1\n\2. \1]\5 for \3 a \6 that \1\'\6 with \6 from \4 by \1(\6. The \4 on \4 as \4 is \4ing \2\n\t\1:\3ed ";
// A binary key is mostly unprintable: still reported.
// ruleid: raptor-high-entropy-assignment
static const char kBinaryKey[] = "\x8f\x01\x9a\xc3\x7e\x11\xd4\x02\xee\x5b\x90\x13\x48\xa7\xf1\x06\x3c\xb2\x0d\x99\x61\xfe\x27\x84\x1a\xc9\x55\x0e\xb7\x32\x8d\xe0";
