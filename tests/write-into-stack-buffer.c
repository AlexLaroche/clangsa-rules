#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFSIZE 256

void copy_string1(char *string)
{
	char buf[BUFSIZE];
	static char globuf[BUFSIZE];
	char *ptr;

	// ruleid: raptor-write-into-stack-buffer
	snprintf(buf, BUFSIZE, "%s", string);

	// ok: raptor-write-into-stack-buffer
	snprintf(globuf, BUFSIZE, "%s", string);

	ptr = (char *)malloc(BUFSIZE);

	// ok: raptor-write-into-stack-buffer
	snprintf(ptr, BUFSIZE, "%s", string);
}

void copy_string2(char *string)
{
	char buf[BUFSIZE];
	static char globuf[BUFSIZE];

	// ok: raptor-write-into-stack-buffer
	strlcpy(buf, string, BUFSIZE);

	// ok: raptor-write-into-stack-buffer
	strlcpy(buf, "Hello, world!", BUFSIZE);

	// ok: raptor-write-into-stack-buffer
	strlcpy(globuf, string, BUFSIZE);
}

void copy_string3(char *string)
{
	char buf[BUFSIZE];
	static char globuf[BUFSIZE];

	// ok: raptor-write-into-stack-buffer
	memcpy(buf, string, BUFSIZE);

	// ok: raptor-write-into-stack-buffer
	memcpy(globuf, string, BUFSIZE);
}

void bad(int limit)
{
	char buf[BUFSIZE];

	for (int i = 0; i < limit; i++)
	{
		// this should be caught, but there are too many false positives
		// todoruleid: raptor-write-into-stack-buffer
		buf[i] = 'A';
	}
}

int main()
{
	printf("Hello, World!");
	return 0;
}

/* a parameter declared as an array is a pointer, not a stack buffer */
void param_array(unsigned char ivec[16], const unsigned char *iv)
{
	// ok: raptor-write-into-stack-buffer
	memcpy(ivec, iv, 16);
}

// --- The length cannot exceed the array (SymCrypt triage, 2026-11-09).
#define BLOCK 16
#define MIN(a, b) ((a) < (b) ? (a) : (b))
int fits_buffer(const unsigned char *src, size_t len, unsigned long long off)
{
	unsigned char block[BLOCK], key[64], tmp[32];
	// ok: raptor-write-into-stack-buffer
	memset(block, 0, sizeof(block));            // sizeof(dest)
	// ok: raptor-write-into-stack-buffer
	memcpy(block, src, BLOCK);                   // constant == size
	// ok: raptor-write-into-stack-buffer
	memcpy(key, src, 32);                        // constant < size
	// ok: raptor-write-into-stack-buffer
	memcpy(tmp, src, MIN(sizeof(tmp), len));     // clamped
	// ok: raptor-write-into-stack-buffer
	memcpy(block, src, off & (BLOCK - 1));       // masked
	// ok: raptor-write-into-stack-buffer
	memcpy(block, src, len % BLOCK);             // modulo
	if (len <= sizeof(key)) {
		// ok: raptor-write-into-stack-buffer
		memcpy(key, src, len);                     // enclosing if
	}
	if (len > sizeof(tmp))
		return -1;
	// ok: raptor-write-into-stack-buffer
	memcpy(tmp, src, len);                       // earlier early-exit guard
	return block[0] + key[0] + tmp[0];
}
int may_overflow(const unsigned char *src, size_t len, char *s)
{
	unsigned char block[BLOCK], key[64];
	char name[16];
	// ruleid: raptor-write-into-stack-buffer
	memcpy(block, src, 32);                      // constant > size
	// ruleid: raptor-write-into-stack-buffer
	memcpy(block, src, len);                     // unchecked
	if (len <= 128) {
		// ruleid: raptor-write-into-stack-buffer
		memcpy(key, src, len);                     // bound larger than key
	}
	if (len > sizeof(key))
		len = sizeof(key);                         // clamped to 64, block is 16
	// ruleid: raptor-write-into-stack-buffer
	memcpy(block, src, len);
	// ruleid: raptor-write-into-stack-buffer
	strncat(name, s, sizeof(name));              // strncat bound ignores contents
	return block[0] + key[0] + name[0];
}
