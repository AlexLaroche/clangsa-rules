#include <stdio.h>
#include <string.h>

#define SIZE 256

/* stubs added for the clang port (not part of the original semgrep test) */
extern void *steDispatchTable;
int StartServiceCtrlDispatcher(void *);
void SvcFormatMessage(char *, size_t);
void SvcDebugOut(char *, int);

int test1()
{
	char buf[1024];

	// ruleid: raptor-incorrect-use-of-memset
	memset(buf, sizeof(buf), 0);

	// ruleid: raptor-incorrect-use-of-memset
	memset(buf, sizeof(buf), 'A');

	// ok: raptor-incorrect-use-of-memset
	memset(buf, 0, sizeof(buf));

	return 0;
}

int test2()
{
	char buf[SIZE];

	// ruleid: raptor-incorrect-use-of-memset
	memset(buf, SIZE, 0);

	// ok: raptor-incorrect-use-of-memset
	memset(buf, 0, SIZE);

	return 0;
}

void test3()
{
	// ...
	if (!StartServiceCtrlDispatcher(steDispatchTable))
	{
		char szString[1024];

		// ruleid: raptor-incorrect-use-of-memset
		memset(szString, sizeof(szString), '\0');
		SvcFormatMessage(szString, sizeof(szString));
		SvcDebugOut(szString, 0);
	}
}

int main()
{
	printf("Hello, World!");
	return 0;
}
