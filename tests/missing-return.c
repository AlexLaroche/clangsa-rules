#include <stdio.h>

// ok: raptor-missing-return
int bad();

// ok: raptor-missing-return
int baddie(int foo);

// ruleid: raptor-missing-return
int bad1(void)
{
	printf("Hello, World!");
}

// ok: raptor-missing-return
void good1(void)
{
	printf("Hello, World!");
}

// ok: raptor-missing-return
int main(int argc, char **argv)
{
	printf("Hello, World!");
	return 0;
}

// Every path ends in a noreturn call (FreeRADIUS stubs ending in abort(),
// _fr_assert_fail ending in fr_fault()).
__attribute__((noreturn)) void fr_fault(int);
void abort(void) __attribute__((noreturn));
// ok: raptor-missing-return
int backtrace_stub(void *cookie)
{
	(void)cookie;
	abort();
}

// ok: raptor-missing-return
int assert_fail(const char *msg)
{
	if (msg)
		fr_fault(1);
	else
		fr_fault(2);
}

// ruleid: raptor-missing-return
int not_always(const char *msg)
{
	if (msg)
		fr_fault(1);
}
