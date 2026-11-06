#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* stubs so that the test compiles */
#define strlen raptor_strlen
#define calloc raptor_calloc
unsigned long raptor_strlen();
void *raptor_calloc();
int security_check(char *data);
int printff(const char *fmt, ...);
void die(const char *msg);
char *cp;
enum { OBJ_STR, OBJ_INT, OBJ_BOOL };
struct object {
	int type;
	union {
		char *str;
		int *num;
		int *bool;
	} un;
};
char *alloc_string(void);
int *alloc_int(void);
int *alloc_bool(void);

#define FAIL 0
#define PASS 1

void bad1(char *data)
{
	int result = security_check(data);

	// ruleid: raptor-missing-break-in-switch
	switch (result)
	{
	case FAIL:
		printf("Security check failed!\n");
	case PASS:
		printf("Security check passed.\n");
		break;
	default:
		printf("Unknown error (%d), exiting...\n", result);
		exit(1);
	}
}

void good1(char *data)
{
	int result = security_check(data);

	// ok: raptor-missing-break-in-switch
	switch (result)
	{
	case FAIL:
		printf("Security check failed!\n");
		exit(1);
	case PASS:
		printf("Security check passed.\n");
		break;
	default:
		printf("Unknown error (%d), exiting...\n", result);
		exit(1);
	}
}

struct object *init_object(int type)
{
	struct object *obj;

	if (!(obj = (struct object *)malloc(sizeof(struct object))))
		return NULL;

	obj->type = type;
	// ruleid: raptor-missing-break-in-switch
	switch (type)
	{
	case OBJ_STR:
		obj->un.str = alloc_string();
	case OBJ_INT:
		obj->un.num = alloc_int();
		break;
	case OBJ_BOOL:
		obj->un.bool = alloc_bool();
		break;
	}
	return obj;
}

void printMessage(int month)
{
	// ruleid: raptor-missing-break-in-switch
	switch (month)
	{
	case 1:
		printf("January");
	case 2:
		printf("February");
	case 3:
		printf("March");
	case 4:
		printf("April");
	case 5:
		printff("May");
	case 6:
		printf("June");
	case 7:
		printf("July");
	case 8:
		printf("August");
	case 9:
		printf("September");
	case 10:
		printf("October");
	case 11:
		printf("November");
	case 12:
		printf("December");
	}
	printf(" is a great month");
}

char *escape_string(char *string)
{
	char *output, *dest;
	int escape = 0;

	// there's also an incorrect use of sizeof() here
	if (!(output = dest = (char *)calloc(strlen(string + 1, sizeof(string)))))
		die("calloc: %m");

	while (*string)
	{
		// ruleid: raptor-missing-break-in-switch
		switch (*cp)
		{
		case '\\':
			if (escape)
			{
				*dest++ = '\\';
				escape = 0;
			}
			else
				escape = 1;
			break;
		case '\n':
			*dest++ = ' ';
		default:
			*string = *dest++;
		}
		string++;
	}

	return output;
}

// A generated state machine (llhttp llhttp__internal__run): each case is a
// labelled block ending in __builtin_unreachable() after an inner switch
// whose cases all jump away.
int machine(int st, const unsigned char *p, const unsigned char *endp)
{
	// ok: raptor-missing-break-in-switch
	switch (st) {
	case 0:
	s_closed: {
		if (p == endp)
			return 0;
		switch (*p) {
		case 10:
			p++;
			goto s_closed;
		default:
			p++;
			goto s_open;
		}
		__builtin_unreachable();
	}
	case 1:
	s_open: {
		if (p == endp)
			return 1;
		p++;
		goto s_closed;
	}
	default:
		return -1;
	}
}
// A fall-through marked as intended (llhttp llhttp_finish: `/* FALLTHROUGH */`).
int finish(int mode, int (*cb)(void))
{
	int err;
	// ok: raptor-missing-break-in-switch
	switch (mode) {
	case 2:
		err = cb();
		if (err != 0)
			return err;
	/* FALLTHROUGH */
	case 1:
		return 0;
	default:
		return -1;
	}
}
int finish_attr(int mode, int (*cb)(void))
{
	// ok: raptor-missing-break-in-switch
	switch (mode) {
	case 2:
		cb();
		__attribute__((fallthrough));
	case 1:
		return 0;
	default:
		return -1;
	}
}
// An unmarked one is still reported.
int finish_unmarked(int mode, int (*cb)(void))
{
	// ruleid: raptor-missing-break-in-switch
	switch (mode) {
	case 2:
		cb();
	case 1:
		return 0;
	default:
		return -1;
	}
}

// Both branches of an if/else leave (libuv uv_inet_pton).
int pton(int af, const char *src, char *s)
{
	// ok: raptor-missing-break-in-switch
	switch (af) {
	case 2:
		return src[0];
	case 10: {
		if (s != 0)
			return s[0];
		else
			return src[1];
	}
	default:
		return -1;
	}
}
// A case macro that ends in break, used with a trailing `;` (libuv uv__fs_work:
// `#define X(type, action) case UV_FS_##type: r = action; break;`).
#define XCASE(n, action) \
	case n:          \
		r = action;  \
		break;
int fs_work(int type)
{
	int r = 0;
	// ok: raptor-missing-break-in-switch
	switch (type) {
	XCASE(1, type + 1);
	XCASE(2, type + 2);
	default:
		abort();
	}
	return r;
}

int main()
{
	printf("Hello, World!");
	return 0;
}
