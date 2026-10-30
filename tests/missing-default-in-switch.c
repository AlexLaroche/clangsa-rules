// Marco Ivaldi <raptor@0xdeadbeef.info>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* stubs so that the test compiles */
int security_check(char *data);
typedef struct { int id; } *Pkt;
void initAuth(Pkt p);
void initReset(Pkt p);
void initDisconnect(Pkt p);
void processPacket(Pkt p);
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
int foo(void);
int x, y;

#define FAIL 0
#define PASS 1

void bad1(char *data)
{
	int result = security_check(data);

	// ruleid: raptor-missing-default-in-switch
	switch (result)
	{
	case FAIL:
		printf("Security check failed!\n");
		exit(1);
		break;
	case PASS:
		printf("Security check passed.\n");
		break;
	}
}

void good1(char *data)
{
	int result = security_check(data);

	// ok: raptor-missing-default-in-switch
	switch (result)
	{
	case FAIL:
		printf("Security check failed!\n");
		exit(1);
		break;
	case PASS:
		printf("Security check passed.\n");
		break;
	default:
		printf("Unknown error (%d), exiting...\n", result);
		exit(1);
	}
}

void bad2(Pkt packet)
{
	// ruleid: raptor-missing-default-in-switch
	switch (packet->id)
	{
	case 1:
		initAuth(packet);
		break;
	case 2:
		initReset(packet);
		break;
	case 3:
		initDisconnect(packet);
		break;
	}

	processPacket(packet);
}

struct object *init_object(int type)
{
	struct object *obj;

	if (!(obj = (struct object *)malloc(sizeof(struct object))))
		return NULL;

	obj->type = type;
	// ruleid: raptor-missing-default-in-switch
	switch (type)
	{
	case OBJ_STR:
		obj->un.str = alloc_string();
		break;
	case OBJ_INT:
		obj->un.num = alloc_int();
		break;
	case OBJ_BOOL:
		obj->un.bool = alloc_bool();
		break;
	}
	return obj;
}

void test()
{
	// ruleid: raptor-missing-default-in-switch
	switch (foo() + x + y)
	{
	case 1:
		break;
	case 2:
		break;
	}

	// ok: raptor-missing-default-in-switch
	switch (foo() + x + y)
	{
	case 1:
		break;
	default:
		break;
	case 2:
		break;
	}

	// ok: raptor-missing-default-in-switch
	switch (foo() + x + y)
	{
	case 1:
		break;
	case 2:
		break;
	default:
		break;
	}
}

int main()
{
	printf("Hello, World!");
	return 0;
}
