#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#define MEMSIZE 256
#define EXTRA 16
char *buf;
size_t req_size;
char *xfer;
typedef char AStruct;
size_t user_len, user_offset;
struct databuf { char *data; size_t used; size_t allocated_length; };

void alloc_memory()
{
	// ruleid: raptor-unchecked-ret-malloc
	char *ptr = (char *)malloc(MEMSIZE);
}

int alloc_memory_and_check1()
{
	// ok: raptor-unchecked-ret-malloc
	char *ptr = (char *)malloc(MEMSIZE);
	if (ptr == NULL)
		return -1;

	// ...
	return 0;
}

int alloc_memory_and_check2()
{
	char *ptr;

	// ok: raptor-unchecked-ret-malloc
	if ((ptr = (char *)malloc(MEMSIZE)) != NULL)
	{
		// ...
		return 0;
	}
	return -1;
}

int alloc_memory_and_check3()
{
	// ok: raptor-unchecked-ret-malloc
	char *ptr = (char *)malloc(MEMSIZE);
	if (!ptr)
		return -1;

	// ...
	return 0;
}

int alloc_memory_and_check4()
{
	char *ptr;

	// ok: raptor-unchecked-ret-malloc
	if (!(ptr = (char *)malloc(MEMSIZE)))
		return -1;

	// ...
	return 0;
}

void test_func()
{
	// ruleid: raptor-unchecked-ret-malloc
	buf = (char *)malloc(req_size);
	strncpy(buf, xfer, req_size);
}

void test_func2()
{
	// ruleid: raptor-unchecked-ret-malloc
	AStruct *s = (AStruct *)malloc(user_len);
	s[user_offset] = 0xff;
}

int append_data(struct databuf *buf, char *src, size_t len)
{
	size_t new_size = buf->used + len + EXTRA;

	if (new_size < len)
		return -1;

	if (new_size > buf->allocated_length)
	{
		// ruleid: raptor-unchecked-ret-malloc
		buf->data = (char *)realloc(buf->data, new_size);
		buf->allocated_length = new_size;
	}

	memcpy(buf->data + buf->used, src, len);
	buf->used += len;

	return 0;
}

// A helper that tests its argument for NULL checks the allocation passed to
// it (OpenVPN `check_malloc_return(e)`, and its ALLOC_OBJ macro
// `check_malloc_return((dptr) = malloc(sizeof(type)))`).
void out_of_memory(void);
static inline void check_alloc(void *p)
{
	if (!p)
		out_of_memory();
}
void log_ptr(void *p);
#define ALLOC_ONE(d, type) check_alloc((d) = (type *)malloc(sizeof(type)))
char *alloc_checked_by_helper(size_t n)
{
	// ok: raptor-unchecked-ret-malloc
	char *e = (char *)malloc(n);
	check_alloc(e);
	return e;
}
int *alloc_in_helper_argument(void)
{
	int *d;
	// ok: raptor-unchecked-ret-malloc
	ALLOC_ONE(d, int);
	return d;
}
char *alloc_passed_to_other(size_t n)
{
	// ruleid: raptor-unchecked-ret-malloc
	char *e = (char *)malloc(n);
	log_ptr(e);
	return e;
}

int main()
{
	printf("Hello, World!");
	return 0;
}
