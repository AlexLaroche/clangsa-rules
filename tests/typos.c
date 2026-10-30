#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

/* stubs so that the test compiles */
void die(const char *msg);
int get_security_flags(char *username);
#define FLAG_AUTHENTICATED 1
#define LOGIN_OK 0
#define LOGIN_FAILED 1
int get_string(char *s);
int check_for_overflow(char *s);
int copy_string(char *dst, char *src);
unsigned long frag_len;
struct ssl { void *init_buf; int init_num; } *s;
int BUF_MEM_grow_clean(void *buf, int len);
#define DTLS1_HM_HEADER_LENGTH 12
void SSLerr(int f, int r);
#define SSL_F_DTLS1_GET_MESSAGE_FRAGMENT 1
#define ERR_R_BUF_LIB 2
void processChar(char c);
void movingToNewInput(void);
int nowtok, tok_mb_cur_max, tok_mb_cur_min;
struct { int mb_cur_max; } *result;
void lr_error(void *f, const char *fmt, ...);
void *cmfile;
const char *_(const char *s);
int e, d, ax, ay, x1, y1, x2, y2, ddx[10], ddy[10];
int borg_extract_dir(int y1, int x1, int y2, int x2);
int borg_cave_floor_bold(int y, int x);
#define MNAMELEN 90
struct { char f_mntfromname[MNAMELEN]; int f_type; } *mp;
#define MOUNT_TYPE_NFS 1
#define MOUNT_TYPE_NFS3 2
void xstrlcpy(char *dst, const char *src, unsigned long size);
typedef struct fsa_node_addr fsa_node_addr;
char *nodes_arg;
void fsa_error(int level, const char *fmt, ...);
#define LOG_ERR 3
void do_someting(void);
void do_something(void);
char szbuf1[64];
void assert(const char *msg, int cond);
struct { void *rx; } *state;
typedef struct window WINDOW;
#define OK 0

void bad1()
{
	char *src, *dst;
	int left;

	while (*src && left)
	{
		*dst++ = *src++;
		// ruleid: raptor-typos
		if (left = 0)
		{
			die("badlen");
		}
		left--;
	}
}

void good1(char *path, char *dir, char *obj)
{
	char *last;

	// ok: raptor-typos
	if ((last = strrchr(path, '/')) != NULL)
	{
		strcpy(obj, last + 1);
		if (last == path)
		{
			strcpy(dir, "/");
		}
		else
		{
			*last = '\0';
			strcpy(dir, path);
			*last = '/';
		}
	}
	else
	{
		dir[0] = dir[0] = '\0';
	}
}

int bad2(char *username)
{
	int f;
	f = get_security_flags(username);

	// ruleid: raptor-typos
	if (f = FLAG_AUTHENTICATED)
	{
		return LOGIN_OK;
	}
	return LOGIN_FAILED;
}

void bad3(char *src, char *dst)
{
	// ruleid: raptor-typos
	if (get_string(src) &&
		check_for_overflow(src) & copy_string(dst, src))
	{
		printf("string safely copied\n");
	}
}

void bad4(char *src, int len)
{
	char dst[256];

	// ruleid: raptor-typos
	if (len > 0 && len <= sizeof(dst))
		;
	memcpy(dst, src, len);
}

void bad5(char *src, char *dst)
{
	int i;
	// ruleid: raptor-typos
	for (i == 5; src[i] && i < 10; i++)
	{
		dst[i - 5] = src[i];
	}
}

void bad6(char *userinput)
{
	// ruleid: raptor-typos
	char buf[040];

	// ok: raptor-typos
	char buf2[0x40];

	snprintf(buf, 40, "%s", userinput);
}

void bad7()
{
	// ruleid: raptor-typos
	if (frag_len &
		!BUF_MEM_grow_clean(s->init_buf, (int)frag_len +
											 DTLS1_HM_HEADER_LENGTH + s->init_num))
	{
		SSLerr(SSL_F_DTLS1_GET_MESSAGE_FRAGMENT, ERR_R_BUF_LIB);
		goto err;
	}
err:;
}

void bad8(int j)
{
	int i = 10;

	// ruleid: raptor-typos
	i = +j;
}

int isValid(int value)
{
	// ruleid: raptor-typos
	if (value = 100)
	{
		printf("Value is valid\n");
		return (1);
	}

	printf("Value is not valid\n");
	return (0);
}

void processString(char *str)
{
	int i;

	for (i = 0; i < strlen(str); i++)
	{
		if (isalnum(str[i]))
		{
			processChar(str[i]);
		}
		// ruleid: raptor-typos
		else if (str[i] = ':')
		{
			movingToNewInput();
		}
	}
}

#define SIZE 50
int *tos, *p1, stack[SIZE];

void push(int i)
{
	p1++;
	if (p1 == (tos + SIZE))
	{
		printf("Print stack overflow error message and exit\n");
	}
	// ruleid: raptor-typos
	*p1 == i;
}

int pop(void)
{
	if (p1 == tos)
	{
		printf("Print stack underflow error message and exit\n");
	}
	p1--;
	return *(p1 + 1);
}

void test1()
{
	// ruleid: raptor-typos
	if ((nowtok == tok_mb_cur_max && result->mb_cur_max != 0) || (nowtok == tok_mb_cur_max && result->mb_cur_max != 0))
		lr_error(cmfile, _("duplicate definition of <%s>"), nowtok == tok_mb_cur_min ? "mb_cur_min" : "mb_cur_max");
}

int test2()
{
	e = borg_extract_dir(y1, x1, y2, x2);

	// ruleid: raptor-typos
	if ((ay <= 1) && (ay <= 1))
		return (e);

	if (ay > ax)
	{
		d = (y1 < y2) ? 2 : 8;
		if (borg_cave_floor_bold(y1 + ddy[d], x1 + ddx[d]))
			return (d);
	}
}

void test3()
{
	char *at;
	char mntfrombuf[MNAMELEN];
	char *mntfromptr;

	mntfromptr = mp->f_mntfromname;

	switch (mp->f_type)
	{
	case MOUNT_TYPE_NFS:
	case MOUNT_TYPE_NFS3:
		at = strchr(mp->f_mntfromname, '@');
		// ruleid: raptor-typos
		if (at != '\0')
		{
			xstrlcpy(mntfrombuf, (at + 1), sizeof(mntfrombuf));
		}
	}
}

int test4()
{
	fsa_node_addr *prev_node = NULL;
	char *cur = nodes_arg; /* point to start of string */

	for (int i = 0; i < strlen(nodes_arg); i++)
	{
		if (nodes_arg[i] != ',' && (nodes_arg[i] < '0' || nodes_arg[i] > '9'))
		{
			fsa_error(LOG_ERR, "Invalid nodes argument: %s\n", nodes_arg);
			return 1;
		}
	}
	// ruleid: raptor-typos
	while (cur != NULL && cur != '\0')
	{
		int node_num = (int)strtol(cur, (char **)NULL, 10);
		if (node_num == 0 && errno != 0)
		{
			do_someting();
		}
	}
}

void test5()
{
	// ruleid: raptor-typos
	if (strcpy(szbuf1, "Manager") == 0)
	{
		do_something();
	}
}

void test6()
{
	// ...

	// ok: raptor-typos
	assert("in this state, the rx chain should be empty", state->rx == NULL);
}

int wgetnstr(WINDOW *win, char *str, int n)
{
	char *_str;
	int c;

	if (n == 0)
	{
		// ruleid: raptor-typos
		str = '\0';
		return OK;
	}
	_str = str;
}

int main(int argc, char *argv[])
{
	tos = stack;
	p1 = stack;
	// ...
	return 0;
}

#define reject(x, usage) (((x) & 1) && !((x) & (usage)))

int typos_macro_args(int x, unsigned char *t)
{
	// ruleid: raptor-typos
	if (reject(x, 2|4))
		return 0;
	// ok: raptor-typos
	if (((t[1] ^ t[4]) & (t[2] ^ t[5]) & (t[3] ^ t[6])) != 0xff)
		return 0;
	return 1;
}

void *typos_chained_assignment(void **a, void **b)
{
	// ruleid: raptor-typos
	if ((*a = *b = malloc(1)) == NULL)
		return NULL;
	return *a;
}
