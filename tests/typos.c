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
	if (reject(x, t[0]|t[1]))
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

// Flag tests: one operand is a constant mask, the only meaning of `&` here
// (libssh2 `if(attrs->flags & LIBSSH2_SFTP_ATTR_SIZE)`, OpenSSL
// `if (buflen & 3)`, GStreamer `if (depth & 0x80)`).
#define ATTR_SIZE 0x1
#define ATTR_UID 0x2
enum { MODE_A = 4, MODE_B = 8 };
int typos_flag_tests(unsigned flags, unsigned len, int a, int b)
{
	// ok: raptor-typos
	if (flags & ATTR_SIZE)
		return 1;
	// ok: raptor-typos
	if (!(flags & (ATTR_SIZE | ATTR_UID)))
		return 2;
	// ok: raptor-typos
	if (len & 3)
		return 3;
	// ok: raptor-typos
	if (a == 1 && (flags & MODE_B))
		return 4;
	// ruleid: raptor-typos
	if (flags | MODE_A) // always true
		return 5;
	// ruleid: raptor-typos
	if (a & b)
		return 6;
	return 0;
}

// A bitwise operator inside a call argument builds that argument (a mask
// passed to a lookup); it is not the condition's operator (WireGuard
// `if (!wg_index_hashtable_lookup(t, HANDSHAKE | KEYPAIR, ...))`).
#define TYPE_HANDSHAKE 1
#define TYPE_KEYPAIR 2
int lookup_entry(int table, unsigned mask, unsigned index);
int typos_mask_argument(int table, unsigned index, unsigned a, unsigned b)
{
	// ok: raptor-typos
	if (!lookup_entry(table, TYPE_HANDSHAKE | TYPE_KEYPAIR, index))
		return 1;
	// ok: raptor-typos
	if (lookup_entry(table, a & b, index) > 0)
		return 2;
	// ruleid: raptor-typos
	if (lookup_entry(table, a, index) & b)
		return 3;
	return 0;
}

// Differently spelled operands that expand to the same value are
// configuration checks, not copy-paste typos (kernel
// `IS_ENABLED(CONFIG_A) || IS_ENABLED(CONFIG_B)`,
// `static_assert(AES_BLOCK_SIZE == AES_KEYSIZE_128)`).
#define CONFIG_A 0
#define CONFIG_B 0
#define BLOCK_SIZE 16
#define KEYSIZE_128 16
#define CHECK(e) (e)
#define ENABLED(o) (0 || (o))
int typos_same_value_macros(int x, int y)
{
	// ok: raptor-typos
	if (CONFIG_A || CONFIG_B)
		return 1;
	// ok: raptor-typos
	if (BLOCK_SIZE == KEYSIZE_128)
		return 2;
	// ok: raptor-typos
	if (CHECK(BLOCK_SIZE == KEYSIZE_128))
		return 5;
	// ok: raptor-typos
	if (ENABLED(CONFIG_A) || ENABLED(CONFIG_B))
		return 6;
	// ruleid: raptor-typos
	if (CONFIG_A || CONFIG_A)
		return 3;
	// ruleid: raptor-typos
	if (x == y && x == y)
		return 4;
	return 0;
}

// An assignment in its own parentheses is the conventional way to say it is
// meant (clang's -Wparentheses): `if ((he = lookup(k)))`,
// `if (!(bio = BIO_new(...)))`, OpenVPN `ASSERT(mac = buf_prepend(...))`.
void *lookup_item(int key);
void fail_check(void);
#define CHECK_ALLOC(x) do { if (!(x)) fail_check(); } while (0)
int typos_parenthesized_assignment(int key, void **out)
{
	void *he;
	// ok: raptor-typos
	if ((he = lookup_item(key)))
		return 1;
	// ok: raptor-typos
	if (!(he = lookup_item(key + 1)))
		return 2;
	// ok: raptor-typos
	CHECK_ALLOC(*out = lookup_item(key + 2));
	// ruleid: raptor-typos
	if (he = lookup_item(key + 3))
		return 3;
	return 0;
}

// Flags handed to a macro that tests them with its own operator
// (OpenVPN `msg(M_WARN | M_ERRNO, ...)` expanding to
// `if ((flags) & M_FATAL) _exit(1);`).
#define M_FATAL 0x10
#define M_WARN 0x20
#define M_ERRNO 0x40
void do_exit(int code);
#define EXIT_IF_FATAL(flags) do { if ((flags) & M_FATAL) do_exit(1); } while (0)
void typos_flags_to_macro(unsigned level, unsigned a)
{
	// ok: raptor-typos
	EXIT_IF_FATAL(M_WARN | M_ERRNO);
	// ruleid: raptor-typos
	if (level | a)
		do_exit(2);
}

// More flag idioms (OpenVPN): a masked value compared on either side of a
// comparison, an `|` chain or a ?: branch building an argument, and a test
// of one bit built by a shift.
#define OPT_A 1
#define OPT_B 2
#define OPT_C 4
#define BIT(i) (1u << (i))
int check_perm(unsigned mask);
#define VERIFY(mask) do { if (!check_perm(mask)) return -1; } while (0)
int typos_more_flag_idioms(unsigned a, unsigned b, unsigned subnet, unsigned flags,
			   unsigned verbosity, int optional, unsigned type_mask, int i)
{
	// ok: raptor-typos
	if ((a & subnet) != (b & subnet))
		return 1;
	// ok: raptor-typos
	if (verbosity >= (flags & OPT_C))
		return 2;
	// ok: raptor-typos
	if (!check_perm(OPT_A | OPT_B | OPT_C))
		return 3;
	// ok: raptor-typos
	VERIFY(OPT_A | OPT_B | OPT_C);
	// ok: raptor-typos
	if (check_perm(optional ? OPT_A | OPT_B : OPT_C))
		return 4;
	// ok: raptor-typos
	if (type_mask & (1u << i))
		return 5;
	// ok: raptor-typos
	if (BIT(i) & type_mask)
		return 6;
	// ruleid: raptor-typos
	if (a & subnet)
		return 7;
	return 0;
}

// OpenSSH idioms: a scan loop whose `;` sits on its own line, an empty if
// body marked by a comment, a literal sign, the same call made twice on
// purpose, a mask built inside a compared &, and an assignment handed to a
// call.
int skip_field(const char **p);
int lookup_uid(int uid);
int getid(void);
int typos_openssh_idioms(const char *line, const char *place, unsigned revents,
			 unsigned mask, int n)
{
	const char *cp;
	int r, sign, uid, i;
	// ok: raptor-typos
	for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
		;
	// ruleid: raptor-typos
	for (i = 0; i < n; i++);
	// ok: raptor-typos
	if (*place)			/* no space */
		/* NOTHING */;
	// ok: raptor-typos
	sign = +1;
	// ok: raptor-typos
	if ((r = skip_field(&cp)) != 0 || (r = skip_field(&cp)) != 0)
		return r;
	// ok: raptor-typos
	if ((revents & (mask | 0x10 | 0x8)) != 0)
		return 1;
	// ok: raptor-typos
	if (lookup_uid(uid = getid()) == 0)
		return 2;
	return sign + i;
}

// Constant-time combinations of predicates (0/1 or 0/all-ones masks): `|`
// and `&` give the same truth value as `||` and `&&`, without branching
// (SymCrypt dsa.c, ec_short_weierstrass.c, fdef_mod.c).
unsigned ModElementIsZero(const int *e);
unsigned IntIsEqualUint32(const int *e, unsigned v);
unsigned IntGetValueLsbits32(const int *e);
int isalnum_bits(int c);
int isdigit_bits(int c);
int ct_predicates(const int *r, const int *s, const int *a, const int *b)
{
	// ok: raptor-typos
	if (!(ModElementIsZero(r) | ModElementIsZero(s)))
		return 1;
	// ok: raptor-typos
	if (ModElementIsZero(r) & ModElementIsZero(s))
		return 2;
	// ok: raptor-typos
	if (IntIsEqualUint32(a, 0) | IntIsEqualUint32(b, 0) |
	    (((IntGetValueLsbits32(a) | IntGetValueLsbits32(b)) & 1) ^ 1))
		return 3;
	// ruleid: raptor-typos
	if (IntGetValueLsbits32(a) & IntGetValueLsbits32(b))    // 2 & 1 == 0
		return 4;
	// ruleid: raptor-typos
	if (strcmp((const char *)a, "x") & strcmp((const char *)b, "y"))
		return 5;
	// ruleid: raptor-typos
	if (isalnum_bits(*a) & isdigit_bits(*b))  // ctype-like: arbitrary bits
		return 6;
	return 0;
}

// The complement of a constant mask (SymCrypt ec_mul.c: reject unknown flags).
#define FLAG_A 1
#define FLAG_B 2
int only_known_flags(unsigned flags)
{
	// ok: raptor-typos
	if ((flags & ~(FLAG_A | FLAG_B)) != 0)
		return -1;
	return 0;
}
