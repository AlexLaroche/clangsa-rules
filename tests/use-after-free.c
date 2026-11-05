#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEMSIZE 256
#define BUFSIZER1 128
#define BUFSIZER2 256

void alloc_and_free1()
{
	int err = 1, bailout = 0;
	char *ptr = (char *)malloc(MEMSIZE);

	// this should be caught but it isn't, due to a documented limitation in semgrep
	// https://semgrep.dev/docs/writing-rules/pattern-syntax/#ellipses-and-statement-blocks
	// (semgrep: todoruleid; caught here by the CFG-based analysis, so the
	// annotation was moved to the use and promoted to ruleid)
	if (err)
	{
		bailout = 1;
		free(ptr);
	}
	if (bailout)
		// ruleid: raptor-use-after-free
		fprintf(stderr, "error: %p\n", ptr);

	free(ptr);
	// ruleid: raptor-use-after-free
	fprintf(stderr, "error: %p\n", ptr);
}

void alloc_and_free2()
{
	char *ptr = (char *)malloc(MEMSIZE);

	free(ptr);
	ptr = (char *)malloc(MEMSIZE);
	// ok: raptor-use-after-free
	fprintf(stderr, "error: %p\n", ptr);
}

void uaf(int argc, char **argv)
{
	char *buf1R1;
	char *buf2R1;
	char *buf2R2;
	char *buf3R2;
	buf1R1 = (char *)malloc(BUFSIZER1);
	buf2R1 = (char *)malloc(BUFSIZER1);
	free(buf2R1);
	buf2R2 = (char *)malloc(BUFSIZER2);
	buf3R2 = (char *)malloc(BUFSIZER2);
	// ruleid: raptor-use-after-free
	strncpy(buf2R1, argv[1], BUFSIZER1 - 1);
	free(buf1R1);
	free(buf2R2);
	free(buf3R2);
}

// https://docs.microsoft.com/en-us/cpp/sanitizers/error-heap-use-after-free
int heap_use_after_free()
{
	char *x = (char *)malloc(10 * sizeof(char));
	free(x);

	// ...

	// ruleid: raptor-use-after-free
	return x[5];
}

char test()
{
	char *ptr = (char *)malloc(10 * sizeof(char));
	free(ptr);

	// ruleid: raptor-use-after-free
	return *ptr;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct name
{
	char *myname;
	void (*func)(char *str);
} NAME;

void other_func(char *ignored) {}
void refreencode(char *ignored) {}

int bad_code1()
{
	NAME *var;
	char buf[10];
	var = (NAME *)malloc(sizeof(struct name));
	free(var);
	// ruleid: raptor-use-after-free
	strcpy(buf, (char *)var);
	// ruleid: raptor-use-after-free
	other_func((char *)&(*var));
	// ruleid: raptor-use-after-free
	other_func((char *)&var[0]);
	// ruleid: raptor-use-after-free
	var->func(var->myname);
	return 0;
}

int bad_code2()
{
	NAME *var;
	char buf[10];
	var = (NAME *)malloc(sizeof(struct name));
	free(var);
	// ruleid: raptor-use-after-free
	strcpy(buf, (char *)&*var);
	// ruleid: raptor-use-after-free
	other_func((char *)var);
	// ruleid: raptor-use-after-free
	other_func((char *)var->myname);
	return 0;
}

int okay_code1()
{
	NAME *var;
	var = (NAME *)malloc(sizeof(struct name));
	free(var);
	var = NULL;
	// This will segmentation fault
	// ok: raptor-use-after-free
	other_func((char *)var);
	other_func((char *)var->myname);
	other_func((char *)&*var);
	return 0;
}

int okay_code2()
{
	NAME *var;
	var = (NAME *)malloc(sizeof(struct name));
	free(var);
	var = NULL;
	var = (NAME *)malloc(sizeof(struct name));
	// ok: raptor-use-after-free
	other_func((char *)var);
	other_func((char *)var->myname);
	other_func((char *)&*var);
	return 0;
}

#include <stdio.h>
#include <stdlib.h>

typedef struct name2
{
	char *myname;
	void (*func)(char *str);
} NAME2;

void other_func_2(char *ignored) {}

int bad_code1_2()
{
	NAME2 *var;
	var = (NAME2 *)malloc(sizeof(struct name2));
	free(var);
	// ruleid: raptor-use-after-free
	var->func("use after free");
	return 0;
}

int okay_code1_2()
{
	NAME2 *var;
	var = (NAME2 *)malloc(sizeof(struct name2));
	free(var);
	var = NULL;
	// This will segmentation fault
	// ok: raptor-use-after-free
	var->func("use after free");
	return 0;
}

int bad_code2_2()
{
	NAME2 *var;
	var = (NAME2 *)malloc(sizeof(struct name2));
	free(var);
	// ruleid: raptor-use-after-free
	other_func_2(var->myname);
	return 0;
}

int okay_code2_2()
{
	NAME2 *var;
	var = (NAME2 *)malloc(sizeof(struct name2));
	free(var);
	var = NULL;
	// This will segmentation fault
	// ok: raptor-use-after-free
	other_func_2(var->myname);
	return 0;
}

struct NAME
{
	char first_name[32];
	int auth;
} s_auth;

int bad_code3()
{
	struct NAME *var;
	var = malloc(sizeof(s_auth));
	free(var);
	// ruleid: raptor-use-after-free
	if (var->auth)
	{
		printf("you have logged in already");
	}
	else
	{
		printf("you do not have the permision to log in.");
	}
	return 0;
}

int ok_code3()
{
	struct NAME *var;
	var = malloc(sizeof(s_auth));
	free(var);
	var = NULL;
	// ok: raptor-use-after-free
	if (var->auth)
	{
		printf("you have logged in already");
	}
	else
	{
		printf("you do not have the permision to log in.");
	}
	return 0;
}

struct lv
{
	int length;
	char *value;
} lv;

struct lv2
{
	int length;
	struct lv *lv;
} lv2;

int bad_code4()
{
	int initial = 1000;
	struct lv *lv = malloc(sizeof(*lv));
	lv->length = initial;
	lv->value = malloc(initial);
	free(lv);
	// ruleid: raptor-use-after-free
	free(lv->value);
	return 0;
}

int ok_code4()
{
	int initial = 1000;
	struct lv *lv = malloc(sizeof(*lv));
	lv->length = initial;
	lv->value = malloc(initial);
	// ok: raptor-use-after-free
	free(lv->value);
	// ok: raptor-use-after-free
	free(lv);
	return 0;
}

int bad_code5()
{
	int initial = 1000;
	struct lv *lv = malloc(sizeof(*lv));
	lv->length = initial;
	lv->value = malloc(initial);

	struct lv2 *lv2 = malloc(sizeof(*lv2));
	lv2->length = initial;
	lv2->lv = lv;
	// ok: raptor-use-after-free
	free(lv2->lv);
	// ruleid: raptor-use-after-free
	free(lv2->lv->value);
	// ok: raptor-use-after-free
	free(lv2);
	return 0;
}

int ok_code5()
{
	int initial = 1000;
	struct lv *lv = malloc(sizeof(*lv));
	lv->length = initial;
	lv->value = malloc(initial);

	struct lv2 *lv2 = malloc(sizeof(*lv2));
	lv2->length = initial;
	lv2->lv = lv;
	// ok: raptor-use-after-free
	free(lv2->lv->value);
	// ok: raptor-use-after-free
	free(lv2->lv);
	// ok: raptor-use-after-free
	free(lv2);
	return 0;
}

int bad_code6()
{
	NAME *var;
	var = (NAME *)malloc(sizeof(struct name));
	free(var);
	// ruleid: raptor-use-after-free
	(*var).func("use after free");
	return 0;
}

int ok_code6()
{
	NAME *var;
	var = (NAME *)malloc(sizeof(struct name));
	free(var);
	var = (NAME *)malloc(sizeof(struct name));
	// ok: raptor-use-after-free
	(*var).func("use after free");
	return 0;
}

int bad_code7()
{
	char *var;
	char buf[10];
	var = (char *)malloc(100);
	free(var);
	// ruleid: raptor-use-after-free
	char buf0 = var[0];
	// ruleid: raptor-use-after-free
	strcpy(buf, var);
	return 0;
}

// sizeof does not read its operand (libarchive cab: `free(ds->pos_tbl);
// ds->pos_tbl = malloc(sizeof(ds->pos_tbl[0]) * w_slot);`).
struct tbl { int *pos_tbl; };
int regrow(struct tbl *ds, int n)
{
	free(ds->pos_tbl);
	// ok: raptor-use-after-free
	ds->pos_tbl = malloc(sizeof(ds->pos_tbl[0]) * n);
	return ds->pos_tbl != NULL;
}

// An out-parameter refills the pointer (libssh2 test fixture:
// `free(*out); ret = run_command(out, ...); strchr(*out, '\r')`).
int run_command(char **out, const char *cmd);
int rerun(char **out)
{
	free(*out);
	int ret = run_command(out, "port");
	// ok: raptor-use-after-free
	char *hit = strchr(*out, '\r');
	return ret || hit;
}

// A function that always exits ends the path (libtiff tiffdump:
// `free(visited_diroff); Fatal("Cycle detected");`).
static void fatal(const char *msg);
void check_cycle(long *visited, int n, long off)
{
	for (int j = 0; j < n; j++)
		if (visited[j] == off) {
			free(visited);
			fatal("cycle");
		}
	// ok: raptor-use-after-free
	visited[0] = off;
}
static void fatal(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

// Passing &p lets the call set p again; nothing is read through p (bsdtar
// apply_substitution(..., &subst_name, ...)).
int substitute(const char *in, char **out);
int resubstitute(const char *a, const char *b)
{
	char *subst;
	if (substitute(a, &subst) == 1)
		free(subst);
	// ok: raptor-use-after-free
	return substitute(b, &subst);
}

// A second release is DoubleFree's report, not a use (libssh2 SSH2_FREE).
typedef struct session {
	void (*free)(void *, void **);
	void *abstract;
} SESSION;
#define SSH2_FREE(s, p) (s)->free((p), &(s)->abstract)
typedef struct ocsp_req OCSP_REQUEST;
void OCSP_REQUEST_free(OCSP_REQUEST *req);
void release_again(SESSION *session, unsigned char *data, OCSP_REQUEST *req)
{
	SSH2_FREE(session, data);
	// ok: raptor-use-after-free
	SSH2_FREE(session, data);
	OCSP_REQUEST_free(req);
	// ok: raptor-use-after-free
	OCSP_REQUEST_free(req);
}

// A *_free defined here that releases only what the object holds (curl
// Curl_bufref_free: frees br->ptr, then the fields are set again).
struct bufref {
	void *ptr;
	size_t len;
};
void bufref_free(struct bufref *br)
{
	free(br->ptr);
	br->ptr = NULL;
}
void bufref_set(struct bufref *br, void *ptr, size_t len)
{
	bufref_free(br);
	// ok: raptor-use-after-free
	br->ptr = ptr;
	br->len = len;
}

// The release is an argument of another call (libarchive's tests:
// `assertEqualInt(ARCHIVE_OK, archive_read_free(a));`).
struct archive;
int archive_read_free(struct archive *a);
int assert_equal_int(int a, int b);
void close_archive(struct archive *a)
{
	// ok: raptor-use-after-free
	assert_equal_int(0, archive_read_free(a));
}

// A destructor of what the object holds, with the object as a second
// argument (curl `Curl_req_free(&data->req, data);`), or one whose body is
// not here (libarchive `__archive_write_filters_free(a);`).
struct req {
	char *buf;
};
struct easy {
	struct req req;
	int magic;
};
void Curl_req_free(struct req *req, struct easy *data);
void __archive_write_filters_free(struct archive *a);
int archive_write_add_filter_bzip2(struct archive *a);
int close_easy(struct easy *data, struct archive *a)
{
	Curl_req_free(&data->req, data);
	// ok: raptor-use-after-free
	data->magic = 0;
	__archive_write_filters_free(a);
	// ok: raptor-use-after-free
	return archive_write_add_filter_bzip2(a);
}

// A non-blocking release retried in a loop (libssh2 BLOCK_ADJUST:
// `do { rc = ssh2_channel_free(channel); if (rc != EAGAIN) break;
// wait(channel->session); } while (1);`).
struct sess;
typedef struct channel {
	struct sess *session;
	char *buf;
} CHANNEL;
static int channel_free(CHANNEL *channel)
{
	if (channel->buf)
		return -37;
	free(channel);
	return 0;
}
void wait_session(struct sess *s);
int channel_close(CHANNEL *channel)
{
	int rc;
	do {
		rc = channel_free(channel);
		if (rc != -37)
			break;
		// ok: raptor-use-after-free
		wait_session(channel->session);
	} while (1);
	return rc;
}

// A per-type destructor reached through the object itself
// (BIND 9 `obj->type->rep->free(obj)`) releases what the object holds;
// the object is put back afterwards.
struct cfg_obj;
typedef struct {
	void (*free)(struct cfg_obj *obj);
} Rep;
typedef struct {
	Rep *rep;
} CfgType;
struct cfg_obj {
	CfgType *type;
	unsigned magic;
};
void mem_put(void *p, unsigned long size);
void destroy_cfgobj(struct cfg_obj *obj)
{
	obj->type->rep->free(obj);
	// ok: raptor-use-after-free
	obj->magic = 0;
	mem_put(obj, sizeof(*obj));
}

int main()
{
	printf("Hello, World!");
	return 0;
}
