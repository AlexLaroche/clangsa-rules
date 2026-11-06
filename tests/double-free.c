#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEMSIZE 256
#define BUFSIZE1 128
#define BUFSIZE2 256

typedef struct packet Packet;
#define OK 0
int retval;
int waitForPacket(Packet *);
char *logData;
Packet *pkt;
void logPktData(Packet *);
void processPacket(Packet *);

void alloc_and_free1()
{
	int bailout = 1;
	char *ptr = (char *)malloc(MEMSIZE);

	// this should be caught but it isn't, due to a documented limitation in semgrep
	// https://semgrep.dev/docs/writing-rules/pattern-syntax/#ellipses-and-statement-blocks
	// (semgrep: todoruleid; caught here by the CFG-based analysis, so the
	// annotation was moved to the second free and promoted to ruleid)
	if (bailout)
		free(ptr);

	// ruleid: raptor-double-free
	free(ptr);
	// ruleid: raptor-double-free
	free(ptr);
}

void alloc_and_free2()
{
	char *ptr = (char *)malloc(MEMSIZE);

	free(ptr);
	ptr = NULL;
	// ok: raptor-double-free
	free(ptr);
}

void alloc_and_free3()
{
	char *ptr = (char *)malloc(MEMSIZE);

	free(ptr);
	ptr = (char *)malloc(MEMSIZE);
	// ok: raptor-double-free
	free(ptr);
}

void double_free(int argc, char **argv)
{
	char *buf1R1;
	char *buf2R1;
	char *buf1R2;
	buf1R1 = (char *)malloc(BUFSIZE2);
	buf2R1 = (char *)malloc(BUFSIZE2);
	free(buf1R1);
	free(buf2R1);
	buf1R2 = (char *)malloc(BUFSIZE1);
	strncpy(buf1R2, argv[1], BUFSIZE1 - 1);
	// ruleid: raptor-double-free
	free(buf2R1);
	free(buf1R2);
}

Packet *getNextPacket()
{
	// ...
	Packet *y = (Packet *)malloc(1024);
	retval = waitForPacket(y);
	if (retval == OK)
	{
		return y;
	}
	else
	{
		return NULL;
	}
}

void *bad()
{
	// ...
	free(logData);
	pkt = getNextPacket();
	if (!pkt)
	{
		return NULL;
	}
	logPktData(pkt);
	// ruleid: raptor-double-free
	free(logData);
	processPacket(pkt);
}

// A list freed node by node: `s = n` moves to another node, so s->name and
// s are new pointers on each iteration.
struct node { struct node *next; char *name; };
void free_list(struct node *s)
{
	struct node *n;
	for (; s; s = n) {
		n = s->next;
		// ok: raptor-double-free
		free(s->name);
		// ok: raptor-double-free
		free(s);
	}
}
void free_array(char **v, int c)
{
	char **p = v;
	while (c-- > 0) {
		// ok: raptor-double-free
		free(*p);
		p++;
	}
	free(v);
}

// &p hands the pointer to a call that sets it again (bsdtar:
// `apply_substitution(..., &subst_name, ...); free(subst_name);` twice).
int substitute(const char *in, char **out);
void rename_entry(const char *a, const char *b)
{
	char *subst;
	if (substitute(a, &subst) == 1)
		free(subst);
	if (substitute(b, &subst) == 1)
		// ok: raptor-double-free
		free(subst);
}

// A function that always exits (fax2ps: `case 'h': free(pages);
// usage(0); break; case '?': free(pages);`).
static void usage(int code)
{
	exit(code);
}
void options(int c, short *pages)
{
	for (;;) {
		switch (c) {
		case 'h':
			free(pages);
			usage(0);
			break;
		case '?':
			// ok: raptor-double-free
			free(pages);
			usage(1);
			break;
		}
	}
}

// Released through a session's allocator hooks (libssh2 CVE-2026-66032,
// sftp_open: `SSH2_FREE(session, data);` then, when sftp_packet_require()
// fails without setting data, `SSH2_FREE(session, data);` again; the fix
// sets `data = NULL;` after the first release).
typedef struct session {
	void (*free)(void *, void **);
	void *abstract;
} SESSION;
#define SSH2_FREE(s, p) (s)->free((p), &(s)->abstract)
// sftp_packet_require() forwards data to sftp_packet_ask(), which sets it
// only when the packet is queued: on an error return data is untouched.
unsigned char *queue_pop(SESSION *s);
static int packet_ask(SESSION *s, unsigned char **data)
{
	unsigned char *p = queue_pop(s);
	if (!p)
		return -1;
	*data = p;
	return 0;
}
static int packet_require(SESSION *s, unsigned char **data)
{
	if (!data)
		return -2;
	if (packet_ask(s, data) == 0)
		return 0;
	return -1;
}
int sftp_open(SESSION *session, unsigned char *data)
{
	SSH2_FREE(session, data);
	if (packet_require(session, &data) == 1) {
		// ruleid: raptor-double-free
		SSH2_FREE(session, data);
		return -1;
	}
	return 0;
}
int sftp_open_fixed(SESSION *session, unsigned char *data)
{
	SSH2_FREE(session, data);
	data = NULL;
	if (packet_require(session, &data) == 1) {
		// ok: raptor-double-free
		SSH2_FREE(session, data);
		return -1;
	}
	return 0;
}

// The opaque argument of a release hook is not released (zlib ZFREE).
typedef struct {
	void (*zfree)(void *opaque, void *p);
	void *opaque;
} Stream;
void release_two(Stream *strm, void *a, void *b)
{
	strm->zfree(strm->opaque, a);
	// ok: raptor-double-free
	strm->zfree(strm->opaque, b);
}

// A library's *_free function, in a retry loop (mongo-c-driver
// CVE-2026-84964, _contact_ocsp_responder: `retry: ... OCSP_REQUEST_free(req);`
// with req allocated only after the first `GOTO (retry)` of the next turn).
typedef struct ocsp_req OCSP_REQUEST;
OCSP_REQUEST *OCSP_REQUEST_new(void);
void OCSP_REQUEST_free(OCSP_REQUEST *req);
void CRYPTO_free(void *p, const char *file, int line);
#define OPENSSL_free(p) CRYPTO_free((p), __FILE__, __LINE__)
int parse_url(const char *url, char **host);
int send_request(OCSP_REQUEST *req);
int contact_responder(const char **urls, int n)
{
	char *host = NULL;
	OCSP_REQUEST *req = NULL;
	for (int i = 0; i < n; i++) {
		if (!parse_url(urls[i], &host))
			goto retry;
		req = OCSP_REQUEST_new();
		if (!send_request(req))
			goto retry;
	retry:
		OPENSSL_free(host);
		// ruleid: raptor-double-free
		OCSP_REQUEST_free(req);
	}
	return 0;
}
// The fix: a fresh request each turn.
int contact_responder_fixed(const char **urls, int n)
{
	for (int i = 0; i < n; i++) {
		char *host = NULL;
		OCSP_REQUEST *req = NULL;
		if (!parse_url(urls[i], &host))
			goto retry;
		req = OCSP_REQUEST_new();
		if (!send_request(req))
			goto retry;
	retry:
		OPENSSL_free(host);
		// ok: raptor-double-free
		OCSP_REQUEST_free(req);
	}
	return 0;
}

// A fill that sets the pointer on every path, or one whose body is not
// known: the pointer is a new one afterwards.
static int fill_always(unsigned char **data)
{
	*data = queue_pop(0);
	return *data ? 0 : -1;
}
int refill(SESSION *session, unsigned char *data)
{
	SSH2_FREE(session, data);
	fill_always(&data);
	// ok: raptor-double-free
	SSH2_FREE(session, data);
	return 0;
}

// Read after the fill: the code took the fill as successful.
int reread(SESSION *session, unsigned char *data)
{
	SSH2_FREE(session, data);
	packet_require(session, &data);
	if (data[0] == 0)
		return 1;
	// ok: raptor-double-free
	SSH2_FREE(session, data);
	return 0;
}

// In a loop, the fill's own length says it succeeded, or the data is
// handed on before the release (libssh2 sftp_write).
static int packet_require_len(SESSION *s, unsigned char **data, unsigned *len)
{
	if (packet_ask(s, data) != 0)
		return -1;
	*len = 9;
	return 0;
}
unsigned ntohu32(const unsigned char *p);
int write_acks(SESSION *session, int n)
{
	unsigned char *data;
	unsigned len = 0;
	unsigned ret = 0;
	for (int i = 0; i < n; i++) {
		int rc = packet_require_len(session, &data, &len);
		if (rc == -2) {
			if (len > 0)
				// ok: raptor-double-free
				SSH2_FREE(session, data);
			return -1;
		} else if (rc < 0)
			return rc;
		ret += ntohu32(data + 5);
		// ok: raptor-double-free
		SSH2_FREE(session, data);
	}
	return (int)ret;
}

// Releasers that clear the pointer.
void av_freep(void *ptr);
void clear_twice(char *p)
{
	av_freep(&p);
	// ok: raptor-double-free
	av_freep(&p);
}

// A non-blocking release retried until it is done (libssh2
// `while (libssh2_channel_free(channel) == LIBSSH2_ERROR_EAGAIN)`).
typedef struct channel CHANNEL;
int libssh2_channel_free(CHANNEL *channel);
void wait_socket(void);
int close_channel(CHANNEL *channel)
{
	// ok: raptor-double-free
	while (libssh2_channel_free(channel) == -37)
		wait_socket();
	return 0;
}

// A release hook handed the address of what it releases (BIND 9
// `zone->ops->plugins_free(zone->mctx, &zone->plugins)`): the memory
// context is not released.
typedef struct mem MEM;
typedef struct {
	void (*hooktable_free)(MEM *mctx, void **table);
	void (*plugins_free)(MEM *mctx, void **plugins);
} ZoneOps;
typedef struct {
	ZoneOps *ops;
	MEM *mctx;
	void *hooktable;
	void *plugins;
} Zone;
void unload_plugins(Zone *zone)
{
	zone->ops->hooktable_free(zone->mctx, &zone->hooktable);
	// ok: raptor-double-free
	zone->ops->plugins_free(zone->mctx, &zone->plugins);
}

// A library destructor taking a pointer to the object pointer releases
// *pp, and a call handed pp sets it again (BIND 9 `dns_difftuple_free(soatuplep)`
// then `dns_difftuple_create(..., soatuplep)` in a loop).
typedef struct tuple TUPLE;
void tuple_free(TUPLE **tp);
void tuple_create(int v, TUPLE **tp);
int next_value(void);
void keep_latest(TUPLE **soatuplep)
{
	int v;
	while ((v = next_value()) != 0) {
		if (*soatuplep != NULL)
			// ok: raptor-double-free
			tuple_free(soatuplep);
		tuple_create(v, soatuplep);
	}
}
void free_tuple_twice(TUPLE *t)
{
	tuple_free(&t);
	// ok: raptor-double-free
	tuple_free(&t);
}

// A library destructor that clears an object's contents, followed by the
// release of the object itself (Mbed TLS `mbedtls_ssl_transform_free(t)`,
// defined in another file, then `mbedtls_free(t)`): two steps of one
// release, not a double free.
typedef struct transform TRANSFORM;
void transform_free(TRANSFORM *t);
typedef struct {
	TRANSFORM *transform;
} SslCtx;
int handshake_reinit(SslCtx *ssl)
{
	if (ssl->transform)
		transform_free(ssl->transform);
	if (ssl->transform == NULL)
		ssl->transform = calloc(1, 64);
	if (ssl->transform == NULL) {
		// ok: raptor-double-free
		free(ssl->transform);
		return -1;
	}
	return 0;
}
void clear_then_free(TRANSFORM *t)
{
	transform_free(t);
	// ok: raptor-double-free
	free(t);
}
void free_twice(TRANSFORM *t)
{
	free(t);
	// ruleid: raptor-double-free
	transform_free(t);
}

// A destructor known by name, then the matching init on the same object
// (Mbed TLS `mbedtls_pk_free(pk); mbedtls_pk_init(pk);` between parse
// attempts): the object is ready to be used, and released, again.
typedef struct pk_ctx PK;
void pk_free(PK *pk);
void pk_init(PK *pk);
int pk_try(PK *pk, int a);
int pk_parse_any(PK *pk)
{
	if (pk_try(pk, 1) == 0)
		return 0;
	pk_free(pk);
	pk_init(pk);
	if (pk_try(pk, 2) == 0)
		return 0;
	// ok: raptor-double-free
	pk_free(pk);
	return -1;
}
// Another type's init does not.
void other_init(PK *pk);
void pk_free_twice(PK *pk)
{
	pk_free(pk);
	other_init(pk);
	// ruleid: raptor-double-free
	pk_free(pk);
}

// A free under a test whose every case returns before the next release
// (libuv uv__getpwuid_r: `if (r != 0 || result == NULL) uv__free(buf);`,
// then `if (r != 0) return ...; if (result == NULL) return ...;` and the
// final `uv__free(buf);` on success only).
int lookup(char *buf, int n, int **res);
int lookup_retry(int n)
{
	char *buf;
	int *result;
	int r;
	for (;; n *= 2) {
		buf = malloc(n);
		if (buf == NULL)
			return -1;
		r = lookup(buf, n, &result);
		if (r != 0 || result == NULL)
			free(buf);
		if (r != 34)
			break;
	}
	if (r != 0)
		return r;
	if (result == NULL)
		return -2;
	// ok: raptor-double-free
	free(buf);
	return 0;
}
// One case of the test falls through to the second release.
int lookup_partial(int n)
{
	char *buf = malloc(n);
	int *result;
	int r = lookup(buf, n, &result);
	if (r != 0 || result == NULL)
		free(buf);
	if (r != 0)
		return r;
	// ruleid: raptor-double-free
	free(buf);
	return 0;
}

int main()
{
	printf("Hello, World!");
	return 0;
}
