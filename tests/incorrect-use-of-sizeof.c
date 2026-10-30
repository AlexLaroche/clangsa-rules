#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* stubs added for the clang port (not part of the original semgrep test) */
#include <stdint.h>
typedef struct { int a, b; } AnObj;
void error(const char *, ...);
#define AUTH_FAIL 0
#define AUTH_SUCCESS 1
void ExitError(const char *);
void DoAuthenticatedTask(char *);
typedef long ngx_int_t;
typedef struct { size_t len; unsigned char *data; } ngx_str_t;
typedef struct { void *log; } ngx_connection_t;
typedef struct { void *pool; ngx_connection_t *connection; } ngx_http_request_t;
typedef struct { int dummy; } ngx_buf_t;
typedef struct { int dummy; } ngx_chain_t;
typedef struct { unsigned not_found; size_t len; unsigned char *data; } ngx_http_variable_value_t;
typedef struct { ngx_str_t cmd_str; ngx_http_variable_value_t *memc_key_vv, *memc_value_vv; } ngx_http_memc_ctx_t;
extern int ngx_http_memc_module;
#define ngx_http_get_module_ctx(r, m) ((ngx_http_memc_ctx_t *)0)
#define ngx_log_error(level, log, err, ...) error(__VA_ARGS__)
#define NGX_LOG_ERR 4
#define NGX_ERROR -1
#define NGX_OK 0
#define NGX_ESCAPE_MEMCACHED 6
#define CRLF "\r\n"
uintptr_t ngx_escape_uri(unsigned char *, unsigned char *, size_t, int);
ngx_buf_t *ngx_create_temp_buf(void *, size_t);
ngx_chain_t *ngx_alloc_chain_link(void *);

void bad1()
{
	double *foo;

	// ruleid: raptor-incorrect-use-of-sizeof
	foo = (double *)malloc(sizeof(foo));
}

void good1()
{
	double *foo;

	// ok: raptor-incorrect-use-of-sizeof
	foo = (double *)malloc(sizeof(*foo));
}

void bad2(char *buf)
{
	size_t size;

	// ruleid: raptor-incorrect-use-of-sizeof
	size = sizeof(buf);
}

void good2()
{
	char buf[256];
	size_t size;

	// ok: raptor-incorrect-use-of-sizeof
	size = sizeof(buf);
}

void bad3()
{
	AnObj *o = (AnObj *)malloc(sizeof(AnObj));
	// ruleid: raptor-incorrect-use-of-sizeof
	memset(o, 0x0, sizeof(o));
}

char *read_username(int sockfd)
{
	char *buffer, *style, userstring[1024];
	int i;

	buffer = (char *)malloc(1024);

	if (!buffer)
	{
		error("buffer allocation failed: %m");
		return NULL;
	}

	if (read(sockfd, userstring, sizeof(userstring) - 1) <= 0)
	{
		free(buffer);
		error("read failure: %m");
		return NULL;
	}
	userstring[sizeof(userstring) - 1] = '\0';
	style = strchr(userstring, ':');

	if (style)
		*style++ = '\0';
	sprintf(buffer, "username=%.32s", userstring);

	if (style)
		// ruleid: raptor-incorrect-use-of-sizeof
		snprintf(buffer, sizeof(buffer) - strlen(buffer) - 1, ", style=%s\n", style);

	return buffer;
}

char *username = "admin";
char *pass = "password";

int AuthenticateUser(char *inUser, char *inPass)
{
	// ruleid: raptor-incorrect-use-of-sizeof
	printf("Sizeof username = %d\n", sizeof(username));
	// ruleid: raptor-incorrect-use-of-sizeof
	printf("Sizeof pass = %d\n", sizeof(pass));

	// ruleid: raptor-incorrect-use-of-sizeof
	if (strncmp(username, inUser, sizeof(username)))
	{
		printf("Auth failure of username using sizeof\n");
		return (AUTH_FAIL);
	}

	// ruleid: raptor-incorrect-use-of-sizeof
	if (!strncmp(pass, inPass, sizeof(pass)))
	{
		printf("Auth success of password using sizeof\n");
		return (AUTH_SUCCESS);
	}
	else
	{
		printf("Auth fail of password using sizeof\n");
		return (AUTH_FAIL);
	}
}

// https://github.com/openresty/memc-nginx-module/commit/1e5e8655b3783d29dec1a9941bb6571989cf7dbb
ngx_int_t
ngx_http_memc_create_incr_decr_cmd_request(ngx_http_request_t *r)
{
	size_t len;
	ngx_buf_t *b;
	ngx_http_memc_ctx_t *ctx;
	ngx_chain_t *cl;
	uintptr_t escape;
	ngx_http_variable_value_t *key_vv;
	ngx_http_variable_value_t *value_vv;

	ctx = ngx_http_get_module_ctx(r, ngx_http_memc_module);

	/* prepare the "key" argument */

	key_vv = ctx->memc_key_vv;

	if (key_vv == NULL || key_vv->not_found || key_vv->len == 0)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					  "the \"$memc_key\" variable is not set");
		return NGX_ERROR;
	}

	escape = 2 * ngx_escape_uri(NULL, key_vv->data, key_vv->len,
								NGX_ESCAPE_MEMCACHED);

	/* prepare the "value" argument */

	value_vv = ctx->memc_value_vv;

	/* XXX validate if $memc_value_vv is a valid uint64 string */
	// this should be caught but it isn't, due to a known issue in semgrep
	// https://github.com/semgrep/semgrep/issues/11327
	// todoruleid: raptor-incorrect-use-of-sizeof
	len = ctx->cmd_str.len + sizeof(' ') + key_vv->len + escape + sizeof(' ') + value_vv->len + sizeof(CRLF) - 1;

	b = ngx_create_temp_buf(r->pool, len);
	if (b == NULL)
	{
		return NGX_ERROR;
	}

	cl = ngx_alloc_chain_link(r->pool);
	if (cl == NULL)
	{
		return NGX_ERROR;
	}

	// ...

	return NGX_OK;
}

int main(int argc, char **argv)
{
	int authResult;

	if (argc < 3)
	{
		ExitError("Usage: Provide a username and password");
	}
	authResult = AuthenticateUser(argv[1], argv[2]);
	if (authResult != AUTH_SUCCESS)
	{
		ExitError("Authentication failed");
	}
	else
	{
		DoAuthenticatedTask(argv[1]);
	}
	return 0;
}

int count_names(void)
{
	static const char *names[] = { "a", "b", "c" };
	int n = 0;

	// ok: raptor-incorrect-use-of-sizeof
	n += sizeof(names) / sizeof(names[0]);
	// ok: raptor-incorrect-use-of-sizeof
	n += sizeof(names) / sizeof(*names);
	return n;
}
