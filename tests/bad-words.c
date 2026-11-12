#include <stdio.h>

/* Identifiers that only contain a marker word, log-level constants and
 * header names are not findings (httpd h2_mplx.c triage, 2026-11-12). */
	// ok: raptor-bad-words
#define APLOG_WARNING 4
	// ok: raptor-bad-words
#define APLOG_DEBUG 7
	// ok: raptor-bad-words
#define AP_DEBUG_ASSERT(x) ((void)(x))
static void log_it(int level, const char *msg) { (void)level; (void)msg; }

	// ok: raptor-bad-words
#if APR_POOL_DEBUG
	// ok: raptor-bad-words
#include "h2_private.h"
#endif

int do_something(char *string)
{
	// ok: raptor-bad-words
	int bug = 0;

	// ruleid: raptor-bad-words
	/* XXX */
	printf("Hello, World!");

	if (bug)
	{
		// ruleid: raptor-bad-words
		// TODO: handle condition
	}

	// ruleid: raptor-bad-words
	// this might be insecure

	// ok: raptor-bad-words
	log_it(APLOG_WARNING, "x");
	// ok: raptor-bad-words
	log_it(APLOG_DEBUG, "x");
	// ok: raptor-bad-words
	AP_DEBUG_ASSERT(string != NULL);

	/* A real word after a skipped identifier on the same line still counts. */
	// ruleid: raptor-bad-words
	log_it(APLOG_DEBUG, "x"); /* BUG: level */
	// ruleid: raptor-bad-words
	log_it(APLOG_WARNING, "unsafe copy");
	// ruleid: raptor-bad-words
	char *db_password = 0;
	return 1;
}

int main()
{
	printf("Hello, World!");
	return 0;
}
