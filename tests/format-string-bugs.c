#include <stdio.h>
#include <syslog.h>

#define BUFSIZE 256

/* stubs added for the clang port (not part of the original semgrep test) */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
typedef struct SordWorld SordWorld;
extern void *sord;
extern int d;
void sord_free(void *);
SordWorld *sord_world_new(void);
int finished(SordWorld *, void *, int);

void build_string(char *string)
{
	char buf[BUFSIZE];

	// ruleid: raptor-format-string-bugs
	snprintf(buf, BUFSIZE, string);

	// ok: raptor-format-string-bugs
	snprintf(buf, BUFSIZE, "%s", string);
}

void print_stuff(char *string)
{
	char buf[BUFSIZE];

	// ruleid: raptor-format-string-bugs
	printf(string);

	// ok: raptor-format-string-bugs
	printf("%s\n", string);
}

void log_stuff(char *string)
{
	char buf[BUFSIZE];

	// ruleid: raptor-format-string-bugs
	syslog(LOG_ERR, string);

	// ok: raptor-format-string-bugs
	syslog(LOG_ERR, "%s", string);
}

void log_error(char *fmt, ...)
{
	char buf[BUFSIZE];
	va_list ap;

	va_start(ap, fmt);
	// ruleid: raptor-format-string-bugs
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	// ruleid: raptor-format-string-bugs
	syslog(LOG_NOTICE, buf);
}

void printWrapper(char *string)
{
	// ruleid: raptor-format-string-bugs
	printf(string);
}

/* namespace basic_tests (C++ only, removed for the C port) */

	void test_001()
	{
		const char *env_001 = getenv("PATH");

		// ruleid: raptor-format-string-bugs
		printf(env_001, 1);

		// ok: raptor-format-string-bugs
		printf("%s", env_001);

		// ruleid: raptor-format-string-bugs
		scanf(env_001, &d);
	}

int test_002(int argc, char **argv)
{
	int d = 0;
	// ruleid: raptor-format-string-bugs
	scanf(argv[1], &d);
}

int test_003(int argc, char **argv)
{
	static const size_t n_quads = 300;

	sord_free(NULL); // Shouldn't crash

	SordWorld *world = sord_world_new();

	// ok: raptor-format-string-bugs
	fprintf(stderr, "expected ");

	// ruleid: raptor-format-string-bugs
	fprintf(stderr, argv[1]);

	return finished(world, sord, EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	char buf[5012];
	memcpy(buf, argv[1], 5012);
	printWrapper(argv[1]);
	return 0;
}

void fmt_conditional(int mr, int len, char *user)
{
	static char umsg[] = "usage: %d\n";

	// ok: raptor-format-string-bugs
	fprintf(stdout, mr ? ":%d" : "%7d bytes", len);
	// ok: raptor-format-string-bugs
	printf(umsg, len);
	// ruleid: raptor-format-string-bugs
	printf(mr ? user : "%d", len);
}

// printf-like wrappers with a format attribute forward their own format
// parameter, and the compiler checks the callers' formats (OpenVPN
// buf_printf(), status_printf()).
int log_vformat(char *out, size_t n, const char *format, va_list ap)
	__attribute__((format(printf, 3, 0)));
int log_vformat(char *out, size_t n, const char *format, va_list ap)
{
	// ok: raptor-format-string-bugs
	return vsnprintf(out, n, format, ap);
}
int log_format(char *out, size_t n, const char *format, ...)
	__attribute__((format(printf, 3, 4)));
int log_format(char *out, size_t n, const char *format, ...)
{
	va_list ap;
	int r;
	va_start(ap, format);
	// ok: raptor-format-string-bugs
	r = vsnprintf(out, n, format, ap);
	va_end(ap);
	return r;
}
// A constant array initialized with a literal is a constant format
// (OpenVPN `static const char usage_message[] = "..."`).
static const char usage_text[] = "usage: %s [options]\n";
void print_usage(const char *name)
{
	// ok: raptor-format-string-bugs
	printf(usage_text, name);
}
// A non-wrapper taking a format from its caller is still reported.
void print_label(const char *label)
{
	// ruleid: raptor-format-string-bugs
	printf(label);
}
