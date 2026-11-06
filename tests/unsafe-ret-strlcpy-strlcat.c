#include <stdio.h>
#include <string.h>

#define BUFSIZE 256

void copy_string1(char *string)
{
	char buf[BUFSIZE];
	size_t length;

	// ruleid: raptor-unsafe-ret-strlcpy-strlcat
	length = strlcpy(buf, string, BUFSIZE);

	// use length to access buf, e.g. with strncat()
}

int copy_string2(const char *string)
{
	char buf[BUFSIZE];

	if (!string)
		return -1;

	// ok: raptor-unsafe-ret-strlcpy-strlcat
	if (strlcpy(buf, string, BUFSIZE) >= BUFSIZE)
		return -1; // truncation

	// safely use buf here, knowing it is complete and null-terminated

	return 0;
}

void append_string(char *string)
{
	char buf[BUFSIZE];
	size_t length;

	// ruleid: raptor-unsafe-ret-strlcpy-strlcat
	length = strlcat(buf, string, BUFSIZE);

	// use length to access buf
}

void qualify_username(char *username)
{
	char buf[1024];
	size_t length;

	// ruleid: raptor-unsafe-ret-strlcpy-strlcat
	length = strlcpy(buf, username, sizeof(buf));
	strncat(buf, "@127.0.0.1", sizeof(buf) - length);
	// ...
}

// The result compared with the size given to the call: truncation is
// detected (OpenVPN `if (ciphers_len >= len) msg(M_FATAL, ...)`,
// `buf->len += (str_len < cap) ? str_len : cap - 1`).
void fatal(const char *msg);
size_t copy_checked(char *dst, const char *src, size_t len)
{
	// ok: raptor-unsafe-ret-strlcpy-strlcat
	size_t n = strlcpy(dst, src, len);
	if (n >= len)
		fatal("too long");
	return n;
}

int append_clamped(char *dst, const char *src, int cap)
{
	// ok: raptor-unsafe-ret-strlcpy-strlcat
	int n = (int)strlcat(dst, src, (size_t)cap);
	return (n < cap) ? n : cap - 1;
}

#define CHECK(x) do { if (!(x)) fatal(#x); } while (0)
size_t append_newline(char *buf, size_t size)
{
	// ok: raptor-unsafe-ret-strlcpy-strlcat
	size_t len = strlcat(buf, "\n", size);
	CHECK(len < size);
	return len;
}

size_t copy_compared_elsewhere(char *dst, const char *src, size_t len, size_t other)
{
	// ruleid: raptor-unsafe-ret-strlcpy-strlcat
	size_t n = strlcpy(dst, src, len);
	if (n >= other)
		return 0;
	return n;
}

int main()
{
	printf("Hello, World!");
	return 0;
}
