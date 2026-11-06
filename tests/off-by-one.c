#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define BUFSIZE 256

/* stubs added for the clang port (not part of the original semgrep test) */
#include <stdlib.h>
#define MAX_MAC 16
struct session { int mac[MAX_MAC + 1]; };
typedef struct { int count; } LabelText;
struct line { struct line *next, *prev; char *data; size_t length; };
struct buffer { int numLines; };
extern struct buffer *currentBuffer;
extern int nondet;
void die(const char *);
int read_network_integer(int);
void countTabs(struct line *);

void bad1(char *string)
{
	char buf[BUFSIZE];

	strncpy(buf, string, BUFSIZE);
	// ruleid: raptor-off-by-one
	buf[BUFSIZE] = '\0';
}

void good1(char *string)
{
	char buf[BUFSIZE];

	strncpy(buf, string, BUFSIZE);
	// ok: raptor-off-by-one
	buf[BUFSIZE - 1] = '\0';
}

void bad2(char *string)
{
	char firstname[20];
	char lastname[20];
	char fullname[40];

	fullname[0] = '\0';

	// ruleid: raptor-off-by-one
	strncat(fullname, firstname, 40);
}

void good2(char *string)
{
	char firstname[20];
	char lastname[20];
	char fullname[40];

	fullname[0] = '\0';

	// ok: raptor-off-by-one
	strncat(fullname, firstname, sizeof(fullname) - strlen(fullname) - 1);
}

void bad3(char *string)
{
	char filename[BUFSIZE];

	// commented-out because of too many false positives: raptor-off-by-one
	for (int i = 0; i <= BUFSIZE; i++)
	{
		char c = getc(stdin); /* stdin added for the clang port */
		if (c == 'EOF')
		{
			filename[i] = '\0';
		}
		filename[i] = getc(stdin);
	}
}

void good3(char *string)
{
	char filename[BUFSIZE];

	// ok: raptor-off-by-one
	for (int i = 0; i < BUFSIZE; i++)
	{
		char c = getc(stdin); /* stdin added for the clang port */
		if (c == 'EOF')
		{
			filename[i] = '\0';
		}
		filename[i] = getc(stdin);
	}
}

void test_func()
{
	int id_sequence[3];

	id_sequence[0] = 123;
	id_sequence[1] = 234;
	id_sequence[2] = 345;
	// ruleid: raptor-off-by-one
	id_sequence[3] = 456;
}

void processRawStr(uint8_t *s, size_t sz)
{
	uint8_t buf[1024];
	memset(buf, 0x0, sizeof(buf));
	memcpy(buf, s, sizeof(buf));
	// ruleid: raptor-off-by-one
	buf[sizeof(buf)] = '\0';
	// ...
}

void process_string(char *src)
{
	char dest[32];
	int i; /* declaration added for the clang port */

	// commented-out because of too many false positives: raptor-off-by-one
	for (i = 0; src[i] && (i <= sizeof(dest)); i++)
		dest[i] = src[i];

	// ...

	return;
}

void get_user(char *user)
{
	char buf[1024];

	// ruleid: raptor-off-by-one
	if (strlen(user) > sizeof(buf))
		die("error: user string too long\n");

	strcpy(buf, user);
	// ...
}

int get_mac(int fd, struct session *session)
{
	unsigned int i, n;

	n = read_network_integer(fd);
	if (n > MAX_MAC)
		return 1;

	// commented-out because of too many false positives: raptor-off-by-one
	for (i = 0; i <= n; i++)
		session->mac[i] = read_network_integer(fd);
	return 0;
}

int variant1(int argc, char *argv[])
{
	char buf[10];

	// ruleid: raptor-off-by-one
	*(buf + 10) = 'A';

	return 0;
}

int variant2(int argc, char *argv[])
{
	char bStr[10];
	// commented-out because of too many false positives: raptor-off-by-one
	for (unsigned i = 1; i <= 10; ++i)
	{
		bStr[i] = (char)i + 'a';
	}
	return 0;
}

static LabelText *text_create(char *orig_str, int char_width)
{
	int i, j;
	char line[256]; /* a line should not exceed this length */
	int pos;
	int last_space;
	int new_line;
	LabelText *text = 0;
	char *str = 0;
	text = calloc(1, sizeof(LabelText));

	str = strdup(orig_str);

	if (char_width > 0)
	{
		for (i = 0; i < strlen(str); i++)
			if (str[i] == 10)
				text->count++;

		// ruleid: raptor-off-by-one
		if (str[strlen(str) - 1] != 10)
			text->count++;
	}

	return NULL;
}

static LabelText *text_create2(char *orig_str, int char_width)
{
	int i, j;
	char line[256]; /* a line should not exceed this length */
	int pos;
	int last_space;
	int new_line;
	LabelText *text = 0;
	char *str = 0;
	int length;
	text = calloc(1, sizeof(LabelText));

	str = strdup(orig_str);
	length = strlen(str);

	if (char_width > 0)
	{
		for (i = 0; i < strlen(str); i++)
			if (str[i] == 10)
				text->count++;

		// ruleid: raptor-off-by-one
		if (str[strlen(str) - 1] != 10)
			text->count++;
	}

	return NULL;
}

void addLineAfter(struct line *whichLine, char *data)
{
	struct line *temp = whichLine->next;
	struct line *newLine = (struct line *)malloc(sizeof(struct line));
	temp->prev = newLine;
	whichLine->next = newLine;
	newLine->next = temp;
	newLine->prev = whichLine;
	// ruleid: raptor-off-by-one
	newLine->data = (char *)malloc(strlen(data));
	strcpy(newLine->data, data);
	newLine->length = strlen(data);
	countTabs(newLine);
	currentBuffer->numLines++;
}

void addLineAfter_fixed(struct line *whichLine, char *data)
{
	struct line *temp = whichLine->next;
	struct line *newLine = (struct line *)malloc(sizeof(struct line));
	temp->prev = newLine;
	whichLine->next = newLine;
	newLine->next = temp;
	newLine->prev = whichLine;
	// ok: raptor-off-by-one
	newLine->data = (char *)malloc(strlen(data) + 1);
	strcpy(newLine->data, data);
	newLine->length = strlen(data);
	countTabs(newLine);
	currentBuffer->numLines++;
}

char *flawed_strdup(const char *input) /* was void: returns copy */
{
	char *copy;

	// ruleid: raptor-off-by-one
	copy = (char *)malloc(strlen(input));
	strcpy(copy, input);
	return copy;
}

char *ok_strdup(const char *input) /* was void: returns copy */
{
	char *copy;

	// ok: raptor-off-by-one
	copy = (char *)malloc(strlen(input) + 1);
	strcpy(copy, input);
	return copy;
}

char *flawed_strdup2(const char *input) /* was void: returns copy */
{
	char *copy;

	int len = strlen(input);

	// ruleid: raptor-off-by-one
	copy = (char *)malloc(len);
	strcpy(copy, input);
	return copy;
}

char *ok_strdup2(const char *input) /* was void: returns copy */
{
	char *copy;

	int len = strlen(input);

	// ok: raptor-off-by-one
	copy = (char *)malloc(len + 1);
	strcpy(copy, input);
	return copy;
}

int two_dimensions(int argc, char *argv[])
{
	char buffer[1][256];
	// ruleid: raptor-off-by-one
	buffer[0][256] = '!';
	// ruleid: raptor-off-by-one
	buffer[1][1] = '!';
	// ok: raptor-off-by-one
	buffer[0][255] = '!';
	return 0;
}

void f(const char *str)
{
	// ruleid: raptor-off-by-one
	char *buffer = malloc(strlen(str));
	free(buffer);
}

void f2(const char *str) /* renamed: duplicate definition */
{
	// ok: raptor-off-by-one
	char *buffer = malloc(strlen(str) + 1);
	free(buffer);
}

void f3(const char *str) /* renamed: duplicate definition */
{
	// ok: raptor-off-by-one
	char *buffer = malloc(strlen(str) + 1);
	free(buffer);
}

void f4(const char *str) /* renamed: duplicate definition */
{
	size_t len = strlen(str);
	// ruleid: raptor-off-by-one
	char *buffer = malloc(len);
	free(buffer);
}

void f5(const char *str) /* renamed: duplicate definition */
{
	size_t len = strlen(str);
	// ok: raptor-off-by-one
	char *buffer = malloc(len + 1);
	free(buffer);
}

void f6(const char *str) /* renamed: duplicate definition */
{
	size_t len;
	len = strlen(str);
	// ruleid: raptor-off-by-one
	char *buffer = malloc(len);
	free(buffer);
}

void f7(const char *str) /* renamed: duplicate definition */
{
	size_t len = strlen(str);
	len += 1;
	// todook: raptor-off-by-one
	char *buffer = malloc(len);
	free(buffer);
}

void f8(const char *str) /* renamed: duplicate definition */
{
	size_t len = strlen(str);
	if (nondet)
	{
		len += 1;
	}
	// ruleid: raptor-off-by-one
	char *buffer = malloc(len);
	free(buffer);
}

void f9(const char *str) /* renamed: duplicate definition */
{
	size_t len = strlen(str);
	if (len)
	{
		// ruleid: raptor-off-by-one
		char *buffer = malloc(len);
		free(buffer);
	}
}

// Indexing with len - 1 under a test that the string is not empty (Mbed TLS
// mbedtls_mpi_read_file: `if (slen > 0 && s[slen - 1] == '\n')`).
void chomp(char *s)
{
	size_t slen = strlen(s);
	// ok: raptor-off-by-one
	if (slen > 0 && s[slen - 1] == '\n')
		slen--;
	if (slen != 0)
		// ok: raptor-off-by-one
		s[slen - 1] = 0;
	// ok: raptor-off-by-one
	if (strlen(s) && s[strlen(s) - 1] == '\r')
		s[0] = 0;
}
// A test of another value does not protect the index.
void chomp_bad(char *s, int n)
{
	size_t slen = strlen(s);
	// ruleid: raptor-off-by-one
	if (n > 0 && s[slen - 1] == '\n')
		s[0] = 0;
}

// A test that the string is not empty: `*s &&`, or `!*s ||` / `len == 0 ||`
// (FFmpeg format_line: `*line && line[strlen(line) - 1] != '\r'`,
// sdp_parse_fmtp_config_h264: `*value == 0 || value[strlen(value) - 1] == ','`,
// rtsp_parse_streaming_commands: `len == 0 || url[len - 1] != '/'`).
int ends_with(const char *line, char *url)
{
	size_t len = strlen(url);
	// ok: raptor-off-by-one
	if (*line && line[strlen(line) - 1] != '\r')
		return 1;
	// ok: raptor-off-by-one
	if (*line == 0 || line[strlen(line) - 1] == ',')
		return 2;
	// ok: raptor-off-by-one
	if (line[0] != '\0' && line[strlen(line) - 1] == '/')
		return 3;
	// ok: raptor-off-by-one
	if (len == 0 || url[len - 1] != '/')
		return 4;
	// ruleid: raptor-off-by-one
	if (*url || line[strlen(line) - 1] == ',')
		return 5;
	return 0;
}

// A signed index tested for >= 0: an empty string gives -1 (FFmpeg
// log_callback: `for (i = strlen(msg) - 1; i >= 0 && msg[i] == '\n'; i--)`,
// mov_open_dref: `for (l = strlen(path) - 1; l >= 0; l--) if (path[l] == '/')`).
int trim_nl(char *msg, const char *path)
{
	int i, l, n = 0;
	// ok: raptor-off-by-one
	for (i = strlen(msg) - 1; i >= 0 && msg[i] == '\n'; i--)
		msg[i] = 0;
	for (l = strlen(path) - 1; l >= 0; l--)
		// ok: raptor-off-by-one
		if (path[l] == '/')
			n++;
	return n;
}

// An unsigned index wraps instead of going negative.
void trim_nl_unsigned(char *msg)
{
	size_t i = strlen(msg) - 1;
	// ruleid: raptor-off-by-one
	if (i >= 0 && msg[i] == '\n')
		// ruleid: raptor-off-by-one
		msg[i] = 0;
}

int main()
{
	printf("Hello, World!");
	return 0;
}
