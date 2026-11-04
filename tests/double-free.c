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

int main()
{
	printf("Hello, World!");
	return 0;
}
