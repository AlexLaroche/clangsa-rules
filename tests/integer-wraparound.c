// Marco Ivaldi <raptor@0xdeadbeef.info>

#include <stdio.h>
#include <stdlib.h>
#include <stdckdint.h> // C23
#include <stdint.h>
#include <string.h>
#include <errno.h>

// stubs so that the test compiles
#pragma clang diagnostic ignored "-Wint-conversion"
#pragma clang diagnostic ignored "-Wimplicit-int"
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
typedef struct { int w, h; } img_t;
int get_num_imgs(void);
char **response;
int packet_get_int(void);
char *packet_get_string(void *);
typedef unsigned char u_char;
typedef unsigned int u_int;
struct XML_ParserStruct { size_t m_groupSize; char *m_groupConnector; struct { size_t level; } m_prologState; } *parser;
struct { int *scaffIndex; } *dtd;
struct tfb_softc;
struct wsdisplay_cursor { u_int which; struct { u_int index, count; u_char *red; } cmap; };
#define WSDISPLAY_CURSOR_DOCMAP 1
int copyin(const void *, void *, size_t);
typedef struct ht_entry { struct ht_entry *next; void *key, *value; } *ht_entry_t;
typedef struct { size_t num_keys, num_buckets; ht_entry_t *buckets; } *ht_t;
typedef int dl_status;
typedef void *dl_t;
typedef void *plist_t;
plist_t plist_new_dict(void);
void plist_to_xml(plist_t, char **, uint32_t *);
void plist_free(plist_t);
#define DL_ERROR (-1)
typedef int CURLcode;
#define CURLE_OUT_OF_MEMORY 27
struct Curl_easy;
typedef struct { int allocDefaultAtts; struct DEFAULT_ATTRIBUTE *defaultAtts; } ELEMENT_TYPE;
typedef struct DEFAULT_ATTRIBUTE { int id; } DEFAULT_ATTRIBUTE;
typedef int ATTRIBUTE_ID, XML_Bool;
typedef char XML_Char;
typedef struct XML_ParserStruct *XML_Parser;
typedef int ENCODING;
enum XML_Account { XML_ACCOUNT_NONE };
enum XML_Error { XML_ERROR_NONE };
#define XML_ROLE_GROUP_OPEN 1
typedef void *code(long);
long lVar2, sVar1, sVar7;
void *data;
char *__s, *__ptr;
typedef struct { int size; } printbuf;
int iVar2, iVar3;

void bad1()
{
	img_t *table_ptr;
	int num_imgs;

	// ...

	num_imgs = get_num_imgs();
	// ruleid: raptor-integer-wraparound
	table_ptr = (img_t *)malloc(sizeof(img_t) * num_imgs);

	// ...
}

int good1(void)
{
	int num_imgs = get_num_imgs();
	size_t alloc_size;

	if (num_imgs <= 0)
		return -1;

	if (ckd_mul(&alloc_size, (size_t)num_imgs, sizeof(img_t)))
		return -1; // overflow

	// ok: raptor-integer-wraparound
	img_t *table_ptr = malloc(alloc_size);
	if (!table_ptr)
		return -1;

	// ...

	free(table_ptr);
	return 0;
}

int good2(void)
{
	int num_imgs = get_num_imgs();

	if (num_imgs <= 0)
		return -1;

	if ((size_t)num_imgs > SIZE_MAX / sizeof(img_t))
		return -1; // overflow

	// the rule doesn't currently check for this pattern of overflow prevention, but it arguably should
	// todook: raptor-integer-wraparound
	img_t *table_ptr = malloc((size_t)num_imgs * sizeof(img_t));
	if (!table_ptr)
		return -1;

	// ...

	free(table_ptr);
	return 0;
}

// https://vulncat.fortify.com/
void bad2()
{
	int nresp = packet_get_int();

	if (nresp > 0)
	{
		// ruleid: raptor-integer-wraparound
		response = malloc(nresp * sizeof(char *));
		for (int i = 0; i < nresp; i++)
			response[i] = packet_get_string(NULL);
	}
}

// https://fromdayzerotozeroday.com/
void bad3(n)
{
	// ruleid: raptor-integer-wraparound
	char *const new_connector = (char *)realloc(parser->m_groupConnector, parser->m_groupSize *= 2);
	// ruleid: raptor-integer-wraparound
	int *const new_scaff_index = (int *)realloc(dtd->scaffIndex, parser->m_groupSize * sizeof(int));

	n *= 2;
	// ruleid: raptor-integer-wraparound
	char *buf = (char *)malloc(n);
}

u_char *make_table(unsigned int width, unsigned int height, u_char *init_row)
{
	unsigned int n;
	int i;
	u_char *buf;

	n = width * height;

	// ruleid: raptor-integer-wraparound
	buf = (char *)malloc(n);
	if (!buf)
		return NULL;
	for (i = 0; i < height; i++)
		memcpy(&buf[i * width], init_row, width);

	return buf;
}

// http://www.phrack.org/issues/60/10.html#article
int myfunction(int *array, int len)
{
	int *myarray, i;

	// ruleid: raptor-integer-wraparound
	myarray = malloc(len * sizeof(int));
	if (myarray == NULL)
	{
		return -1;
	}

	for (i = 0; i < len; i++)
	{
		myarray[i] = array[i];
	}

	return myarray;
}

static int
set_cursor(struct tfb_softc *sc, struct wsdisplay_cursor *p)
{
	u_int v, index = 0, count = 0, icount = 0;
	uint8_t r[2], g[2], b[2], image[512], mask[512];
	int error, s;

	v = p->which;
	if (v & WSDISPLAY_CURSOR_DOCMAP)
	{
		index = p->cmap.index; // p->cmap.index is u_int
		count = p->cmap.count; // p->cmap.count is u_int
		// ruleid: raptor-integer-wraparound
		if (index >= 2 || (index + count) > 2)
			return (EINVAL);
		error = copyin(p->cmap.red, &r[index], count);
	}
}

void **ht_get_all(ht_t self, int want_key)
{
	// ruleid: raptor-integer-wraparound
	void **ret = (void **)calloc(self->num_keys + 1, sizeof(void *));
	if (ret)
	{
		void **tail = ret;
		size_t i;
		for (i = 0; i < self->num_buckets; i++)
		{
			ht_entry_t curr;
			for (curr = self->buckets[i]; curr; curr = curr->next)
			{
				*tail++ = (want_key ? curr->key : curr->value);
			}
		}
	}
	return ret;
}

dl_status dl_start(dl_t self)
{
	// ...
	plist_t dict = plist_new_dict();
	// ...
	char *xml = NULL;
	uint32_t xml_length = 0;
	plist_to_xml(dict, &xml, &xml_length);
	plist_free(dict);

	size_t length = 16 + xml_length;
	// ruleid: raptor-integer-wraparound
	char *packet = (char *)calloc(length, sizeof(char));
	if (!packet)
	{
		return DL_ERROR;
	}

	// ...
}

// https://cc-sw.com/using-codeql-and-semgrep-to-assist-vulnerability-research-part-1-of-6/
CURLcode Curl_ntlm_core_mk_nt_hash(struct Curl_easy *data,
								   const char *password,
								   unsigned char *ntbuffer /* 21 bytes */)
{
	size_t len = strlen(password);
	// ruleid: raptor-integer-wraparound
	unsigned char *pw = len ? malloc(len * 2) : strdup("");
	CURLcode result;

	if (!pw)
		return CURLE_OUT_OF_MEMORY;
}

// https://cc-sw.com/using-codeql-and-semgrep-to-assist-vulnerability-research-part-1-of-6/
static int
defineAttribute(ELEMENT_TYPE *type, ATTRIBUTE_ID *attId, XML_Bool isCdata,
				XML_Bool isId, const XML_Char *value, XML_Parser parser)
{
	DEFAULT_ATTRIBUTE *temp;
	int count = type->allocDefaultAtts * 2;
	// ruleid: raptor-integer-wraparound
	temp = (DEFAULT_ATTRIBUTE *)realloc(type->defaultAtts,
										(count * sizeof(DEFAULT_ATTRIBUTE)));
	if (temp == NULL)
		return 0;
	type->allocDefaultAtts = count;
	type->defaultAtts = temp;
}

// https://cc-sw.com/using-codeql-and-semgrep-to-assist-vulnerability-research-part-1-of-6/
static enum XML_Error
doProlog(XML_Parser parser, const ENCODING *enc, const char *s, const char *end,
		 int tok, const char *next, const char **nextPtr, XML_Bool haveMore,
		 XML_Bool allowClosingDoctype, enum XML_Account account)
{
	switch (tok) {
case XML_ROLE_GROUP_OPEN:
	if (parser->m_prologState.level >= parser->m_groupSize)
	{
		if (parser->m_groupSize)
		{
			// ruleid: raptor-integer-wraparound
			char *const new_connector = (char *)realloc(
				parser->m_groupConnector, parser->m_groupSize *= 2);
		}
	}

	}
	// ...
	return XML_ERROR_NONE;
}

// https://cc-sw.com/using-codeql-and-semgrep-to-assist-vulnerability-research-part-1-of-6/
int test_propagation()
{
	lVar2 = sVar1 * 2;
	// ruleid: raptor-integer-wraparound
	data = (void *)(*(code *)malloc)(lVar2);

	// ...
	return 0;
}

// https://cc-sw.com/using-codeql-and-semgrep-to-assist-vulnerability-research-part-1-of-6/
int more_operands()
{
	// ruleid: raptor-integer-wraparound
	__s = (char *)(*(code *)malloc)(sVar7 * 3 + 1);

	// ...
	return 0;
}

// https://cc-sw.com/using-codeql-and-semgrep-to-assist-vulnerability-research-part-1-of-6/
int printbuf_memappend(printbuf *p, char *buf, int size)
{
	if (p->size <= iVar2)
	{
		iVar3 = p->size * 2; // Integer overflow
		if (iVar3 <= iVar2 + 8)
		{
			iVar3 = iVar2 + 9;
		}
		// ruleid: raptor-integer-wraparound
		__ptr = (char *)realloc(__ptr, (long)iVar3); // Alloc call
	}
}

// stubs replacing <windows.h> and <iostream>
typedef void *LPVOID;
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_READWRITE 0x04
#define MEM_RELEASE 0x8000
LPVOID VirtualAlloc(LPVOID, size_t, unsigned, unsigned);
int VirtualFree(LPVOID, size_t, unsigned);

int windows_example()
{
	int nresp = 1073741824;				  // 2^30, close to INT_MAX
	size_t size = nresp * sizeof(char *); // Overflow occurs here!

	// If sizeof(char*) == 4, then nresp * 4 = 4,294,967,296
	// But this exceeds UINT32_MAX (4,294,967,295), so it wraps to 0
	if (size == 0)
	{
		fprintf(stderr, "Integer overflow detected! Size is 0.\n");
		return 1;
	}

	// ruleid: raptor-integer-wraparound
	LPVOID ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (ptr == NULL)
	{
		fprintf(stderr, "VirtualAlloc failed. Size may be invalid due to overflow.\n");
		return 1;
	}

	printf("Memory allocated successfully at: %p\n", ptr);
	VirtualFree(ptr, 0, MEM_RELEASE);
	return 0;
}

int main()
{
	printf("Hello, World!");
	return 0;
}
