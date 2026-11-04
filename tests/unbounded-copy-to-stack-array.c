// raptor.UnboundedCopyToStackArray: a string of unknown length is copied
// into a fixed-size local array (strcpy, strcat, sprintf "%s"...) and nothing
// in the function compares its length with anything: a stack overflow
// (CWE-121, CWE-787).
// Modelled on CVE-2026-40489 (editorconfig-core-c, ec_glob, an incomplete fix of CVE-2023-0341:
// `char l_pattern[2 * PATTERN_MAX]; strcpy(l_pattern, pattern);`, fixed by
// rejecting `strlen(pattern) >= sizeof(l_pattern)` before the copy).
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define PATTERN_MAX 4097

// CVE-2026-40489
int ec_glob(const char *pattern, const char *string) {
  char l_pattern[2 * PATTERN_MAX];
  // ruleid: raptor-unbounded-copy-to-stack-array
  strcpy(l_pattern, pattern);
  return strcmp(l_pattern, string);
}

// The fix.
int ec_glob_fixed(const char *pattern, const char *string) {
  char l_pattern[2 * PATTERN_MAX];
  size_t pattern_len = strlen(pattern);
  if (pattern_len >= sizeof(l_pattern))
    return -1;
  // ok: raptor-unbounded-copy-to-stack-array
  memcpy(l_pattern, pattern, pattern_len + 1);
  return strcmp(l_pattern, string);
}

// Checked, then strcpy.
int copy_checked(const char *name) {
  char buf[64];
  if (strlen(name) >= sizeof(buf))
    return -1;
  // ok: raptor-unbounded-copy-to-stack-array
  strcpy(buf, name);
  return buf[0];
}

// strcat and sprintf of unchecked strings.
int build_path(const char *dir, const char *file) {
  char path[256];
  // ok: raptor-unbounded-copy-to-stack-array
  strcpy(path, "/srv/");
  // ruleid: raptor-unbounded-copy-to-stack-array
  strcat(path, dir);
  // ok: raptor-unbounded-copy-to-stack-array
  strcat(path, "/");
  return path[0] + file[0];
}

int format_user(const char *user, int id) {
  char line[128];
  // ruleid: raptor-unbounded-copy-to-stack-array
  sprintf(line, "user=%s id=%d", user, id);
  // ok: raptor-unbounded-copy-to-stack-array
  sprintf(line, "id=%d", id);
  // ok: raptor-unbounded-copy-to-stack-array
  sprintf(line, "user=%.32s", user);
  // ok: raptor-unbounded-copy-to-stack-array
  sprintf(line, "%s", "constant");
  return line[0];
}

// The source is an array that fits.
struct rec {
  char name[32];
};
int copy_field(const struct rec *r) {
  char small[16], big[32];
  // ok: raptor-unbounded-copy-to-stack-array
  strcpy(big, r->name);
  // ruleid: raptor-unbounded-copy-to-stack-array
  strcpy(small, r->name);
  return small[0] + big[0];
}

// Not a stack array: a static buffer, a parameter, a heap pointer.
char g_buf[64];
int not_stack(char *out, const char *s) {
  static char saved[64];
  // ok: raptor-unbounded-copy-to-stack-array
  strcpy(saved, s);
  // ok: raptor-unbounded-copy-to-stack-array
  strcpy(out, s);
  // ok: raptor-unbounded-copy-to-stack-array
  strcpy(g_buf, s);
  return saved[0];
}

// Length checked through a local holding strlen().
int copy_len_local(const char *s) {
  char buf[32];
  size_t n = strlen(s);
  if (n > 31)
    n = 31;
  if (n + 1 > sizeof(buf))
    return -1;
  // ok: raptor-unbounded-copy-to-stack-array
  strcpy(buf, s);
  return buf[0];
}

// vsprintf with a caller format.
void log_msg(const char *fmt, ...) {
  char msg[512];
  va_list ap;
  va_start(ap, fmt);
  // ruleid: raptor-unbounded-copy-to-stack-array
  vsprintf(msg, fmt, ap);
  va_end(ap);
  puts(msg);
}

// Strings from a table of literals, or a local only set to literals
// (libtiff tests: openModeStrings[openMode]).
static const char *const modes[] = {"r", "w", "a"};
int open_name(int m, int big) {
  char name[64];
  const char *kind = big ? "big" : "classic";
  // ok: raptor-unbounded-copy-to-stack-array
  sprintf(name, "test_%s_%s.tif", modes[m], kind);
  // ok: raptor-unbounded-copy-to-stack-array
  strcat(name, modes[m]);
  return name[0];
}

// CVE-2026-27821 (GPAC nhmldmx_config_output): an XML attribute value copied
// into a local array; the fix bounds it with strncpy.
typedef struct {
  char *name, *value;
} XMLAttribute;
int config_output(const XMLAttribute *att) {
  char szXmlHeaderEnd[1000];
  // ok: raptor-unbounded-copy-to-stack-array
  strcpy(szXmlHeaderEnd, "");
  // ruleid: raptor-unbounded-copy-to-stack-array
  strcpy(szXmlHeaderEnd, att->value);
  // ok: raptor-unbounded-copy-to-stack-array
  strncpy(szXmlHeaderEnd, att->value, sizeof(szXmlHeaderEnd) - 1);
  return szXmlHeaderEnd[0];
}

// CVE-2026-71979 (INDI lilxml oneXMLchar): the destination is a parameter
// declared as an array, the caller's fixed error buffer, and the tag names
// formatted into it grow without bound. The fix uses snprintf.
typedef struct {
  char *s;
} String;
typedef struct {
  int ln;
  String endtag;
  String tag;
} Parser;
int close_tag(Parser *lp, char ynot[]) {
  // ruleid: raptor-unbounded-copy-to-stack-array
  sprintf(ynot, "Line %d: closing tag %s does not match %s", lp->ln, lp->endtag.s, lp->tag.s);
  // ok: raptor-unbounded-copy-to-stack-array
  sprintf(ynot, "Line %d: early XML EOF", lp->ln);
  // ok: raptor-unbounded-copy-to-stack-array
  snprintf(ynot, 1024, "Line %d: closing tag %s", lp->ln, lp->endtag.s);
  return -1;
}
int copy_into_sized_param(char out[64], const char *s) {
  // ruleid: raptor-unbounded-copy-to-stack-array
  strcpy(out, s);
  return 0;
}
// A plain pointer parameter says nothing about the buffer.
int copy_into_pointer(char *out, const char *s) {
  // ok: raptor-unbounded-copy-to-stack-array
  strcpy(out, s);
  return 0;
}
