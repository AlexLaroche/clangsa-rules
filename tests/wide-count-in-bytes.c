// raptor.WideCountInBytes: a function that takes the size of a wide-character
// buffer as a number of characters is given a number of bytes (sizeof of the
// array, n * sizeof(WCHAR), or a variable computed that way), so it may write
// twice (or four times) past the end of the buffer (CWE-135, CWE-787).
// Modelled on Wine bd7ec9a (comctl32 propsheet.c, toolbar.c, treeview.c:
// MultiByteToWideChar given byte counts), CPython bpo-32869
// (MultiByteToWideChar(..., wname, sizeof(wname))) and BambuStudio
// (GetModuleFileNameW(nullptr, app_path, sizeof(app_path))).
#include <stddef.h>
#include <stdlib.h>
#include <wchar.h>

typedef unsigned short WCHAR;
typedef WCHAR *LPWSTR;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef void *HMODULE;
#define CP_ACP 0
#define MAX_PATH 260
#define max(a, b) ((a) > (b) ? (a) : (b))

int MultiByteToWideChar(UINT, DWORD, const char *, int, LPWSTR, int);
int WideCharToMultiByte(UINT, DWORD, const WCHAR *, int, char *, int, const char *, int *);
DWORD GetModuleFileNameW(HMODULE, LPWSTR, DWORD);
DWORD GetModuleFileNameA(HMODULE, char *, DWORD);
DWORD GetCurrentDirectoryW(DWORD, LPWSTR);
int LoadStringW(HMODULE, UINT, LPWSTR, int);
LPWSTR lstrcpynW(LPWSTR, const WCHAR *, int);
void *Alloc(size_t);
void *ReAlloc(void *, size_t);
void use(const void *);

// Wine propsheet.c PROPSHEET_SetTitleA
void set_title(const char *text) {
  WCHAR szTitle[256];
  // ruleid: raptor-wide-count-in-bytes
  MultiByteToWideChar(CP_ACP, 0, text, -1, szTitle, sizeof(szTitle));
  use(szTitle);
}

// Wine toolbar.c TOOLBAR_TTGetDispInfo
int get_disp_info(const char *text, WCHAR **out) {
  int len = -1 + MultiByteToWideChar(CP_ACP, 0, text, -1, NULL, 0);
  *out = Alloc((len + 1) * sizeof(WCHAR));
  // ruleid: raptor-wide-count-in-bytes
  MultiByteToWideChar(CP_ACP, 0, text, len + 1, *out, (len + 1) * sizeof(WCHAR));
  return 0;
}

// Wine treeview.c TREEVIEW_UpdateDispInfo: the byte count is in a variable
void update_disp_info(const char *text, LPWSTR *item) {
  LPWSTR newText;
  int buflen;
  int len = MultiByteToWideChar(CP_ACP, 0, text, -1, NULL, 0);
  buflen = max((len) * sizeof(WCHAR), 64);
  newText = (LPWSTR)ReAlloc(*item, buflen);
  if (newText) {
    *item = newText;
    // ruleid: raptor-wide-count-in-bytes
    MultiByteToWideChar(CP_ACP, 0, text, -1, *item, buflen);
  }
}

// BambuStudio GUI_App.cpp
void module_path(void) {
  WCHAR app_path[MAX_PATH];
  // ruleid: raptor-wide-count-in-bytes
  GetModuleFileNameW(NULL, app_path, sizeof(app_path));
  use(app_path);
}

// The C library's wide functions count characters too.
void c_library(const char *mb, const wchar_t *ws) {
  wchar_t buf[64];
  // ruleid: raptor-wide-count-in-bytes
  mbstowcs(buf, mb, sizeof(buf));
  // ruleid: raptor-wide-count-in-bytes
  wcsncpy(buf, ws, sizeof(buf) - 1);
  // ruleid: raptor-wide-count-in-bytes
  swprintf(buf, sizeof buf, L"%ls", ws);
  // ruleid: raptor-wide-count-in-bytes
  wmemcpy(buf, ws, sizeof(buf));
  use(buf);
}

// Count first, buffer second.
void count_first(void) {
  WCHAR dir[MAX_PATH];
  // ruleid: raptor-wide-count-in-bytes
  GetCurrentDirectoryW(sizeof(dir), dir);
  // ruleid: raptor-wide-count-in-bytes
  LoadStringW(NULL, 1, dir, sizeof(dir));
  use(dir);
}

// --- character counts ---

void fixed(const char *text, const wchar_t *ws, const WCHAR *wt, int len) {
  WCHAR szTitle[256];
  wchar_t buf[64];
  WCHAR *p = Alloc(len * sizeof(WCHAR));
  // ok: raptor-wide-count-in-bytes
  MultiByteToWideChar(CP_ACP, 0, text, -1, szTitle, sizeof(szTitle) / sizeof(WCHAR));
  // ok: raptor-wide-count-in-bytes
  MultiByteToWideChar(CP_ACP, 0, text, -1, szTitle, sizeof(szTitle) / sizeof(szTitle[0]));
  // ok: raptor-wide-count-in-bytes
  MultiByteToWideChar(CP_ACP, 0, text, -1, p, len);
  // ok: raptor-wide-count-in-bytes
  MultiByteToWideChar(CP_ACP, 0, text, -1, szTitle, 256);
  // ok: raptor-wide-count-in-bytes
  wcsncpy(buf, ws, sizeof(buf) / sizeof(buf[0]) - 1);
  // ok: raptor-wide-count-in-bytes
  lstrcpynW(szTitle, wt, MAX_PATH);
  use(p);
  use(buf);
}

// The narrow output of WideCharToMultiByte and the A functions count bytes.
void narrow(const WCHAR *w) {
  char out[64];
  // ok: raptor-wide-count-in-bytes
  WideCharToMultiByte(CP_ACP, 0, w, -1, out, sizeof(out), NULL, NULL);
  // ok: raptor-wide-count-in-bytes
  GetModuleFileNameA(NULL, out, sizeof(out));
  use(out);
}

// A byte count variable that is converted before use.
void converted(const char *text, int len) {
  size_t bytes = len * sizeof(WCHAR);
  WCHAR *p = Alloc(bytes);
  // ok: raptor-wide-count-in-bytes
  MultiByteToWideChar(CP_ACP, 0, text, -1, p, bytes / sizeof(WCHAR));
  use(p);
}
