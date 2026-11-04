// raptor.FreedFieldNotCleared: on an error path a function frees a field it
// filled in earlier (`obj->text`) and returns, but leaves the pointer in the
// object, which outlives the call. Whoever cleans the object up later frees
// it again, or reads it (CWE-415, CWE-416).
// Modelled on CVE-2026-88812 (X.Org xserver, _CheckSetDoodad: the doodad is
// already attached to the geometry, `_GetCountedString(&wire, client,
// &doodad->text.text)`, and when the font string fails `free(doodad->text.text);
// return status;`; XkbFreeGeometry() frees text again. Fixed by
// `doodad->text.text = NULL;`).
#include <stdlib.h>
#include <string.h>

typedef struct {
  char *text;
  char *font;
  int width;
} TextDoodad;
typedef struct {
  TextDoodad text;
  int type;
} Doodad;
typedef struct Geometry Geometry;

Doodad *add_doodad(Geometry *geom, int name);
int get_counted_string(char **wire, char **out);

// CVE-2026-88812
int check_set_doodad(Geometry *geom, char **wire, int name) {
  int status;
  Doodad *doodad = add_doodad(geom, name);
  if (!doodad)
    return 11;
  status = get_counted_string(wire, &doodad->text.text);
  if (status != 0)
    return status;
  status = get_counted_string(wire, &doodad->text.font);
  if (status != 0) {
    // ruleid: raptor-freed-field-not-cleared
    free(doodad->text.text);
    return status;
  }
  return 0;
}

// The fix.
int check_set_doodad_fixed(Geometry *geom, char **wire, int name) {
  int status;
  Doodad *doodad = add_doodad(geom, name);
  if (!doodad)
    return 11;
  status = get_counted_string(wire, &doodad->text.text);
  if (status != 0)
    return status;
  status = get_counted_string(wire, &doodad->text.font);
  if (status != 0) {
    // ok: raptor-freed-field-not-cleared
    free(doodad->text.text);
    doodad->text.text = NULL;
    return status;
  }
  return 0;
}

// Through a parameter, with an assignment.
typedef struct {
  char *name;
  char *value;
} Header;
int parse_header(Header *h, const char *line) {
  h->name = strdup(line);
  if (!h->name)
    return -1;
  h->value = strdup(line + 1);
  if (!h->value) {
    // ruleid: raptor-freed-field-not-cleared
    free(h->name);
    return -1;
  }
  return 0;
}

// The object goes too.
int make_header(Header **out, const char *line) {
  Header *h = malloc(sizeof *h);
  if (!h)
    return -1;
  h->name = strdup(line);
  h->value = strdup(line + 1);
  if (!h->value) {
    // ok: raptor-freed-field-not-cleared
    free(h->name);
    free(h);
    return -1;
  }
  *out = h;
  return 0;
}

// A fresh object nobody else sees yet: leaked, not freed twice.
int new_header(const char *line) {
  Header *h = calloc(1, sizeof *h);
  if (!h)
    return -1;
  h->name = strdup(line);
  if (!h->name)
    return -1;
  h->value = strdup(line);
  if (!h->value) {
    // ok: raptor-freed-field-not-cleared
    free(h->name);
    return -1;
  }
  free(h->value);
  free(h->name);
  free(h);
  return 0;
}

// Not filled in here: the field's owner is somebody else's business.
int drop_name(Header *h, int bad) {
  if (bad) {
    // ok: raptor-freed-field-not-cleared
    free(h->name);
    return -1;
  }
  return 0;
}

// A clear function: no early return on an error path.
void clear_header(Header *h) {
  h->name = NULL;
  // ok: raptor-freed-field-not-cleared
  free(h->value);
}

// Reassigned before returning.
int reset_value(Header *h, const char *v) {
  h->value = strdup(v);
  if (strlen(v) > 64) {
    // ok: raptor-freed-field-not-cleared
    free(h->value);
    h->value = strdup("");
    return -1;
  }
  return 0;
}

// A stack object dies with the function.
int local_header(const char *line) {
  Header h;
  h.name = strdup(line);
  h.value = strdup(line);
  if (!h.value) {
    // ok: raptor-freed-field-not-cleared
    free(h.name);
    return -1;
  }
  return 0;
}

// Other release functions.
void g_free(void *p);
int set_title(Header *h, const char *t) {
  h->value = strdup(t);
  if (t[0] == 0) {
    // ruleid: raptor-freed-field-not-cleared
    g_free(h->value);
    return 1;
  }
  return 0;
}

// A field in a union, freed by a cleanup that dispatches on a tag.
// Tag set before the release (X.Org: the doodad is a union and
// `doodad->any.type` is set first): the cleanup frees the field again.
typedef struct {
  int type;
  int priority;
} AnyDoodad;
typedef struct {
  int type;
  char *text;
  char *font;
} TextDoodadU;
typedef union {
  AnyDoodad any;
  TextDoodadU text;
} DoodadU;
DoodadU *add_doodad_u(Geometry *geom, int name);
int set_text_doodad(Geometry *geom, char **wire, int name, int type) {
  DoodadU *doodad = add_doodad_u(geom, name);
  if (!doodad)
    return 11;
  doodad->any.type = type;
  if (get_counted_string(wire, &doodad->text.text) != 0)
    return 2;
  if (get_counted_string(wire, &doodad->text.font) != 0) {
    // ruleid: raptor-freed-field-not-cleared
    free(doodad->text.text);
    return 2;
  }
  return 0;
}

// Tag set only after the release, on the success path (wolfSSL
// wolfSSL_X509_ATTRIBUTE_set: `value.asn1_string` is freed on failure and
// `value->type` is set afterwards): the cleanup does not touch the field.
typedef struct {
  char *data;
  int length;
} Asn1String;
typedef struct {
  int type;
  union {
    char *ptr;
    Asn1String *asn1_string;
  } value;
} Asn1Type;
typedef struct {
  Asn1Type *value;
} Attribute;
Asn1String *asn1_string_new(void);
int asn1_string_set(Asn1String *s, const char *data, int sz);
void asn1_string_free(Asn1String *s);
int attribute_set(Attribute *attr, const char *data, int sz, int type) {
  attr->value->value.asn1_string = asn1_string_new();
  if (asn1_string_set(attr->value->value.asn1_string, data, sz) != 0) {
    // ok: raptor-freed-field-not-cleared
    asn1_string_free(attr->value->value.asn1_string);
    return 0;
  }
  attr->value->type = type;
  return 1;
}
