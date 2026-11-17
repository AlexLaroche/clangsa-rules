// raptor.IgnoredStatusReturn on C++: callees without a plain identifier
// (overloaded operators, conversion functions) must not crash the checker.
// Found on OpenJDK HotSpot stubGenerator_x86_64.cpp (2026-11-17): the
// end-of-TU pass called NamedDecl::getName() on `operator==` and asserted.

struct Reg {
  int enc;
  bool operator==(const Reg &o) const { return enc == o.enc; }
  int operator()(int x) const {
    if (x < 0)
      return -1;
    return enc + x;
  }
  operator int() const {
    if (enc < 0)
      return -1;
    return enc;
  }
};

static int set_up(Reg *r, int v) {
  if (v < 0)
    return -1;
  r->enc = v;
  return 0;
}

int use_checked(Reg *r) {
  // ok: raptor-ignored-status-return
  if (set_up(r, 1) != 0)
    return -1;
  // ok: raptor-ignored-status-return
  if (set_up(r, 2) < 0)
    return -1;
  return 0;
}

void use_dropped(Reg *r, int v) {
  // ruleid: raptor-ignored-status-return
  set_up(r, v);
}

int use_operators(Reg a, Reg b) {
  // ok: raptor-ignored-status-return
  if (a == b)
    return 1;
  // ok: raptor-ignored-status-return
  a(4);
  // ok: raptor-ignored-status-return
  int n = a;
  return n;
}
