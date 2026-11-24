// raptor.UncheckedRandomRead: random bytes are read and the call is not
// checked for having filled the buffer, so a short or failed read leaves
// zero or stale bytes in a key, nonce or session id (CWE-252, CWE-330).
// Modelled on OpenWrt rpcd fb0302d (session ids: `ret = fread(buf, 1,
// sizeof(buf), f); if (ret < 0)`), libdogecoin b7891cf (keys: `assert(len_read
// == len)`, compiled out by NDEBUG) and Netatalk 2721b62 (AFP nonces: `ret =
// read(fd, buf, len); if (ret <= 0)`).
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

ssize_t getrandom(void *, size_t, unsigned int);
int getentropy(void *, size_t);
int RAND_bytes(unsigned char *, int);
void use(const void *, size_t);

// OpenWrt rpcd session.c rpc_random
int rpc_random(char *dest) {
  unsigned char buf[16] = {0};
  FILE *f;
  int i;
  int ret;
  f = fopen("/dev/urandom", "r");
  if (!f)
    return -1;
  // ruleid: raptor-unchecked-random-read
  ret = fread(buf, 1, sizeof(buf), f);
  fclose(f);
  if (ret < 0)
    return ret;
  for (i = 0; i < 16; i++)
    sprintf(dest + (i << 1), "%02x", buf[i]);
  return 0;
}

// libdogecoin random.c dogecoin_random_bytes_internal
int random_bytes(unsigned char *buf, unsigned int len) {
  FILE *frand = fopen("/dev/urandom", "r");
  if (!frand)
    return 0;
  // ruleid: raptor-unchecked-random-read
  size_t len_read = fread(buf, 1, len, frand);
  assert(len_read == len);
  fclose(frand);
  return 1;
}

// Netatalk uam.c uam_random_string
int uam_random_string(char *buf, int len) {
  int ret;
  int fd;
  if ((fd = open("/dev/urandom", O_RDONLY)) < 0)
    return -1;
  // ruleid: raptor-unchecked-random-read
  ret = read(fd, buf, len);
  close(fd);
  if (ret <= 0)
    return -1;
  return 0;
}

// Result discarded.
void seed(unsigned char key[32]) {
  int fd = open("/dev/random", O_RDONLY);
  // ruleid: raptor-unchecked-random-read
  read(fd, key, 32);
  close(fd);
  // ruleid: raptor-unchecked-random-read
  getentropy(key, 32);
  // ruleid: raptor-unchecked-random-read
  RAND_bytes(key, 32);
  use(key, 32);
}

// A device path behind a macro, a descriptor kept in a struct.
#define RANDOM_DEVICE "/dev/urandom"
struct rng { int fd; };
void rng_fill(struct rng *r, unsigned char *out, size_t n) {
  r->fd = open(RANDOM_DEVICE, O_RDONLY);
  // ruleid: raptor-unchecked-random-read
  if (read(r->fd, out, n) < 0)
    abort();
}

// --- complete checks ---

int fixed_rpcd(char *dest) {
  unsigned char buf[16];
  size_t ret;
  FILE *f = fopen("/dev/urandom", "r");
  if (!f)
    return -1;
  // ok: raptor-unchecked-random-read
  ret = fread(buf, 1, sizeof(buf), f);
  fclose(f);
  if (ret != sizeof(buf))
    return -1;
  use(buf, 16);
  return 0;
}

int fixed_direct(unsigned char *buf, size_t len) {
  int fd = open("/dev/urandom", O_RDONLY);
  // ok: raptor-unchecked-random-read
  if (read(fd, buf, len) != (ssize_t)len)
    return -1;
  return 0;
}

// Netatalk's fix: partial reads accumulated in a loop.
int fixed_loop(char *buf, int len) {
  int fd = open("/dev/urandom", O_RDONLY);
  int done = 0;
  while (done < len) {
    // ok: raptor-unchecked-random-read
    ssize_t r = read(fd, buf + done, len - done);
    if (r <= 0)
      return -1;
    done += r;
  }
  return 0;
}

// The result goes back to the caller.
ssize_t pass_up(unsigned char *buf, size_t n) {
  int fd = open("/dev/urandom", O_RDONLY);
  // ok: raptor-unchecked-random-read
  return read(fd, buf, n);
}

// All-or-nothing APIs only need some check.
int all_or_nothing(unsigned char key[32]) {
  // ok: raptor-unchecked-random-read
  if (getentropy(key, 32) != 0)
    return -1;
  // ok: raptor-unchecked-random-read
  if (RAND_bytes(key, 32) != 1)
    return -1;
  // ok: raptor-unchecked-random-read
  if (getrandom(key, 32, 0) < 0)
    return -1;
  return 0;
}

// OpenSSL ml_kem.c ossl_ml_kem_decap: a best-effort fill on a path that fails
// anyway; (void) says the result is ignored on purpose, as for
// raptor.IgnoredStatusReturn.
int decap_fail(unsigned char *shared_secret) {
  // ok: raptor-unchecked-random-read
  (void)RAND_bytes(shared_secret, 32);
  // ok: raptor-unchecked-random-read
  (void)getrandom(shared_secret, 32, 0);
  return 0;
}

// Not a random device.
int read_config(unsigned char *buf, size_t n) {
  int fd = open("/etc/app.conf", O_RDONLY);
  FILE *f = fopen("/etc/app.conf", "r");
  // ok: raptor-unchecked-random-read
  read(fd, buf, n);
  // ok: raptor-unchecked-random-read
  fread(buf, 1, n, f);
  return 0;
}

// FreeRADIUS 3.2.10 rlm_eap_fast eap_fast.c eap_fast_send_pac_tunnel (fixed in
// 708852c4a1): the project's own assertion macro is compiled out by NDEBUG
// (non-developer builds), so RAND_bytes never runs and the PAC-Opaque GCM IV
// stays all-zero.
#ifdef NDEBUG
#define rad_assert(expr) ((void)0)
#else
#define rad_assert(expr) assert(expr)
#endif
#define fr_assert(_x) rad_assert(_x)
int send_pac(void) {
  unsigned char iv[12];
  memset(iv, 0, sizeof(iv));
  // ruleid: raptor-unchecked-random-read
  rad_assert(RAND_bytes(iv, sizeof(iv)) != 0);
  use(iv, sizeof(iv));
  // ruleid: raptor-unchecked-random-read
  fr_assert(RAND_bytes(iv, sizeof(iv)) == 1);
  use(iv, sizeof(iv));
  return 0;
}

// An assertion on a value already checked is fine.
int send_pac_checked(void) {
  unsigned char iv[12];
  int ok = RAND_bytes(iv, sizeof(iv));
  // ok: raptor-unchecked-random-read
  if (ok != 1)
    return -1;
  rad_assert(ok == 1);
  use(iv, sizeof(iv));
  return 0;
}

// The same code built with -DNDEBUG: the assertion discards its argument, so
// the call is not even in the AST; found from the tokens.
#define nd_rad_assert(expr) ((void)0)
#define ND_ASSERT(x) do { } while (0)
int send_pac_ndebug(void) {
  unsigned char iv[12];
  memset(iv, 0, sizeof(iv));
  // ruleid: raptor-unchecked-random-read
  nd_rad_assert(RAND_bytes(iv, sizeof(iv)) != 0);
  use(iv, sizeof(iv));
  // ruleid: raptor-unchecked-random-read
  ND_ASSERT(getrandom(iv, sizeof(iv), 0) == sizeof(iv));
  use(iv, sizeof(iv));
  // ok: raptor-unchecked-random-read
  nd_rad_assert(iv[0] != 0 || RAND_status());
  return 0;
}
