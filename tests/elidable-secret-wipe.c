// raptor.ElidableSecretWipe: memset()/bzero() that zeroes a buffer nobody
// reads again, i.e. a wipe of a secret the optimizer may delete as a dead
// store (CWE-14): a local whose lifetime ends, or heap memory freed right
// after. Modelled on ell 33ed0af (TLS pre-master secret, PRF seed, PEM
// content, settings values), Netatalk 043435c (afppasswd DES key) and GDM
// e2ab745 (PAM response wiped then freed), all fixed with explicit_bzero().
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

void explicit_bzero(void *, size_t);
void l_free(void *);
void *l_malloc(size_t);
void use(const void *, size_t);
int fill(void *, size_t);
void generate_master_secret(void *, const unsigned char *, size_t);

struct tls { unsigned char key_block[64]; unsigned char master_secret[48]; };
struct setting { char *key; char *value; };
struct ctx { unsigned char k[32]; int rounds; };

// ell tls-suites.c tls_send_rsa_client_key_xchg
int send_key_xchg(void *tls) {
  unsigned char pre_master_secret[48];
  fill(pre_master_secret, 48);
  generate_master_secret(tls, pre_master_secret, 48);
  // ruleid: raptor-elidable-secret-wipe
  memset(pre_master_secret, 0, 48);
  return 1;
}

// ell tls.c l_tls_prf_get_bytes: the result does not depend on seed
int prf_get_bytes(void *buf, size_t len) {
  unsigned char seed[64];
  int r;
  fill(seed, sizeof(seed));
  r = fill(buf, len);
  // ruleid: raptor-elidable-secret-wipe
  memset(seed, 0, 64);
  return r;
}

// ell key.c l_key_generate_dh_private: heap copy wiped, then freed
void *generate_private(size_t private_bytes) {
  unsigned char *buf = l_malloc(private_bytes);
  void *private;
  fill(buf, private_bytes);
  private = l_malloc(8);
  use(buf, private_bytes);
  // ruleid: raptor-elidable-secret-wipe
  memset(buf, 0, private_bytes);
  l_free(buf);
  return private;
}

// ell settings.c setting_destroy, GDM gdm_session_worker_clear_pam_response
void setting_destroy(struct setting *pair) {
  l_free(pair->key);
  // ruleid: raptor-elidable-secret-wipe
  memset(pair->value, 0, strlen(pair->value));
  l_free(pair->value);
  l_free(pair);
}

// ell pem.c l_pem_load_private_key error path
int load_private_key(const char *name) {
  char *content = l_malloc(64);
  size_t len = 64;
  if (fill(content, len) < 0)
    goto err;
  return 0;
err:
  if (content) {
    // ruleid: raptor-elidable-secret-wipe
    memset(content, 0, len);
    l_free(content);
  }
  return -1;
}

// Netatalk afppasswd.c convert_passwd: the key dies with the block
void convert_passwd(int keyfd, char *newpwd) {
  if (keyfd > -1) {
    unsigned char key[16];
    fill(key, sizeof(key));
    use(key, 8);
    // ruleid: raptor-elidable-secret-wipe
    memset(key, '\0', sizeof(key));
    if (newpwd)
      use(newpwd, 8);
  }
}

// A whole context struct wiped and freed.
void ctx_free(struct ctx *c) {
  // ruleid: raptor-elidable-secret-wipe
  memset(c, 0, sizeof(*c));
  free(c);
}

// A member of a local struct, and bzero.
int local_struct(void) {
  struct ctx c;
  fill(&c, sizeof(c));
  use(c.k, 32);
  // ruleid: raptor-elidable-secret-wipe
  bzero(&c, sizeof(c));
  return 0;
}

// Wiped on the error path, which then returns: the later use is on another path.
int early_return(int fail) {
  unsigned char key[32];
  fill(key, 32);
  if (fail) {
    // ruleid: raptor-elidable-secret-wipe
    memset(key, 0, 32);
    return -1;
  }
  use(key, 32);
  return 0;
}

// --- not elidable, or not a wipe ---

// ell key.c l_key_extract: the caller's buffer outlives the call
int extract(void *payload, size_t *len) {
  // ok: raptor-elidable-secret-wipe
  memset(payload, 0, *len);
  return 0;
}

// ell tls.c tls_cleanup_handshake: memory the object keeps
void cleanup_handshake(struct tls *tls) {
  // ok: raptor-elidable-secret-wipe
  memset(tls->master_secret, 0, 48);
}

// Netatalk uams_dhx_pam.c: static storage stays visible
static unsigned char randbuf[16];
void wipe_static(void) {
  static unsigned char local_static[16];
  use(randbuf, 16);
  use(local_static, 16);
  // ok: raptor-elidable-secret-wipe
  memset(randbuf, 0, sizeof(randbuf));
  // ok: raptor-elidable-secret-wipe
  memset(local_static, 0, sizeof(local_static));
}

// Initialisation, not a wipe: nothing was stored before.
int init_then_use(void) {
  unsigned char buf[32];
  // ok: raptor-elidable-secret-wipe
  memset(buf, 0, sizeof(buf));
  return fill(buf, sizeof(buf));
}

// Netatalk afppasswd.c: the tail is cleared and the key is used afterwards.
void clear_tail(void) {
  unsigned char key[16];
  size_t j = 8;
  fill(key, 8);
  // ok: raptor-elidable-secret-wipe
  memset(key + j, 0, sizeof(key) - j);
  use(key, sizeof(key));
}

// Reused on the next iteration.
void loop_reuse(int n) {
  unsigned char block[16];
  for (int i = 0; i < n; i++) {
    fill(block, 16);
    use(block, 16);
    // ok: raptor-elidable-secret-wipe
    memset(block, 0, 16);
  }
}

// The fix: explicit_bzero cannot be removed.
void fixed(void) {
  unsigned char key[16];
  fill(key, 16);
  use(key, 16);
  // ok: raptor-elidable-secret-wipe
  explicit_bzero(key, 16);
}

// Heap memory that is kept, returned, or read before being freed.
unsigned char *keep_heap(size_t n) {
  unsigned char *p = malloc(n);
  fill(p, n);
  // ok: raptor-elidable-secret-wipe
  memset(p, 0, n);
  return p;
}

void read_before_free(unsigned char *p, size_t n) {
  fill(p, n);
  // ok: raptor-elidable-secret-wipe
  memset(p, 0, n / 2);
  use(p, n);
  free(p);
}

void frees_something_else(unsigned char *p, unsigned char *q, size_t n) {
  fill(p, n);
  // ok: raptor-elidable-secret-wipe
  memset(p, 0, n);
  free(q);
}

// A non-zero fill is a pattern, not a wipe.
void poison(void) {
  unsigned char buf[16];
  fill(buf, 16);
  use(buf, 16);
  // ok: raptor-elidable-secret-wipe
  memset(buf, 0xaa, sizeof(buf));
}

// sizeof after the wipe is not a read.
size_t sizeof_after(void) {
  unsigned char key[16];
  fill(key, 16);
  use(key, 16);
  // ruleid: raptor-elidable-secret-wipe
  memset(key, 0, sizeof(key));
  return sizeof(key);
}

// nginx ngx_udp_sendmsg_chain.c: the buffer is read later through a pointer
// stored in another local (msg.msg_control) before the memset.
struct msghdr_ { void *msg_control; size_t msg_controllen; };
int sendmsg_(int, struct msghdr_ *);
int send_cmsg(int fd) {
  struct msghdr_ msg;
  unsigned char msg_control[64];
  msg.msg_control = msg_control;
  msg.msg_controllen = sizeof(msg_control);
  // ok: raptor-elidable-secret-wipe
  memset(msg_control, 0, sizeof(msg_control));
  return sendmsg_(fd, &msg);
}

// openssh bindresvport.c: read later through `sa = &myaddr`.
struct sockaddr_ { unsigned short sa_family; char sa_data[14]; };
struct sockaddr_storage_ { unsigned short ss_family; char pad[126]; };
int getsockname_(int, struct sockaddr_ *, unsigned *);
int bindresvport_(int sd, struct sockaddr_ *sa) {
  struct sockaddr_storage_ myaddr;
  unsigned salen;
  if (sa == NULL) {
    memset(&myaddr, 0, sizeof(myaddr));
    sa = (struct sockaddr_ *)&myaddr;
    salen = sizeof(myaddr);
    if (getsockname_(sd, sa, &salen) == -1)
      return -1;
    // ok: raptor-elidable-secret-wipe
    memset(&myaddr, 0, salen);
  }
  return sa->sa_family;
}

// openvpn manage.c CLEAR(parms): an array of pointers holds no secret bytes.
#define CLEAR(x) memset(&(x), 0, sizeof(x))
void dispatch(void) {
  char *parms[8];
  fill(parms, sizeof(parms));
  use(parms, 8);
  // ok: raptor-elidable-secret-wipe
  CLEAR(parms);
}

// openssh packet.c: a queue node of pointers and a type byte, wiped then freed.
struct sshbuf;
struct packet { struct packet *next; unsigned char type; struct sshbuf *payload; };
void dequeue(struct packet *p) {
  // ok: raptor-elidable-secret-wipe
  memset(p, 0, sizeof(*p));
  free(p);
}

// The same macro on a key is reported, with the name in the message.
void clear_key(void) {
  unsigned char key[32];
  fill(key, sizeof(key));
  use(key, 32);
  // ruleid: raptor-elidable-secret-wipe
  CLEAR(key);
}

// OpenSSL bio_dgram_test.c: aliased through an array element's field.
struct dgram_msg { void *data; size_t data_len; };
int recvmmsg_(struct dgram_msg *, size_t);
int receive(void) {
  struct dgram_msg rx_msg[2];
  unsigned char rx_buf2[64];
  rx_msg[1].data = rx_buf2;
  rx_msg[1].data_len = sizeof(rx_buf2);
  // ok: raptor-elidable-secret-wipe
  memset(rx_buf2, 0, sizeof(rx_buf2));
  return recvmmsg_(rx_msg, 2);
}

// wolfSSL internal.c: aliased through ?:, and only sizeof() came before.
void consume(const unsigned char *, size_t);
void bad_pad(void *ssl, int big) {
  unsigned char dmy[32];
  unsigned char *dummy = big ? (unsigned char *)ssl : dmy;
  // ok: raptor-elidable-secret-wipe
  memset(dmy, 0, sizeof(dmy));
  consume(dummy, 32);
}

// Only sizeof() before the memset: it initialises, it does not wipe.
size_t init_after_sizeof(void) {
  unsigned char buf[16];
  size_t n = sizeof(buf);
  // ok: raptor-elidable-secret-wipe
  memset(buf, 0, sizeof(buf));
  return n;
}

// Released by a function of a shared library, declared in a system header
// (talloc): an opaque call that may read the bytes, so the wipe stays
// (FreeRADIUS mppe_keys.c, rlm_eap_fast.c). libc free() is still a release.
# 1 "/usr/include/talloc.h" 1 3
void *_talloc_zero(const void *ctx, size_t size, const char *name);
int _talloc_free(void *ptr, const char *location);
# 333 "elidable-secret-wipe.c" 2
#define talloc_free(p) _talloc_free(p, __FILE__)
void derive_key(unsigned char *out) {
  unsigned char *buf = _talloc_zero(NULL, 64, "buf");
  consume(buf, 64);
  memcpy(out, buf, 32);
  // ok: raptor-elidable-secret-wipe
  memset(buf, 0, 64);
  talloc_free(buf);
}
void derive_key_libc(unsigned char *out) {
  unsigned char *buf = malloc(64);
  consume(buf, 64);
  memcpy(out, buf, 32);
  // ruleid: raptor-elidable-secret-wipe
  memset(buf, 0, 64);
  free(buf);
}

// The buffer's address is stored in a struct initialiser, and the struct is
// passed on: the memset initialises memory read later (FreeRADIUS trie.c
// fr_trie_walk).
struct walk_cb { unsigned char *start, *end; void *ctx; };
int walk(struct walk_cb *cb);
int trie_walk(void *ctx) {
  unsigned char buffer[65];
  struct walk_cb my_cb = {
    .start = buffer,
    .end = buffer + sizeof(buffer),
    .ctx = ctx,
  };
  // ok: raptor-elidable-secret-wipe
  memset(buffer, 0, sizeof(buffer));
  return walk(&my_cb);
}
