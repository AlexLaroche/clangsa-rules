// raptor.UncappedCreditReplenish: a credit/window counter that the code
// spends (`c->window -= n`) is topped up elsewhere with a variable amount
// (`c->window += n`) and nothing in that function bounds the result. The
// counter can grow past the size the rest of the code assumes it never
// exceeds (`MAX - window` in a guard, `credits - fifo->count` as the room in
// a buffer), and the arithmetic that relies on that bound wraps.
#include <stddef.h>
#include <sys/types.h>

#define MAX_WINDOW ((1U << 31) - 1)
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* ---- nginx HTTP/2 connection window (CVE-2026-123007) ---- */
typedef struct {
  size_t send_window;
  size_t send_queued;
  size_t recv_window;
  size_t bytes_sent;
} h2c_t;

void queue_frame(h2c_t *h2c, size_t n);

void send_chain(h2c_t *h2c, size_t frame_size) {
  queue_frame(h2c, frame_size);
  h2c->send_window -= frame_size;
  h2c->bytes_sent += frame_size;
}

void filter_cleanup(h2c_t *h2c, size_t window) {
  if (h2c->send_window == 0 && window) {
    queue_frame(h2c, 0);
  }
  // ruleid: raptor-uncapped-credit-replenish
  h2c->send_window += window;
}

int state_window_update(h2c_t *h2c, size_t window) {
  if (window > MAX_WINDOW - h2c->send_window) {
    return -1;
  }
  // ok: raptor-uncapped-credit-replenish
  h2c->send_window += window;
  return 0;
}

/* the fix: the refund moves credit back from the queued counter, which the
   WINDOW_UPDATE check accounts for */
void send_chain_fixed(h2c_t *h2c, size_t frame_size) {
  queue_frame(h2c, frame_size);
  h2c->send_window -= frame_size;
  // ok: raptor-uncapped-credit-replenish
  h2c->send_queued += frame_size;
}

void frame_sent(h2c_t *h2c, size_t len) {
  h2c->send_queued -= len;
}

void filter_cleanup_fixed(h2c_t *h2c, size_t window) {
  // ok: raptor-uncapped-credit-replenish
  h2c->send_window += window;
  h2c->send_queued -= window;
}

/* a statistic that is only ever added to is not a credit */
void count_sent(h2c_t *h2c, size_t n) {
  // ok: raptor-uncapped-credit-replenish
  h2c->bytes_sent += n;
}

/* ---- Linux io_edgeport transmit credits (CVE-2026-68365) ---- */
struct edgeport_port {
  unsigned short txCredits;
  unsigned short maxTxCredits;
  int open;
};

int submit(struct edgeport_port *p, int count);

void edge_interrupt_callback(struct edgeport_port *edge_port, const unsigned char *data) {
  int txCredits = data[0] | (data[1] << 8);
  if (txCredits && edge_port->open) {
    // ruleid: raptor-uncapped-credit-replenish
    edge_port->txCredits += txCredits;
  }
}

void edge_interrupt_callback_fixed(struct edgeport_port *edge_port, const unsigned char *data) {
  int txCredits = data[0] | (data[1] << 8);
  if (txCredits && edge_port->open) {
    // ok: raptor-uncapped-credit-replenish
    edge_port->txCredits = MIN(edge_port->txCredits + txCredits, edge_port->maxTxCredits);
  }
}

void send_more(struct edgeport_port *edge_port, int count) {
  edge_port->txCredits -= count;
  if (submit(edge_port, count) < 0) {
    /* give back what this function just took */
    // ok: raptor-uncapped-credit-replenish
    edge_port->txCredits += count;
  }
}

/* ---- other shapes ---- */
struct credit {
  int credits;
  int limit;
};

void spend(struct credit *c, int n) { c->credits = c->credits - n; }

void grant_plain(struct credit *c, int n) {
  // ruleid: raptor-uncapped-credit-replenish
  c->credits = c->credits + n;
}

void grant_one(struct credit *c) {
  // ok: raptor-uncapped-credit-replenish
  c->credits += 1;
}

void grant_then_clamp(struct credit *c, int n) {
  // ok: raptor-uncapped-credit-replenish
  c->credits += n;
  if (c->credits > c->limit)
    c->credits = c->limit;
}

void grant_checked(struct credit *c, int n) {
  if (c->credits + n > c->limit)
    return;
  // ok: raptor-uncapped-credit-replenish
  c->credits += n;
}

void local_counter(int n) {
  int credits = 0;
  credits -= 1;
  // ok: raptor-uncapped-credit-replenish
  credits += n;
  (void)credits;
}

/* ---- noise seen on nginx: lengths and totals are not credits ---- */
struct chain_len {
  size_t len;
  size_t total;
};

void chain_trim(struct chain_len *c, size_t n) { c->len -= n; c->total -= n; }

void chain_add(struct chain_len *c, size_t n) {
  // ok: raptor-uncapped-credit-replenish
  c->len += n;
  // ok: raptor-uncapped-credit-replenish
  c->total = c->total + n;
}

/* the amount is the room left below the maximum (nginx recv_window) */
typedef struct {
  size_t recv_window;
} stream_t;

void consume_recv(stream_t *s, size_t n) { s->recv_window -= n; }

void refill_recv(stream_t *s, int no_buffering, size_t len) {
  size_t size;
  if (no_buffering)
    size = len;
  else
    size = MAX_WINDOW - s->recv_window;
  // ok: raptor-uncapped-credit-replenish
  s->recv_window += size;
}

/* other credit names */
struct conn {
  unsigned peer_quota;
  unsigned tx_budget;
};

void use_quota(struct conn *c, unsigned n) { c->peer_quota -= n; c->tx_budget--; }

void on_grant(struct conn *c, unsigned grant) {
  // ruleid: raptor-uncapped-credit-replenish
  c->peer_quota += grant;
  // ruleid: raptor-uncapped-credit-replenish
  c->tx_budget += grant;
}
