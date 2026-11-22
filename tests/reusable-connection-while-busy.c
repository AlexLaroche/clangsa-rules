// raptor.ReusableConnectionWhileBusy: nginx marks an idle connection
// reusable (ngx_reusable_connection(c, 1)) so that ngx_drain_connections()
// may close it when ngx_get_connection() runs short of free slots. Work
// started on a connection that is still marked reusable, or registered only
// after a call that can drain, lets the drain free the connection while a
// request uses it (CWE-416).
//   - a function increments the busy counter that the idle check tests
//     before marking the connection reusable (`if (h2c->processing)
//     return; ... ngx_reusable_connection(c, 1)`) and never clears the mark:
//     nginx CVE-2026-123633 (ngx_http_v2_create_stream: `h2c->processing++`
//     with the connection left reusable while a HEADERS frame was
//     incomplete);
//   - a function clears the mark, then calls ngx_get_connection() (which can
//     drain and close an idle stream of the same connection, whose close
//     handler re-marks it reusable since the new stream is not visible yet)
//     before inserting the new stream: nginx CVE-2026-121810
//     (ngx_quic_create_stream).
#include <stddef.h>

typedef struct ngx_connection_s ngx_connection_t;
struct ngx_connection_s {
  unsigned reusable : 1;
  int fd;
};
void ngx_reusable_connection(ngx_connection_t *c, unsigned reusable);
ngx_connection_t *ngx_get_connection(int s, void *log);
typedef struct {
  int dummy;
} ngx_rbtree_t;
typedef struct {
  int dummy;
} ngx_rbtree_node_t;
void ngx_rbtree_insert(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);

// --- HTTP/2 (src/http/v2/ngx_http_v2.c) ---
typedef struct {
  ngx_connection_t *connection;
  unsigned processing;
  unsigned last_out;
} h2_conn_t;

void h2_handle_connection(h2_conn_t *h2c) {
  if (h2c->last_out || h2c->processing)
    return;
  ngx_reusable_connection(h2c->connection, 1);
}

int h2_create_stream(h2_conn_t *h2c) {
  // ruleid: raptor-reusable-connection-while-busy
  h2c->processing++;
  return 0;
}

// The fix.
int h2_create_stream_fixed(h2_conn_t *h2c) {
  // ok: raptor-reusable-connection-while-busy
  h2c->processing++;
  ngx_reusable_connection(h2c->connection, 0);
  return 0;
}

// The decrement is the end of the work, not its start.
void h2_close_stream(h2_conn_t *h2c) {
  // ok: raptor-reusable-connection-while-busy
  h2c->processing--;
  h2_handle_connection(h2c);
}

// --- QUIC (src/event/quic/ngx_event_quic_streams.c) ---
typedef struct {
  ngx_rbtree_t tree;
} quic_conn_t;
typedef struct {
  ngx_rbtree_node_t node;
} quic_stream_t;

quic_stream_t *quic_create_stream(ngx_connection_t *c, quic_conn_t *qc, quic_stream_t *qs) {
  unsigned reusable = c->reusable;
  ngx_reusable_connection(c, 0);
  // ruleid: raptor-reusable-connection-while-busy
  ngx_connection_t *sc = ngx_get_connection(c->fd, NULL);
  if (sc == NULL) {
    ngx_reusable_connection(c, reusable);
    return NULL;
  }
  ngx_rbtree_insert(&qc->tree, &qs->node);
  return qs;
}

// The fix: the stream is in the tree before ngx_get_connection() can drain.
quic_stream_t *quic_create_stream_fixed(ngx_connection_t *c, quic_conn_t *qc, quic_stream_t *qs) {
  ngx_rbtree_insert(&qc->tree, &qs->node);
  unsigned reusable = c->reusable;
  ngx_reusable_connection(c, 0);
  // ok: raptor-reusable-connection-while-busy
  ngx_connection_t *sc = ngx_get_connection(c->fd, NULL);
  if (sc == NULL) {
    ngx_reusable_connection(c, reusable);
    return NULL;
  }
  return qs;
}

// Not this rule: a connection accepted with ngx_get_connection() and
// nothing registered after it.
ngx_connection_t *accept_one(int fd) {
  // ok: raptor-reusable-connection-while-busy
  ngx_connection_t *c = ngx_get_connection(fd, NULL);
  ngx_reusable_connection(c, 1);
  return c;
}
