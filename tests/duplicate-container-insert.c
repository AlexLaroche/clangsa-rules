// raptor.DuplicateContainerInsert: an existing object is added to a
// long-lived container from several places, and an add site does not check
// that the object is not already there. A state test is not a membership
// test: when two event paths both decide to add, the object is in the
// container twice and whoever drains it releases it twice.
#include <stddef.h>
#include <stdlib.h>

/* ---- APR-like array (httpd mod_http2, CVE-2026-23918) ---- */
typedef struct {
  int nelts;
  char *elts;
} array_t;
void *array_push(array_t *a);
#define ARRAY_PUSH(a, T) (*((T *)array_push(a)))
#define ARRAY_IDX(a, i, T) (((T *)(a)->elts)[i])

typedef struct stream {
  int id;
  int state;
  void *c2;
} stream_t;

typedef struct mplx {
  array_t *spurge;
  array_t *shold;
} mplx_t;

void stream_destroy(stream_t *s);
int stream_is_running(stream_t *s);

void purge_streams(mplx_t *m) {
  for (int i = 0; i < m->spurge->nelts; ++i)
    stream_destroy(ARRAY_IDX(m->spurge, i, stream_t *));
  m->spurge->nelts = 0;
}

void stream_joined(mplx_t *m, stream_t *stream) {
  // ruleid: raptor-duplicate-container-insert
  ARRAY_PUSH(m->spurge, stream_t *) = stream;
}

void stream_cleanup(mplx_t *m, stream_t *stream) {
  if (stream_is_running(stream)) {
    if (stream->c2) {
      // ruleid: raptor-duplicate-container-insert
      ARRAY_PUSH(m->spurge, stream_t *) = stream;
    }
  } else {
    // ruleid: raptor-duplicate-container-insert
    ARRAY_PUSH(m->spurge, stream_t *) = stream;
  }
}

/* The fix: every add goes through a helper that looks for the object. */
typedef struct mplx2 {
  array_t *spurge;
} mplx2_t;

static int add_for_purge(mplx2_t *m, stream_t *stream) {
  for (int i = 0; i < m->spurge->nelts; ++i) {
    stream_t *s = ARRAY_IDX(m->spurge, i, stream_t *);
    if (s == stream)
      return 0;
  }
  // ok: raptor-duplicate-container-insert
  ARRAY_PUSH(m->spurge, stream_t *) = stream;
  return 1;
}

void stream_joined2(mplx2_t *m, stream_t *stream) { add_for_purge(m, stream); }
void stream_cleanup2(mplx2_t *m, stream_t *stream) {
  /* Calls to the checked helper are not add sites themselves. */
  if (stream_is_running(stream)) {
    // ok: raptor-duplicate-container-insert
    add_for_purge(m, stream);
  } else {
    // ok: raptor-duplicate-container-insert
    add_for_purge(m, stream);
  }
}

/* ---- Tor-like smartlist priority queue (CVE-2018-0491) ---- */
typedef struct smartlist_t smartlist_t;
typedef struct channel {
  int scheduler_state;
  int sched_heap_idx;
} channel_t;
void smartlist_pqueue_add(smartlist_t *sl, int (*cmp)(const void *, const void *),
                          size_t idx_off, void *item);
void *smartlist_pqueue_pop(smartlist_t *sl, int (*cmp)(const void *, const void *),
                           size_t idx_off);
void smartlist_pqueue_remove(smartlist_t *sl, int (*cmp)(const void *, const void *),
                             size_t idx_off, void *item);
int smartlist_contains(const smartlist_t *sl, const void *item);
void smartlist_add(smartlist_t *sl, void *item);
smartlist_t *smartlist_new(void);
int compare_channels(const void *a, const void *b);
enum { SCHED_IDLE, SCHED_WAITING_FOR_CELLS, SCHED_WAITING_TO_WRITE, SCHED_PENDING };

static smartlist_t *channels_pending;

void channel_has_waiting_cells(channel_t *chan) {
  if (chan->scheduler_state == SCHED_WAITING_FOR_CELLS) {
    chan->scheduler_state = SCHED_PENDING;
    // ruleid: raptor-duplicate-container-insert
    smartlist_pqueue_add(channels_pending, compare_channels,
                         offsetof(channel_t, sched_heap_idx), chan);
  }
}

void channel_wants_writes(channel_t *chan) {
  if (chan->scheduler_state == SCHED_WAITING_TO_WRITE) {
    // ruleid: raptor-duplicate-container-insert
    smartlist_pqueue_add(channels_pending, compare_channels,
                         offsetof(channel_t, sched_heap_idx), chan);
    chan->scheduler_state = SCHED_PENDING;
  }
}

/* The fix: the queue keeps the position in sched_heap_idx; test it. */
static smartlist_t *channels_pending2;

void channel_has_waiting_cells2(channel_t *chan) {
  if (chan->scheduler_state == SCHED_WAITING_FOR_CELLS && chan->sched_heap_idx == -1) {
    // ok: raptor-duplicate-container-insert
    smartlist_pqueue_add(channels_pending2, compare_channels,
                         offsetof(channel_t, sched_heap_idx), chan);
  }
}

void channel_wants_writes2(channel_t *chan) {
  if (chan->sched_heap_idx != -1)
    return;
  // ok: raptor-duplicate-container-insert
  smartlist_pqueue_add(channels_pending2, compare_channels,
                       offsetof(channel_t, sched_heap_idx), chan);
}

/* Removed first, or popped from the same container: not in it any more. */
void channel_touch(channel_t *chan) {
  smartlist_pqueue_remove(channels_pending2, compare_channels,
                          offsetof(channel_t, sched_heap_idx), chan);
  // ok: raptor-duplicate-container-insert
  smartlist_pqueue_add(channels_pending2, compare_channels,
                       offsetof(channel_t, sched_heap_idx), chan);
}

void scheduler_run(void) {
  smartlist_t *cp = channels_pending2;
  smartlist_t *to_readd = NULL;
  channel_t *chan;
  while ((chan = smartlist_pqueue_pop(cp, compare_channels,
                                      offsetof(channel_t, sched_heap_idx)))) {
    if (chan->scheduler_state == SCHED_WAITING_TO_WRITE) {
      if (!to_readd)
        to_readd = smartlist_new();
      // ok: raptor-duplicate-container-insert
      smartlist_add(to_readd, chan);
    } else {
      // ok: raptor-duplicate-container-insert
      smartlist_pqueue_add(cp, compare_channels, offsetof(channel_t, sched_heap_idx), chan);
    }
  }
  /* Explicit membership query. */
  channel_t *readd_chan = chan;
  if (!smartlist_contains(cp, readd_chan)) {
    // ok: raptor-duplicate-container-insert
    smartlist_pqueue_add(cp, compare_channels, offsetof(channel_t, sched_heap_idx), readd_chan);
  }
}

/* ---- Shapes that must stay quiet ---- */
typedef struct node {
  int v;
} node_t;
typedef struct registry {
  smartlist_t *nodes;
  smartlist_t *names;
  smartlist_t *ids;
} registry_t;
node_t *node_new(int v);
void hashtable_add(smartlist_t *h, void *item);

/* A fresh object cannot be in the container yet. */
void registry_add_new(registry_t *r, int v) {
  node_t *n = node_new(v);
  // ok: raptor-duplicate-container-insert
  smartlist_add(r->nodes, n);
}
void registry_add_alloc(registry_t *r) {
  node_t *n = malloc(sizeof *n);
  // ok: raptor-duplicate-container-insert
  smartlist_add(r->nodes, n);
}

/* Strings are not objects that get released through the container. */
void registry_name1(registry_t *r, char *name) {
  // ok: raptor-duplicate-container-insert
  smartlist_add(r->names, name);
}
void registry_name2(registry_t *r, char *name) {
  // ok: raptor-duplicate-container-insert
  smartlist_add(r->names, name);
}

/* One add site only: nothing to race with. */
void registry_only(registry_t *r, node_t *n) {
  // ok: raptor-duplicate-container-insert
  smartlist_add(r->ids, n);
}

/* Keyed containers replace an entry instead of duplicating it. */
void registry_hash1(registry_t *r, node_t *n) {
  // ok: raptor-duplicate-container-insert
  hashtable_add(r->nodes, n);
}
void registry_hash2(registry_t *r, node_t *n) {
  // ok: raptor-duplicate-container-insert
  hashtable_add(r->nodes, n);
}

/* Typed APIs with an add/push name are not generic containers: the object
 * is a typed argument, not a void * slot (httpd noise: dav_push_error,
 * ap_add_output_filter, apr_pollset_add, X509_STORE_add_cert). */
typedef struct pool pool_t;
typedef struct error { int status; } error_t;
error_t *err_push(pool_t *p, int status, error_t *prev);
void filter_add(const char *name, void *ctx, node_t *r);
static const char *filter_name;

error_t *dav_like1(pool_t *pool, error_t *err) {
  // ok: raptor-duplicate-container-insert
  return err_push(pool, 500, err);
}
error_t *dav_like2(pool_t *pool, error_t *err) {
  // ok: raptor-duplicate-container-insert
  return err_push(pool, 404, err);
}
void filter_like1(node_t *r) {
  // ok: raptor-duplicate-container-insert
  filter_add(filter_name, 0, r);
}
void filter_like2(node_t *r) {
  // ok: raptor-duplicate-container-insert
  filter_add(filter_name, 0, r);
}

/* A void * context that is not the last argument is not an item being
 * stored (httpd noise: ap_add_output_filter_handle(handle, ctx, r, c)). */
typedef struct filter_rec filter_rec_t;
typedef struct cache_ctx { int n; } cache_ctx_t;
void add_output_filter_handle(filter_rec_t *h, void *ctx, node_t *r, void *c);
static filter_rec_t *invalidate_handle;
void cache_like1(cache_ctx_t *cache, node_t *r) {
  // ok: raptor-duplicate-container-insert
  add_output_filter_handle(invalidate_handle, cache, r, 0);
}
void cache_like2(cache_ctx_t *cache, node_t *r) {
  // ok: raptor-duplicate-container-insert
  add_output_filter_handle(invalidate_handle, cache, r, 0);
}

/* (callback, argument) convention: the void * right after a function pointer
 * is the callback's argument, not a stored item (bind9 noise:
 * isc_work_enqueue(loop, lane, cb, done_cb, cbarg)). */
typedef struct loop loop_t;
typedef void (*work_cb)(void *);
void work_enqueue(loop_t *loop, int lane, work_cb cb, work_cb done_cb, void *cbarg);
void apply(void *);
void apply_done(void *);
typedef struct xfr { loop_t *loop; } xfr_t;
void xfr_like1(xfr_t *xfr) {
  // ok: raptor-duplicate-container-insert
  work_enqueue(xfr->loop, 1, apply, apply_done, xfr);
}
void xfr_like2(xfr_t *xfr) {
  // ok: raptor-duplicate-container-insert
  work_enqueue(xfr->loop, 1, apply, apply_done, xfr);
}
