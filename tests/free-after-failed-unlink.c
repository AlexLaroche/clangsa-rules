// raptor.FreeAfterFailedUnlink: a function searches a list for an object to
// unlink it (`if (w == ctx) { *p = w->next; goto done; }`), and when the
// search fails it still frees the object. The object was not in that list
// because something else holds it, typically a loop that detached the list
// and is calling each entry, which then uses the freed object (CWE-416).
// Modelled on nginx CVE-2026-123634 (ngx_resolve_name_done and
// ngx_resolve_addr_done: "could not cancel %V resolving", then the context is
// freed while ngx_resolver_process_a() is still walking the detached waiting
// list).
#include <stddef.h>

typedef struct ctx_s ctx_t;
struct ctx_s {
  ctx_t *next;
  int state;
  void (*handler)(ctx_t *);
};
typedef struct {
  ctx_t *waiting;
} node_t;
void resolver_free(void *p);
void log_alert(const char *msg);

// nginx src/core/ngx_resolver.c
void resolve_name_done(ctx_t *ctx, node_t *rn) {
  ctx_t *w, **p;
  if (ctx->state == 1 && rn) {
    p = &rn->waiting;
    w = rn->waiting;
    while (w) {
      if (w == ctx) {
        *p = w->next;
        goto done;
      }
      p = &w->next;
      w = w->next;
    }
    log_alert("could not cancel resolving");
  }
done:
  // ruleid: raptor-free-after-failed-unlink
  resolver_free(ctx);
}

// The fix: defer the free to the loop that holds the context.
void free_handler(ctx_t *ctx) { resolver_free(ctx); }
void resolve_name_done_fixed(ctx_t *ctx, node_t *rn) {
  ctx_t *w, **p;
  if (ctx->state == 1 && rn) {
    p = &rn->waiting;
    w = rn->waiting;
    while (w) {
      if (w == ctx) {
        *p = w->next;
        goto done;
      }
      p = &w->next;
      w = w->next;
    }
    ctx->handler = free_handler;
  }
done:
  if (ctx->handler != free_handler) {
    // ok: raptor-free-after-failed-unlink
    resolver_free(ctx);
  }
}

// A for loop and a return from the found branch.
void cancel(ctx_t **head, ctx_t *c) {
  for (ctx_t **pp = head; *pp; pp = &(*pp)->next) {
    if (*pp == c) {
      *pp = c->next;
      resolver_free(c);
      return;
    }
  }
  // ruleid: raptor-free-after-failed-unlink
  resolver_free(c);
}

// Not this rule: not found returns, not found is an error, the object is not
// the one searched for, a search that does not unlink.
int cancel_or_fail(ctx_t **head, ctx_t *c) {
  for (ctx_t **pp = head; *pp; pp = &(*pp)->next) {
    if (*pp == c) {
      *pp = c->next;
      goto found;
    }
  }
  return -1;
found:
  // ok: raptor-free-after-failed-unlink
  resolver_free(c);
  return 0;
}
void cancel_other(ctx_t **head, ctx_t *c, ctx_t *spare) {
  for (ctx_t **pp = head; *pp; pp = &(*pp)->next) {
    if (*pp == c) {
      *pp = c->next;
      break;
    }
  }
  // ok: raptor-free-after-failed-unlink
  resolver_free(spare);
}
int contains(ctx_t *head, ctx_t *c) {
  for (ctx_t *w = head; w; w = w->next)
    if (w == c)
      return 1;
  // ok: raptor-free-after-failed-unlink
  resolver_free(c);
  return 0;
}
