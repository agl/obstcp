#ifndef CURSOR_H
#define CURSOR_H

#define MAYBEUNUSED __attribute__((unused))

// -----------------------------------------------------------------------------
// Utility functions for dealing with generic cursors (obstcp_cursor)...

struct cursor_memchr_state {
  char b;
  size_t current_offset;
  size_t result;
};

static int MAYBEUNUSED
cursor_memchr_f(void *arg, uint8_t *data, size_t len) {
  struct cursor_memchr_state *s = arg;

  void *const p = memchr(data, s->b, len);
  if (!p) {
    s->current_offset += len;
    return 0;
  } else {
    s->result = (p - (void *) data) + s->current_offset;
    return 1;
  }
}

// -----------------------------------------------------------------------------
// Return the offset of the first byte with value @b in the cursor, without
// changing the current location of the cursor. Return -1 if @b was not found.
// -----------------------------------------------------------------------------
static ssize_t MAYBEUNUSED
cursor_memchr(struct obstcp_cursor *c, char b) {
  struct cursor_memchr_state s;
  s.b = b;
  s.current_offset = 0;

  if (c->fold(c, cursor_memchr_f, &s))
    return s.result;

  return -1;
}

struct cursor_has_state {
  size_t n;
  size_t found;
};

static int MAYBEUNUSED
cursor_has_f(void *arg, uint8_t *data, size_t len) {
  struct cursor_has_state *s = arg;
  s->found += len;

  return s->found >= s->n;
}

// -----------------------------------------------------------------------------
// Return true iff the cursor has, at least, @n bytes ready to read
// -----------------------------------------------------------------------------
static int MAYBEUNUSED
cursor_has(struct obstcp_cursor *c, size_t n) {
  struct cursor_has_state s;
  s.n = n;
  s.found = 0;

  c->fold(c, cursor_has_f, &s);
  return s.found >= n;
}

// -----------------------------------------------------------------------------
// See iovec_cursor_read. This assumes that enough bytes are availible
// -----------------------------------------------------------------------------
static const uint8_t * MAYBEUNUSED
cursor_read(uint8_t *buffer, struct obstcp_cursor *c, size_t n) {
  struct iovec iov;

  if (!c->get(c, &iov, n))
    abort();

  if (iov.iov_len == n)
    return (const uint8_t *) iov.iov_base;

  size_t j = 0;
  while (n) {
    memcpy(buffer + j, iov.iov_base, iov.iov_len);
    n -= iov.iov_len;
    j += iov.iov_len;
    if (!c->get(c, &iov, n))
      abort();
  }

  return buffer;
}

// -----------------------------------------------------------------------------
// A cursor join is just the concatenation of two cursors...
// -----------------------------------------------------------------------------
struct cursor_join {
  struct obstcp_cursor c;
  struct obstcp_cursor *a, *b;
};

static int MAYBEUNUSED
cursor_join_get(void *arg, struct iovec *iov, size_t n) {
  struct cursor_join *j = arg;

  if (j->a) {
    if (j->a->get(j->a, iov, n))
      return 1;
  }

  j->a = NULL;
  return j->b->get(j->b, iov, n);
}

static int MAYBEUNUSED
cursor_join_fold(void *arg, int (*f) (void *, uint8_t *, size_t), void *ctx) {
  struct cursor_join *j = arg;

  if (j->a) {
    int r = j->a->fold(j->a, f, ctx);
    if (r)
      return r;
  }

  return j->b->fold(j->b, f, ctx);
}

static void MAYBEUNUSED
cursor_join_init(struct cursor_join *j,
                 struct obstcp_cursor *a, struct obstcp_cursor *b) {
  j->c.get = cursor_join_get;
  j->c.fold = cursor_join_fold;
  j->a = a;
  j->b = b;
}

static void MAYBEUNUSED
cursor_join_discard_first(struct cursor_join *j) {
  j->a = NULL;
}

// -----------------------------------------------------------------------------

#undef MAYBEUNUSED
#endif  // CURSOR_H
