#ifndef VARBUF_H
#define VARBUF_H

#define MAYBEUNUSED __attribute__((unused))

// -----------------------------------------------------------------------------
// Varbuffers. Support functions for read buffers...

#define VARBUF_CHUNK_SIZE 256

struct chunk {
  size_t length, used, read;
  struct chunk *prev, *next;
  uint8_t data[0];
};

static void MAYBEUNUSED
varbuf_init(struct varbuf *vb) {
  memset(vb, 0, sizeof(struct varbuf));
}

static void MAYBEUNUSED
varbuf_free(struct varbuf *vb) {
  struct chunk *c, *next;

  for (c = vb->head; c; c = next) {
    next = c->next;
    free(c);
  }
}

// -----------------------------------------------------------------------------
// Append @len bytes from @buffer to the end of @vb
// -----------------------------------------------------------------------------
static int MAYBEUNUSED
varbuf_copy_in(struct varbuf *vb, const uint8_t *buffer, size_t len) {
  off_t j = 0;

  if (vb->tail) {
    size_t remaining = vb->tail->length - vb->tail->used;
    if (remaining > len)
      remaining = len;

    memcpy(vb->tail->data + vb->tail->used, buffer, remaining);
    vb->tail->used += remaining;
    j += remaining;
    len -= remaining;
  }

  if (len) {
    size_t alloc = len;
    if (alloc < VARBUF_CHUNK_SIZE)
      alloc = VARBUF_CHUNK_SIZE;

    struct chunk *const chunk = malloc(sizeof(struct chunk) + alloc);
    if (!chunk) {
      errno = ENOMEM;
      return -1;
    }

    chunk->length = alloc;
    chunk->used = len;
    chunk->read = 0;
    chunk->next = NULL;
    chunk->prev = vb->tail;
    if (vb->tail) {
      vb->tail->next = chunk;
      vb->tail = chunk;
    } else {
      vb->tail = vb->head = chunk;
    }

    memcpy(chunk->data, buffer + j, len);
  }

  return 0;
}

// -----------------------------------------------------------------------------
// Copy, at most, @len bytes from @vb to @buffer
// -----------------------------------------------------------------------------
static size_t MAYBEUNUSED
varbuf_copy_out(uint8_t *buffer, size_t len, struct varbuf *vb) {
  struct chunk *c, *next;
  off_t j = 0;

  for (c = vb->head; c; c = next) {
    next = c->next;

    size_t todo = c->used - c->read;
    if (todo > len)
      todo = len;

    memcpy(buffer + j, c->data + c->read, todo);
    len -= todo;
    j += todo;
    c->read += todo;

    if (c->read == c->used) {
      free(c);
      vb->head = next;
      if (!next)
        vb->tail = NULL;
    }
  }

  return j;
}

// -----------------------------------------------------------------------------
// Copy everything from @c to the end of @vb. Special case of
// varbuf_copy_cursor, below.
// -----------------------------------------------------------------------------
static int MAYBEUNUSED
varbuf_copy_iovec_cursor(struct varbuf *vb, struct iovec_cursor *c) {
  while (!iovec_cursor_full(c)) {
    struct iovec iov;
    iovec_cursor_get(&iov, c, ULONG_MAX);
    if (varbuf_copy_in(vb, iov.iov_base, iov.iov_len) == -1)
      return 0;
  }

  return 1;
}

// -----------------------------------------------------------------------------
// Copy everything from @c to the end of @vb
// -----------------------------------------------------------------------------
static int MAYBEUNUSED
varbuf_copy_cursor(struct varbuf *vb, struct obstcp_cursor *c) {
  for (;;) {
    struct iovec iov;
    if (!c->get(c, &iov, ULONG_MAX))
      return 1;
    if (varbuf_copy_in(vb, iov.iov_base, iov.iov_len) == -1)
      return 0;
  }

  return 1;
}

// -----------------------------------------------------------------------------
// Discard, at most, @n bytes from a varbuf and return @n less the number of
// bytes actually discarded. (If the return value is > 0, then @vb is empty on
// exit.)
// -----------------------------------------------------------------------------
static size_t MAYBEUNUSED
varbuf_discard(struct varbuf *vb, size_t n) {
  struct chunk *c, *next;

  for (c = vb->head; c && n; c = next) {
    next = c->next;
    size_t todo = n;
    if (todo > c->used - c->read)
      todo = c->used - c->read;

    c->read += todo;
    n -= todo;

    if (c->read == c->used) {
      vb->head = next;
      if (!next)
        vb->tail = NULL;
      free(c);
    }
  }

  return n;
}

struct varbuf_cursor {
  struct obstcp_cursor c;
  struct chunk *chunk;
  size_t read;
  uint8_t *extra;
  size_t used;
};

static int MAYBEUNUSED
varbuf_cursor_get(void *arg, struct iovec *iov, size_t n) {
  struct varbuf_cursor *c = arg;

  if (c->chunk) {
    size_t todo = c->chunk->used - c->chunk->read;
    if (todo > n)
      todo = n;
    iov->iov_base = c->chunk->data + c->chunk->read;
    iov->iov_len = todo;

    c->chunk->read += todo;
    if (c->chunk->read == c->chunk->used)
      c->chunk = c->chunk->next;

    return 1;
  }

  if (c->used > c->read) {
    size_t todo = c->used - c->read;
    if (todo > n)
      todo = n;
    iov->iov_base = c->extra + c->read;
    iov->iov_len = todo;

    c->read += todo;

    return 1;
  }

  return 0;
}

static int MAYBEUNUSED
varbuf_cursor_fold(void *arg, int (*f) (void *, uint8_t *, size_t), void *ctx) {
  struct varbuf_cursor *c = arg;
  int r;

  const struct chunk *chunk = c->chunk;
  while (chunk) {
    r = f(ctx, (uint8_t *) chunk->data + c->chunk->read, chunk->used - c->chunk->read);
    if (r)
      return r;
    chunk = chunk->next;
  }

  if (c->used - c->read) {
    r = f(ctx, c->extra, c->used - c->read);
  } else {
    r = 0;
  }

  return r;
}

// -----------------------------------------------------------------------------
// Construct a generic cursor which walks a varbuf (don't modify it
// concurrently!) and, optionally, a single extra buffer.
// -----------------------------------------------------------------------------
static void MAYBEUNUSED
varbuf_cursor_init(struct varbuf_cursor *c, const struct varbuf *vb,
                   uint8_t *extra, size_t len) {
  c->c.get = varbuf_cursor_get;
  c->c.fold = varbuf_cursor_fold;
  c->chunk = vb->head;

  c->extra = extra;
  c->used = len;
  c->read = 0;
}

// -----------------------------------------------------------------------------

#undef MAYBEUNUSED

#endif  // VARBUF_H
