#ifndef IOVEC_CURSOR
#define IOVEC_CURSOR

#include <stdio.h>

#define MAYBEUNUSED __attribute__((unused))

// -----------------------------------------------------------------------------
// Utility functions for dealing with iovec arrays...

struct iovec_cursor {
  struct obstcp_cursor c;
  struct iovec *iov;  // pointer to the iovecs
  unsigned count;     // number of iovecs
  unsigned i;         // current iovec
  size_t j;           // offset into current iovec
};

static int MAYBEUNUSED
iovec_cursor_get_(void *arg, struct iovec *iov, size_t n) {
  struct iovec_cursor *c = arg;

  if (c->i == c->count)
    return 0;

  size_t todo = c->iov[c->i].iov_len - c->j;
  if (todo > n)
    todo = n;

  iov->iov_base = c->iov[c->i].iov_base + c->j;
  iov->iov_len = todo;

  c->j += todo;
  if (c->j == c->iov[c->i].iov_len) {
    c->j = 0;
    c->i++;
  }

  return 1;
}

static int MAYBEUNUSED
iovec_cursor_fold(void *arg, int (*f) (void *, uint8_t *, size_t len), void *ctx) {
  struct iovec_cursor *c = arg;
  int r;
  unsigned i;

  for (i = c->i; i < c->count; ++i) {
    if (i == c->i) {
      r = f(ctx, c->iov[i].iov_base + c->j, c->iov[i].iov_len - c->j);
    } else {
      r = f(ctx, c->iov[i].iov_base, c->iov[i].iov_len);
    }

    if (r)
      return r;
  }

  return 0;
}

static void MAYBEUNUSED
iovec_cursor_init(struct iovec_cursor *c,
                  struct iovec *iov, unsigned count) {
  c->c.get = iovec_cursor_get_;
  c->c.fold = iovec_cursor_fold;
  c->iov = iov;
  c->count = count;
  c->i = 0;
  c->j = 0;
}

// -----------------------------------------------------------------------------
// Return true iff the cursor is 'full' (i.e. at the end of the iovec array)
// -----------------------------------------------------------------------------
static char MAYBEUNUSED
iovec_cursor_full(struct iovec_cursor *c) {
  return c->i == c->count;
};

// -----------------------------------------------------------------------------
// Append a vector to the array. This assumes that !iovec_cursor_full(c)
// -----------------------------------------------------------------------------
static void MAYBEUNUSED
iovec_cursor_append(struct iovec_cursor *c, const void *a, size_t len) {
  c->iov[c->i].iov_base = (void *) a;
  c->iov[c->i++].iov_len = len;
};

// -----------------------------------------------------------------------------
// Find the first occurance of @byte in the data from the current cursor
// position onwards. If @byte is found, return it's index from the current
// cursor location. Otherwise, return -1
// -----------------------------------------------------------------------------
static ssize_t MAYBEUNUSED
iovec_cursor_memchr(const struct iovec_cursor *c, char byte) {
  unsigned i;
  size_t scanned = 0, j = c->j;

  for (i = c->i; i < c->count; ++i) {
    const void *a = memchr(c->iov[i].iov_base + j, byte, c->iov[i].iov_len - j);
    if (!a) {
      j = 0;
      scanned += c->iov[i].iov_len;
    } else {
      return scanned + (a - (c->iov[i].iov_base + j));
    }
  }

  return -1;
}

// -----------------------------------------------------------------------------
// Get an vector from the current cursor position of, at most, @len bytes.
// -----------------------------------------------------------------------------
static void MAYBEUNUSED
iovec_cursor_get(struct iovec *iov, struct iovec_cursor *c, size_t len) {
  assert(!iovec_cursor_full(c));

  size_t count = c->iov[c->i].iov_len - c->j;
  if (count > len) count = len;

  iov->iov_base = c->iov[c->i].iov_base + c->j;
  iov->iov_len = count;
  c->j += count;
  if (c->j == c->iov[c->i].iov_len) {
    c->j = 0;
    c->i++;
  }
}

// -----------------------------------------------------------------------------
// Copy, at most, @len bytes from @src to @dest
// -----------------------------------------------------------------------------
static size_t MAYBEUNUSED
iovec_cursor_copy(struct iovec_cursor *dest, struct iovec_cursor *src,
                  size_t len) {
  while (len && dest->i < dest->count && src->i < src->count) {
    size_t bytes = src->iov[src->i].iov_len - src->j;
    if (bytes > len) bytes = len;

    dest->iov[dest->i].iov_base = src->iov[src->i].iov_base + src->j;
    dest->iov[dest->i].iov_len = bytes;

    len -= bytes;
    src->j += bytes;
    if (src->j == src->iov[src->i].iov_len) {
      src->j = 0;
      src->i++;
    }
    dest->i++;
  }

  return len;
}

// -----------------------------------------------------------------------------
// Store as many vectors from src as possible until either @dest is full or
// @src is empty.
// -----------------------------------------------------------------------------
static void MAYBEUNUSED
iovec_cursor_copy_cursor(struct iovec_cursor *dest, struct obstcp_cursor *src) {
  while (!iovec_cursor_full(dest)) {
    struct iovec iov;
    if (!src->get(src, &iov, ULONG_MAX))
      return;

    iovec_cursor_append(dest, iov.iov_base, iov.iov_len);
  }
}

static char MAYBEUNUSED
printable(char a) {
  if (a >= 32 && a <= 126)
    return a;

  return '.';
}

static void MAYBEUNUSED
iovec_cursor_debug(const struct iovec_cursor *c) {
  unsigned i;

  for (i = 0; i < c->count; ++i) {
    fprintf(stderr, "iovec %u/%u:\n", i, c->count);
    size_t todo = c->iov[i].iov_len;
    size_t j = 0;

    while (todo >= 16) {
      fprintf(stderr, "  ");

      unsigned k;
      for (k = 0; k < 16; ++k) {
        fprintf(stderr, "%02x ", ((uint8_t *) c->iov[i].iov_base)[j+k]);
      }
      for (k = 0; k < 16; ++k) {
        fprintf(stderr, "%c", printable(((uint8_t *) c->iov[i].iov_base)[j++]));
      }
      fprintf(stderr, "\n");

      todo -= 16;
    }

    if (todo) {
      const size_t origtodo = todo;
      unsigned k = 0;

      fprintf(stderr, "  ");
      while (todo--) {
        fprintf(stderr, "%02x ", ((uint8_t *) c->iov[i].iov_base)[j+(k++)]);
      }
      for (k = 0; k < 16 - origtodo; ++k) {
        fprintf(stderr, "   ");
      }

      todo = origtodo;
      k = 0;
      while (todo--) {
        fprintf(stderr, "%c ", printable(((uint8_t *) c->iov[i].iov_base)[j+(k++)]));
      }
      fprintf(stderr, "\n");
    }
  }

  fflush(stderr);
}

// -----------------------------------------------------------------------------
// Get a pointer to the next @n bytes from the cursor in a linear buffer. If
// the next @n bytes are linear already, return a pointer to the contents of
// one of the vectors. Otherwise, use @buffer to concatenate the fragments,
// returning a pointer to @buffer.
//
// This assumes that enough data exists in @c to be read. See iovec_cursor_has.
// -----------------------------------------------------------------------------
static MAYBEUNUSED const uint8_t *
iovec_cursor_read(uint8_t *buffer, struct iovec_cursor *c, size_t n) {
  if (c->iov[c->i].iov_len - c->j >= n) {
    const uint8_t *const result = ((uint8_t *) c->iov[c->i].iov_base) + c->j;

    c->j += n;
    if (c->j == c->iov[c->i].iov_len) {
      c->j = 0;
      c->i++;
    }
    return result;
  } else {
    off_t j = 0;

    while (n) {
      size_t todo = c->iov[c->i].iov_len - c->j;
      if (todo > n)
        todo = n;
      memcpy(buffer + j, ((uint8_t *) c->iov[c->i].iov_base) + c->j, todo);
      n -= todo;
      j += todo;
      c->j += todo;
      if (c->j == c->iov[c->i].iov_len) {
        c->j = 0;
        c->i++;
      }
    }

    return buffer;
  }
}

// -----------------------------------------------------------------------------
// Advance the current cursor location, at most, @bytes bytes. If the vector
// array contains >= @bytes bytes, then 0 is returned. Otherwise, the number of
// remain bytes not advanced over is returned.
// -----------------------------------------------------------------------------
static size_t MAYBEUNUSED
iovec_cursor_seek(struct iovec_cursor *c,
                  size_t bytes) {
  unsigned i;

  for (i = c->i; i < c->count; ++i) {
    size_t todo = bytes;
    if (todo > c->iov[i].iov_len)
      todo = c->iov[i].iov_len;

    c->j += todo;
    bytes -= todo;

    if (c->j == c->iov[i].iov_len) {
      c->j = 0;
      c->i++;
    }
  }

  return bytes;
}
// -----------------------------------------------------------------------------

#undef MAYBEUNUSED

#endif  // IOVEC_CURSOR
