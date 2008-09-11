#include <assert.h>
#include <stdio.h>

#include <httpd.h>
#include <http_config.h>

#include <apr.h>
#include <apr_general.h>
#include <util_filter.h>
#include <apr_buckets.h>

#include <libobstcp.h>

static const char kFilterName[] = "ObsTCP";

module mod_obstcp;

// -----------------------------------------------------------------------------
// Utility functions for dealing with iovec arrays...

struct iovec_cursor {
  struct iovec *iov;  // pointer to the iovecs
  unsigned count;     // number of iovecs
  unsigned i;         // current iovec
  size_t j;           // offset into current iovec
};

static void
iovec_cursor_init(struct iovec_cursor *c,
                  struct iovec *iov, unsigned count) {
  c->iov = iov;
  c->count = count;
  c->i = 0;
  c->j = 0;
}

static void
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
        fprintf(stderr, "%c", ((uint8_t *) c->iov[i].iov_base)[j++]);
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
        fprintf(stderr, "%c ", ((uint8_t *) c->iov[i].iov_base)[j+(k++)]);
      }
      fprintf(stderr, "\n");
    }
  }
}

// -----------------------------------------------------------------------------
// Return true iff the cursor is 'full' (i.e. at the end of the iovec array)
// -----------------------------------------------------------------------------
static char
iovec_cursor_full(struct iovec_cursor *c) {
  return c->i == c->count;
};

// -----------------------------------------------------------------------------
// Get an vector from the current cursor position of, at most, @len bytes.
// -----------------------------------------------------------------------------
static void
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
// Find the first occurance of @byte in the data from the current cursor
// position onwards. If @byte is found, return it's index from the current
// cursor location. Otherwise, return -1
// -----------------------------------------------------------------------------
static ssize_t
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
// Get a pointer to the next @n bytes from the cursor in a linear buffer. If
// the next @n bytes are linear already, return a pointer to the contents of
// one of the vectors. Otherwise, use @buffer to concatenate the fragments,
// returning a pointer to @buffer.
//
// This assumes that enough data exists in @c to be read. See iovec_cursor_has.
// -----------------------------------------------------------------------------
static const uint8_t *
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
static size_t
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


// -----------------------------------------------------------------------------
// Varbuffers. Support functions for read buffers...

#define VARBUF_CHUNK_SIZE 256

struct chunk {
  size_t length, used, read;
  struct chunk *prev, *next;
  uint8_t data[0];
};

static void
varbuf_init(struct varbuf *vb) {
  memset(vb, 0, sizeof(struct varbuf));
}

static void
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
static int
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
// Fillout a vector array with the unread contents of a varbuf
//
// iovecs: (output) these are filled out with vectors of unread data
// oiovlen: (in/out) on entry, the number of elements of @iovecs. On exist, the
//   number of valid entries in @iovecs
// -----------------------------------------------------------------------------
static void
varbuf_to_iov(struct iovec *iovecs, unsigned *oiovlen, struct varbuf *vb) {
  const unsigned iovlen = *oiovlen;
  unsigned i = 0;
  struct chunk *c;

  for (c = vb->head; c && i < iovlen; c = c->next) {
    iovecs[i].iov_base = c->data + c->read;
    iovecs[i++].iov_len = c->used - c->read;
  }

  *oiovlen = i;
}

// -----------------------------------------------------------------------------
// Return the number of chunks in a varbuf
// -----------------------------------------------------------------------------
static unsigned
varbuf_count(const struct varbuf *vb) {
  unsigned count = 0;
  const struct chunk *c;

  for (c = vb->head; c; c = c->next)
    count++;

  return count;
}

// -----------------------------------------------------------------------------
// Copy everything from @c to the end of @vb
// -----------------------------------------------------------------------------
static int
varbuf_copy_iovec_cursor(struct varbuf *vb, struct iovec_cursor *c) {
  while (!iovec_cursor_full(c)) {
    struct iovec iov;
    iovec_cursor_get(&iov, c, 999999999999l);
    if (varbuf_copy_in(vb, iov.iov_base, iov.iov_len) == -1)
      return -1;
  }

  return 0;
}

// -----------------------------------------------------------------------------
// Discard, at most, @n bytes from a varbuf and return @n, less the number of
// bytes actually discarded. (If the return value is > 0, then @vb is empty on
// exit.)
// -----------------------------------------------------------------------------
static size_t
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
// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// This is a per-server configuration for obstcp
// -----------------------------------------------------------------------------
struct mod_obstcp_config {
  char enabled;
  struct obstcp_keys keys;
};

// -----------------------------------------------------------------------------
// This is a per-connection state for the filters.
// -----------------------------------------------------------------------------
struct mod_obstcp_conn {
  apr_bucket_brigade *bb;
  struct obstcp_server_ctx ctx;
  struct varbuf rbuf;  // contains unprocess input from the network
  struct varbuf obuf;  // contains processed data ready to go up the stack
};

// -----------------------------------------------------------------------------
// This is called to create a per module, per server configuration structure.
// Note that each different port that we are listening is a different 'server'.
// -----------------------------------------------------------------------------
static void *
mod_obstcp_server_config_create(apr_pool_t *p, server_rec *r) {
  struct mod_obstcp_config *config = apr_palloc(p, sizeof(struct mod_obstcp_config));
  obstcp_keys_init(&config->keys);

  return config;
}

static apr_status_t
mod_obstcp_conn_free(void *ptr) {
  struct mod_obstcp_conn *conn = ptr;
  varbuf_free(&conn->rbuf);
  varbuf_free(&conn->obuf);

  return APR_SUCCESS;
}

// -----------------------------------------------------------------------------
// This is called for each connection and may insert filters into the IO path
// if required
// -----------------------------------------------------------------------------
static void
mod_obstcp_pre_connection(conn_rec *c) {
  struct mod_obstcp_config *config =
    ap_get_module_config(c->base_server->module_config, &mod_obstcp);

  if (!config->enabled)
    return;

  struct mod_obstcp_conn *conn = apr_pcalloc(c->pool, sizeof(struct mod_obstcp_conn));
  obstcp_server_ctx_init(&conn->ctx, &config->keys);
  varbuf_init(&conn->rbuf);
  varbuf_init(&conn->obuf);

  apr_pool_cleanup_register(c->pool, conn, mod_obstcp_conn_free, apr_pool_cleanup_null);

  ap_filter_t *s = ap_add_output_filter(kFilterName, conn, NULL, c);
  fprintf(stderr, "  output: %p\n", s);
  s = ap_add_input_filter(kFilterName, conn, NULL, c);
  fprintf(stderr, "  input: %p\n", s);

  fflush(stderr);
}

static apr_status_t
mod_obstcp_obuf_use(apr_bucket_brigade *bb, size_t *oconsumed,
                    struct iovec_cursor *c, ap_input_mode_t mode, apr_off_t bytes,
                    apr_bucket_alloc_t *alloc) {
  size_t consumed = 0;
  *oconsumed = 0;

  if (mode == AP_MODE_GETLINE) {
    const ssize_t lineoffset = iovec_cursor_memchr(c, '\n');
    if (lineoffset == -1)
      return APR_SUCCESS;

    uint8_t *line = malloc(lineoffset + 1);
    if (!line)
      return APR_ENOMEM;

    const uint8_t *a = iovec_cursor_read(line, c, lineoffset + 1);
    if (a != line)
      memcpy(line, a, lineoffset + 1);

    fprintf(stderr, "mod_obstcp: emitting line: ");
    fflush(stderr);
    write(2, line, lineoffset + 1);

    apr_bucket *outb = apr_bucket_heap_create((char *) line, lineoffset + 1,
                                              free, alloc);
    APR_BRIGADE_INSERT_TAIL(bb, outb);
    consumed += lineoffset + 1;
  } else if (mode == AP_MODE_READBYTES) {
    while (bytes && !iovec_cursor_full(c)) {
      struct iovec iov;

      iovec_cursor_get(&iov, c, bytes);
      fprintf(stderr, "mod_obstcp: emitting %zu bytes", iov.iov_len);
      apr_bucket *outb = apr_bucket_heap_create(iov.iov_base, iov.iov_len,
                                                NULL, alloc);
      APR_BRIGADE_INSERT_TAIL(bb, outb);

      bytes -= iov.iov_len;
      consumed += iov.iov_len;
    }
  } else {
    fprintf(stderr, "mod_obstcp: Got unknown mode %d\n", mode);
    fflush(stderr);
    return APR_ECONNABORTED;
  }

  *oconsumed = consumed;
  return APR_SUCCESS;
}

static apr_status_t
mod_obstcp_io_filter_input(ap_filter_t *f, apr_bucket_brigade *bb,
                           ap_input_mode_t mode, apr_read_type_e block,
                           apr_off_t bytes) {
  struct mod_obstcp_conn *conn = f->ctx;
  apr_status_t ret = APR_SUCCESS;

  if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE) {
    fprintf(stderr, "mod_obstcp: ENOTIMPL for mode %d\n", mode);
    fflush(stderr);
    return APR_ENOTIMPL;
  }

  // See if we can satisfy this request from buffers
  {
    const unsigned obufvectors = varbuf_count(&conn->obuf);

    if (obufvectors) {
      struct iovec *iovs = malloc(sizeof(struct iovec) * obufvectors);
      if (!iovs)
        return APR_ENOMEM;
      unsigned iovlen = obufvectors;

      varbuf_to_iov(iovs, &iovlen, &conn->obuf);

      struct iovec_cursor c;
      iovec_cursor_init(&c, iovs, iovlen);
      size_t consumed;

      ret = mod_obstcp_obuf_use(bb, &consumed, &c, mode, bytes, f->c->bucket_alloc);
      free(iovs);
      if (ret != APR_SUCCESS)
        return ret;

      varbuf_discard(&conn->obuf, consumed);
      bytes -= consumed;

      if ((mode == AP_MODE_GETLINE && consumed) ||
          (mode == AP_MODE_READBYTES && !bytes))
        return APR_SUCCESS;
    }
  }

  if (!conn->bb) {
    conn->bb = apr_brigade_create(f->c->pool, f->c->bucket_alloc);
  } else {
    ap_assert(APR_BRIGADE_EMPTY(conn->bb));
  }

  char eof_seen = 0, firstloop = 1;
  size_t consumed;
  apr_bucket *b;

  do {
    apr_status_t r;
    if (block == APR_BLOCK_READ && !firstloop) {
      r = ap_get_brigade(f->next, conn->bb, AP_MODE_READBYTES, APR_BLOCK_READ, 1);
      firstloop = 1;
    } else {
      r = ap_get_brigade(f->next, conn->bb, AP_MODE_READBYTES, APR_NONBLOCK_READ, 8192);
      if (APR_STATUS_IS_EAGAIN(r) && block == APR_BLOCK_READ) {
        firstloop = 0;
        continue;
      }
    }

    if (r != APR_SUCCESS)
      return r;

    firstloop = 0;

    unsigned buckets = 0;

    for (b = APR_BRIGADE_FIRST(conn->bb);
         b != APR_BRIGADE_SENTINEL(conn->bb);
         b = APR_BUCKET_NEXT(b)) {
      if (APR_BUCKET_IS_EOS(b) ||
          APR_BUCKET_IS_METADATA(b))
        continue;
      buckets++;
    }

    const unsigned max_iov =
      buckets + ((OBSTCP_MAX_FRAME + VARBUF_CHUNK_SIZE) / VARBUF_CHUNK_SIZE);
    struct iovec *iniov = malloc(sizeof(struct iovec) * max_iov);
    if (!iniov)
      return APR_ENOMEM;
    struct iovec *outiov = malloc(sizeof(struct iovec) * max_iov);
    if (!outiov) {
      free(iniov);
      return APR_ENOMEM;
    }

    unsigned inlen = max_iov;
    varbuf_to_iov(iniov, &inlen, &conn->rbuf);
    unsigned outlen = max_iov;

    for (b = APR_BRIGADE_FIRST(conn->bb);
         b != APR_BRIGADE_SENTINEL(conn->bb);
         b = APR_BUCKET_NEXT(b)) {
      if (APR_BUCKET_IS_EOS(b) ||
          APR_BUCKET_IS_METADATA(b)) {
        APR_BUCKET_REMOVE(b);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        if (APR_BUCKET_IS_EOS(b))
          eof_seen = 1;
        continue;
      }

      const char *data;
      apr_size_t len;
      r = apr_bucket_read(b, &data, &len, mode);
      if (r != APR_SUCCESS) {
        ret = r;
        free(iniov);
        free(outiov);
        goto exit;
      }

      // I'm assuming that the input buckets are mutable here.
      iniov[inlen].iov_base = (uint8_t *) data;
      iniov[inlen++].iov_len = len;
    }


    if (obstcp_server_read(&conn->ctx, outiov, &outlen, &consumed, iniov, inlen) == -1) {
      perror("obstcp_server_read");
      ret = APR_ECONNABORTED;
      free(iniov);
      free(outiov);
      goto exit;
    }

    // Delete the buffer input data which has now been consumed and, possibly,
    // buffer some of the extra data that wasn't consumed.
    varbuf_discard(&conn->rbuf, consumed);

    struct iovec_cursor inc;
    iovec_cursor_init(&inc, iniov, inlen);
    iovec_cursor_seek(&inc, consumed);

    varbuf_copy_iovec_cursor(&conn->rbuf, &inc);

    const unsigned numprocessed = outlen + varbuf_count(&conn->obuf);
    unsigned processedlen = numprocessed;
    struct iovec *processediov = malloc(sizeof(struct iovec) * processedlen);
    varbuf_to_iov(processediov, &processedlen, &conn->obuf);
    memcpy(processediov + processedlen, outiov, outlen * sizeof(struct iovec));

    struct iovec_cursor processedc;
    iovec_cursor_init(&processedc, processediov, numprocessed);

    ret = mod_obstcp_obuf_use(bb, &consumed, &processedc, mode, bytes, f->c->bucket_alloc);
    const ssize_t remaining = varbuf_discard(&conn->obuf, consumed);

    struct iovec_cursor outc;
    iovec_cursor_init(&outc, outiov, outlen);
    iovec_cursor_seek(&outc, remaining);

    varbuf_copy_iovec_cursor(&conn->obuf, &outc);
    bytes -= consumed;

    for (b = APR_BRIGADE_FIRST(conn->bb);
         b != APR_BRIGADE_SENTINEL(conn->bb);
         b = APR_BUCKET_NEXT(b)) {
      apr_bucket_delete(b);
    }

    free(iniov);
    free(outiov);
  } while (ret == APR_SUCCESS && !eof_seen && block == APR_BLOCK_READ &&
           ((mode == AP_MODE_GETLINE && !consumed) ||
            (mode == AP_MODE_READBYTES && bytes)));

exit:
  for (b = APR_BRIGADE_FIRST(conn->bb);
       b != APR_BRIGADE_SENTINEL(conn->bb);
       b = APR_BUCKET_NEXT(b)) {
    apr_bucket_delete(b);
  }

  return ret;
}

static void
mod_obstcp_flush_iovs(struct obstcp_server_ctx *ctx, apr_bucket_brigade *outbb,
                      const struct iovec *iovs, unsigned numiovs,
                      apr_bucket_alloc_t *alloc) {
  struct iovec iov;
  if (obstcp_server_prefix(ctx, &iov) == -1)
    abort();  // programming error in this code

  if (iov.iov_len) {
    apr_bucket *outb = apr_bucket_heap_create(iov.iov_base, iov.iov_len, NULL, alloc);
    APR_BRIGADE_INSERT_TAIL(outbb, outb);
  }

  unsigned i;
  for (i = 0; i < numiovs; ++i) {
    apr_bucket *outb = apr_bucket_heap_create(iovs[i].iov_base, iovs[i].iov_len, free, alloc);
    APR_BRIGADE_INSERT_TAIL(outbb, outb);
  }
}

static apr_status_t
mod_obstcp_io_filter_output(ap_filter_t *f, apr_bucket_brigade *bb)
{
  struct mod_obstcp_conn *conn = f->ctx;

  if (APR_BRIGADE_EMPTY(bb)) return ap_pass_brigade(f->next, bb);

  apr_bucket_brigade *outbb = apr_brigade_create(f->c->pool, f->c->bucket_alloc);

  static const unsigned kNumIOVs = 8;
  struct iovec iovs[kNumIOVs];
  unsigned iovi = 0, i;

  while (!APR_BRIGADE_EMPTY(bb)) {
    apr_bucket *b = APR_BRIGADE_FIRST(bb);

    if (APR_BUCKET_IS_EOS(b) ||
        APR_BUCKET_IS_FLUSH(b) ||
        APR_BUCKET_IS_METADATA(b) ) {
      APR_BUCKET_REMOVE(b);
      APR_BRIGADE_INSERT_TAIL(outbb, b);
      continue;
    }

    const char *data;
    apr_size_t len;
    apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
    apr_size_t done = 0;

    while (done < len) {
      if (iovi == kNumIOVs) {
        mod_obstcp_flush_iovs(&conn->ctx, outbb, iovs, iovi, f->c->bucket_alloc);
        iovi = 0;
      }

      // TODO(agl): len - done might be too much when we introduce MACs in the
      // future.
      uint8_t *copy = malloc(len - done);
      if (!copy)
        goto NOMEM;

      const ssize_t encrypted = obstcp_server_encrypt
        (&conn->ctx, copy, (const uint8_t *) data + done, len - done);
      iovs[iovi].iov_base = copy;
      iovs[iovi++].iov_len = encrypted;

      if (encrypted < (len - done)) {
        // we have filled a frame; time to flush
        mod_obstcp_flush_iovs(&conn->ctx, outbb, iovs, iovi, f->c->bucket_alloc);
        iovi = 0;
      }

      done += encrypted;
    }

    APR_BUCKET_REMOVE(b);
    apr_bucket_delete(b);
  }

  if (iovi) {
    // flush any trailing data
    mod_obstcp_flush_iovs(&conn->ctx, outbb, iovs, iovi, f->c->bucket_alloc);
  }

  apr_brigade_cleanup(bb);
  return ap_pass_brigade(f->next, outbb);

NOMEM:
  for (i = 0; i < iovi; ++i) {
    free(iovs[i].iov_base);
  }

  return APR_ENOMEM;
}

static const char *
mod_obstcp_filter_enable(cmd_parms *cmd, void *dummy, int arg) {
  struct mod_obstcp_config *config = ap_get_module_config(cmd->server->module_config, &mod_obstcp);
  config->enabled = arg;

  return NULL;
}

static int
hex_char(uint8_t *out, char in) {
  if (in >= '0' && in <= '9') {
    *out = in - '0';
    return 1;
  } else if (in >= 'a' && in <= 'f') {
    *out = 10 + (in - 'a');
    return 1;
  } else if (in >= 'A' && in <= 'F') {
    *out = 10 + (in - 'A');
    return 1;
  } else {
    return 0;
  }
}

static int
hex_decode(uint8_t *dest, const char *src) {
  while (*src) {
    uint8_t v1, v2;
    if (!hex_char(&v1, *src++))
      return 0;
    if (!hex_char(&v2, *src++))
      return 0;

    *dest++ = (v1 << 4) | v2;
  }

  return 1;
}

static const char *
mod_obstcp_key_add(cmd_parms *cmd, void *dummy, const char *hexkey) {
  struct mod_obstcp_config *config = ap_get_module_config(cmd->server->module_config, &mod_obstcp);

  if (strlen(hexkey) != 64)
    return "Obfuscated TCP key is the wrong length (should be 64 hex chars)";

  uint8_t key[32];
  if (!hex_decode(key, hexkey))
    return "Obfuscated TCP contains invalid charactors (should be a hex string)";

  if (!obstcp_keys_key_add(&config->keys, key))
    return "Obfuscated TCP key failed to add (duplicate?)";

  fprintf(stderr, "mod_obstcp: added keyid %x\n", config->keys.keys->keyid);

  return NULL;
}

static const command_rec mod_obstcp_commands[] = {
  AP_INIT_FLAG("ObsTCP", mod_obstcp_filter_enable, NULL, RSRC_CONF,
               "Enable Obfuscated TCP"),
  AP_INIT_TAKE1("ObsTCPPrivateKey", mod_obstcp_key_add, NULL, RSRC_CONF,
                "Set Obfuscated TCP Key"),
  { NULL }
};

static void mod_obstcp_hooks_register (apr_pool_t *p) {
  ap_hook_pre_connection(mod_obstcp_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
  ap_register_input_filter(kFilterName, mod_obstcp_io_filter_input, NULL, AP_FTYPE_CONNECTION);
  ap_register_output_filter(kFilterName, mod_obstcp_io_filter_output, NULL, AP_FTYPE_CONNECTION);
}

module AP_MODULE_DECLARE_DATA mod_obstcp = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  mod_obstcp_server_config_create,
  NULL,
  mod_obstcp_commands,
  mod_obstcp_hooks_register,
};
