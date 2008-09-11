#include <assert.h>
#include <stdio.h>

#include <httpd.h>
#include <http_config.h>

#include <apr.h>
#include <apr_general.h>
#include <util_filter.h>
#include <apr_buckets.h>

#include "../../libobstcp.h"

#include "../../cursor.h"
#include "../../iovec_cursor.h"
#include "../../varbuf.h"

static const char kFilterName[] = "ObsTCP";

module mod_obstcp;

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

struct bucket_cursor {
  struct obstcp_cursor c;
  apr_bucket *b;
  apr_bucket_brigade *bb;
  size_t read;
  ap_input_mode_t mode;
  char seen_eof;
  apr_status_t status;
};

static int
bucket_cursor_get(void *arg, struct iovec *iov, size_t n) {
  struct bucket_cursor *c = arg;

  for (;;) {
    if (c->b == APR_BRIGADE_SENTINEL(c->bb))
      return 0;

    if (APR_BUCKET_IS_EOS(c->b)) {
      c->seen_eof = 1;
      c->read = 0;
      c->b = APR_BUCKET_NEXT(c->b);
      continue;
    } else if (APR_BUCKET_IS_METADATA(c->b)) {
      c->read = 0;
      c->b = APR_BUCKET_NEXT(c->b);
      continue;
    }

    const char *data;
    apr_size_t len;
    apr_status_t r = apr_bucket_read(c->b, &data, &len, c->mode);
    if (r != APR_SUCCESS) {
      c->status = r;
      return 0;
    }
    const apr_size_t origlen = len;

    data += c->read;
    len -= c->read;

    if (len > n)
      len = n;

    // I'm assuming that the input buckets are mutable here.
    iov->iov_base = (uint8_t *) data;
    iov->iov_len = len;

    c->read += len;
    if (c->read == origlen) {
      c->read = 0;
      c->b = APR_BUCKET_NEXT(c->b);
    }

    return 1;
  }
}

static int
bucket_cursor_fold(void *arg, int (*f) (void *, uint8_t *, size_t len), void *ctx) {
  struct bucket_cursor *c = arg;
  apr_bucket *b = c->b;

  for (;;) {
    if (b == APR_BRIGADE_SENTINEL(c->bb))
      return 0;

    if (APR_BUCKET_IS_EOS(b) ||
        APR_BUCKET_IS_METADATA(b)) {
      b = APR_BUCKET_NEXT(b);
      continue;
    }

    const char *data;
    apr_size_t len;
    apr_status_t r = apr_bucket_read(c->b, &data, &len, c->mode);
    if (r != APR_SUCCESS) {
      c->status = r;
      return 0;
    }

    if (b == c->b) {
      data += c->read;
      len -= c->read;
    }

    int n = f(ctx, (uint8_t *) data, len);
    if (n)
      return n;

    b = APR_BUCKET_NEXT(b);
  }
}

static void
bucket_cursor_init(struct bucket_cursor *c, apr_bucket_brigade *bb,
                   ap_input_mode_t mode) {
  c->c.get = bucket_cursor_get;
  c->c.fold = bucket_cursor_fold;
  c->b = APR_BRIGADE_FIRST(bb);
  c->bb = bb;
  c->read = 0;
  c->seen_eof = 0;
  c->mode = mode;
  c->status = APR_SUCCESS;
}

static apr_status_t
mod_obstcp_obuf_use(apr_bucket_brigade *bb, size_t *oconsumed,
                    struct obstcp_cursor *c, ap_input_mode_t mode, apr_off_t bytes,
                    apr_bucket_alloc_t *alloc) {
  size_t consumed = 0;
  *oconsumed = 0;

  if (mode == AP_MODE_GETLINE) {
    const ssize_t lineoffset = cursor_memchr(c, '\n');
    if (lineoffset == -1)
      return APR_SUCCESS;

    uint8_t *line = malloc(lineoffset + 1);
    if (!line)
      return APR_ENOMEM;

    const uint8_t *a = cursor_read(line, c, lineoffset + 1);
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
    while (bytes) {
      struct iovec iov;

      if (!c->get(c, &iov, bytes))
        break;

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

  // See if we can satisfy this request from buffers. We build a cursor over
  // our buffered output data.
  struct varbuf_cursor obufc;
  varbuf_cursor_init(&obufc, &conn->obuf, NULL, 0);
  size_t consumed;

  ret = mod_obstcp_obuf_use(bb, &consumed, (struct obstcp_cursor *) &obufc,
                            mode, bytes, f->c->bucket_alloc);
  if (ret != APR_SUCCESS)
    return ret;

  bytes -= consumed;

  if ((mode == AP_MODE_GETLINE && consumed) ||
      (mode == AP_MODE_READBYTES && !bytes))
    return APR_SUCCESS;

  if (!conn->bb) {
    conn->bb = apr_brigade_create(f->c->pool, f->c->bucket_alloc);
  } else {
    ap_assert(APR_BRIGADE_EMPTY(conn->bb));
  }

  char eof_seen = 0, firstloop = 1;
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

    struct iovec outiov[16];
    unsigned outlen = 16;

    // The input to obstcp_server_read is the buffered (unprocessed) input plus
    // the data from furthur down the stack.
    struct varbuf_cursor rbufc;
    varbuf_cursor_init(&rbufc, &conn->rbuf, NULL, 0);
    struct bucket_cursor bucketc;
    bucket_cursor_init(&bucketc, conn->bb, mode);
    struct cursor_join jointc;
    cursor_join_init(&jointc, (struct obstcp_cursor *) &obufc, (struct obstcp_cursor *) &bucketc);

    if (obstcp_server_read(&conn->ctx, outiov, &outlen, &consumed,
                           (struct obstcp_cursor *) &jointc) == -1) {
      perror("obstcp_server_read");
      ret = APR_ECONNABORTED;
      goto exit;
    }

    // We want to buffer the input data that wasn't consumed. However, the
    // joint cursor might be pointing within the data that we've already
    // buffered, we don't want to buffer that data again so we make sure that
    // we've skipped the whole varbuf_cursor...
    cursor_join_discard_first(&jointc);
    // ... and then buffer the rest
    if (!varbuf_copy_cursor(&conn->rbuf, (struct obstcp_cursor *) &jointc)) {
      ret = APR_ENOMEM;
      goto exit;
    }

    // Now we see if we can satisfy this request using the buffered output data
    // and the new output data from obstcp_server_read
    varbuf_cursor_init(&obufc, &conn->obuf, NULL, 0);
    struct iovec_cursor iovc;
    iovec_cursor_init(&iovc, outiov, outlen);
    cursor_join_init(&jointc, (struct obstcp_cursor *) &obufc, (struct obstcp_cursor *) &iovc);

    ret = mod_obstcp_obuf_use(bb, &consumed, (struct obstcp_cursor *) &jointc,
                              mode, bytes, f->c->bucket_alloc);
    // Again, make sure that we aren't going to buffer data that we've already
    // buffered...
    cursor_join_discard_first(&jointc);
    // ... and then buffer the rest...
    if (!varbuf_copy_cursor(&conn->obuf, (struct obstcp_cursor *) &jointc)) {
      ret = APR_ENOMEM;
      goto exit;
    }

    bytes -= consumed;

    for (b = APR_BRIGADE_FIRST(conn->bb);
         b != APR_BRIGADE_SENTINEL(conn->bb);
         b = APR_BUCKET_NEXT(b)) {
      apr_bucket_delete(b);
    }
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
