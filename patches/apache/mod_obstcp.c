#include "httpd.h"
#include "http_config.h"

#include "apr.h"
#include "apr_general.h"
#include "util_filter.h"
#include "apr_buckets.h"

static const char kFilterName[] = "ObsTCP";

module mod_obstcp;

// -----------------------------------------------------------------------------
// This is a per-server configuration for obstcp
// -----------------------------------------------------------------------------
struct mod_obstcp_config {
  char enabled;
};

// -----------------------------------------------------------------------------
// This is a per-connection state for the filters.
// -----------------------------------------------------------------------------
struct mod_obstcp_conn {
  apr_bucket_brigade *bb;
};

// -----------------------------------------------------------------------------
// This is called to create a per module, per server configuration structure.
// Note that each different port that we are listening is a different 'server'.
// -----------------------------------------------------------------------------
static void *
mod_obstcp_server_config_create(apr_pool_t *p, server_rec *r) {
  struct mod_obstcp_config *config = apr_palloc(p, sizeof(struct mod_obstcp_config));
  config->enabled = 1;

  return config;
}

// -----------------------------------------------------------------------------
// This is called for each connection and may insert filters into the IO path
// if required
// -----------------------------------------------------------------------------
static void
mod_obstcp_filter_insert(request_rec *r) {
  struct mod_obstcp_config *config =
    ap_get_module_config(r->server->module_config, &mod_obstcp);

  if (!config->enabled)
    return;

  struct mod_obstcp_conn *conn = apr_pcalloc(r->pool, sizeof(struct mod_obstcp_conn));

  ap_add_output_filter(kFilterName, conn, r, r->connection);
  ap_add_input_filter(kFilterName, conn, r, r->connection);
}

static apr_status_t
mod_obstcp_io_filter_input(ap_filter_t *f, apr_bucket_brigade *bb,
                           ap_input_mode_t mode, apr_read_type_e block,
                           apr_off_t bytes) {
  struct mod_obstcp_conn *conn = f->ctx;

  if (!conn->bb) {
    conn->bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
  } else {
    ap_assert(APR_BRIGADE_EMPTY(conn->bb));
  }

  apr_status_t r = ap_get_brigade(f->next, conn->bb, mode, block, bytes);
  if (r != APR_SUCCESS)
    return r;

  while (!APR_BRIGADE_EMPTY(conn->bb)) {
    apr_bucket *b = APR_BRIGADE_FIRST(conn->bb);

    if (APR_BUCKET_IS_EOS(b) ||
        APR_BUCKET_IS_METADATA(b)) {
      APR_BUCKET_REMOVE(b);
      APR_BRIGADE_INSERT_TAIL(bb, b);
      continue;
    }

    const char *data;
    apr_size_t len;
    r = apr_bucket_read(b, &data, &len, mode);
    if (r != APR_SUCCESS)
      return r;

    apr_bucket *outb = apr_bucket_heap_create(data, len, NULL, f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, outb);
    apr_bucket_delete(b);
  }

  return APR_SUCCESS;
}

static apr_status_t
mod_obstcp_io_filter_output(ap_filter_t *f, apr_bucket_brigade *bb)
{
  if (APR_BRIGADE_EMPTY(bb)) return ap_pass_brigade(f->next, bb);

  apr_bucket_brigade *outbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);

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

    apr_bucket *outb = apr_bucket_heap_create(data, len, 0, f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(outbb, outb);
    apr_bucket_delete(b);
  }

  apr_brigade_cleanup(bb);
  return ap_pass_brigade(f->next, outbb);
}

static const char *
mod_obstcp_filter_enable(cmd_parms *cmd, void *dummy, int arg) {
  struct mod_obstcp_config *config = ap_get_module_config(cmd->server->module_config, &mod_obstcp);
  config->enabled = arg;

  return NULL;
}

static const command_rec mod_obstcp_commands[] = {
  AP_INIT_FLAG("ObsTCP", mod_obstcp_filter_enable, NULL, RSRC_CONF,
               "Enable Obfuscated TCP"),
  { NULL }
};

static void mod_obstcp_hooks_register (apr_pool_t *p) {
  ap_hook_insert_filter(mod_obstcp_filter_insert, NULL, NULL, APR_HOOK_MIDDLE);
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
