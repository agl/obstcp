// Copyright 2008, Google Inc.
// All rights reserved.

#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>

#include <arpa/inet.h>

#include "libobstcp.h"
#include "sha256.h"
#include "base64.h"
#include "salsa20.h"

#define EXPORTED __attribute__ ((visibility("default")))

#define min_t(type, x, y) ({                        \
        type __min1 = (x);                        \
        type __min2 = (y);                        \
        __min1 < __min2 ? __min1: __min2; })

extern void curve25519_donna(uint8_t *mypublic, const uint8_t *secret,
                             const uint8_t *basepoint);

// -----------------------------------------------------------------------------
// Utility functions for reading and writing the banners and adverts...

#define OBSTCP_KIND_PUBLIC 0
#define OBSTCP_KIND_KEYID 1
#define OBSTCP_KIND_NONCE 2
#define OBSTCP_KIND_OBSPORT 3
#define OBSTCP_KIND_TLSPORT 4

static int
varint_put(uint8_t *out, unsigned length, unsigned *offset, unsigned v) {
  do {
    if (*offset >= length) return 0;
    if (v > 127) {
      out[*offset] = 0x80 | (v & 0x7f);
    } else {
      out[*offset] = v;
    }

    v >>= 7;
    (*offset)++;
  } while (v);

  return 1;
}

static int
varint_get(uint32_t *v, const uint8_t *banner, unsigned length, unsigned *j) {
  uint32_t accum = 0;
  unsigned bytes = 0;

  do {
    if (*j > length) return 0;
    accum <<= 7;
    accum += banner[*j] & 0x7f;
    bytes++;
  } while (bytes < 4 && banner[(*j)++] & 0x80);

  *v = accum;
  return 1;
}

static int
buffer_put(uint8_t *out, unsigned length, unsigned *offset,
           const void *in, unsigned inlen) {
  if (*offset + inlen > length) return 0;
  memcpy(out + *offset, in, inlen);
  (*offset) += inlen;

  return 1;
}

int EXPORTED
obstcp_advert_create(char *output, unsigned length,
                     const struct obstcp_keys *keys, ...) {
  va_list ap;
  uint8_t advert[384];
  unsigned j = 0;
  va_start(ap, keys);

  if (!keys->keys) {
    errno = ENOKEY;
    return -1;
  }

  if (!varint_put(advert, sizeof(advert), &j, OBSTCP_KIND_PUBLIC << 1 | 1)) goto spc;
  if (!varint_put(advert, sizeof(advert), &j, 32)) goto spc;
  if (!buffer_put(advert, sizeof(advert), &j, keys->keys->public_key, 32)) goto spc;

  for (;;) {
    const int type = va_arg(ap, int);
    int port, op;
    uint16_t port16;

    switch (type) {
    case OBSTCP_ADVERT_END:
      break;
    case OBSTCP_ADVERT_OBSPORT:
    case OBSTCP_ADVERT_TLSPORT:
      port = va_arg(ap, int);
      if (port < 1 || port > 65535) {
        errno = EINVAL;
        return -1;
      }

      port16 = htons(port);
      op = type == OBSTCP_ADVERT_OBSPORT ? OBSTCP_KIND_OBSPORT :
                                           OBSTCP_KIND_TLSPORT;
      if (!varint_put(advert, sizeof(advert), &j, op << 1 | 1)) goto spc;
      if (!varint_put(advert, sizeof(advert), &j, 2)) goto spc;
      if (!buffer_put(advert, sizeof(advert), &j, &port16, 2)) goto spc;
      break;
    default:
      errno = EINVAL;
      return -1;
    }

    if (type == OBSTCP_ADVERT_END) break;
  }

  const unsigned outlen = obs_base64_encode_length(j);
  if (outlen <= length) {
    obs_base64_encode(output, advert, j);
  }
  return outlen;

 spc:
  errno = E2BIG;
  return -1;
}

int EXPORTED
obstcp_advert_parse(const char *input, unsigned length, ...) {
  uint8_t advert[384];
  unsigned len, j = 0;
  int tlsport = 0, obsport = 0;
  uint16_t port;
  uint32_t v, type;
  va_list ap;

  va_start(ap, length);

  if (obs_base64_decode_length(length) > sizeof(advert)) return 0;
  if (!obs_base64_decode(advert, &len, input, length)) return 0;

  for (;;) {
    if (j == len) break;
    if (!varint_get(&type, advert, len, &j)) return 0;
    switch (type >> 1) {
    case OBSTCP_KIND_OBSPORT:
    case OBSTCP_KIND_TLSPORT:
      if (!(type & 1)) return 0;
      if (!varint_get(&v, advert, len, &j)) return 0;
      if (v != 2) return 0;
      if (j + 2 > len) return 0;
      memcpy(&port, advert + j, 2);
      j += 2;
      port = ntohs(port);
      if (type >> 1 == OBSTCP_KIND_OBSPORT) {
        obsport = port;
      } else {
        tlsport = port;
      }
      break;
    default:
      if (type & 1) {
        if (!varint_get(&v, advert, len, &j)) return 0;
        if (j + v > len) return 0;
        j += v;
      }
    }
  }

  for (;;) {
    const int type = va_arg(ap, int);
    int *iptr;

    switch (type) {
    case OBSTCP_ADVERT_END:
      return 1;
    case OBSTCP_ADVERT_OBSPORT:
      iptr = va_arg(ap, int *);
      *iptr = obsport;
      break;
    case OBSTCP_ADVERT_TLSPORT:
      iptr = va_arg(ap, int *);
      *iptr = tlsport;
      break;
    default:
      return 0;
    }
  }
}

// -----------------------------------------------------------------------------


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

// -----------------------------------------------------------------------------
// Return true iff the cursor is 'full' (i.e. at the end of the iovec array)
// -----------------------------------------------------------------------------
static char
iovec_cursor_full(struct iovec_cursor *c) {
  return c->i == c->count;
};

// -----------------------------------------------------------------------------
// Append a vector to the array. This assumes that !iovec_cursor_full(c)
// -----------------------------------------------------------------------------
static void
iovec_cursor_append(struct iovec_cursor *c, const void *a, size_t len) {
  c->iov[c->i].iov_base = (void *) a;
  c->iov[c->i++].iov_len = len;
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
// Copy, at most, @len bytes from @src to @dest
// -----------------------------------------------------------------------------
static size_t
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
static void
iovec_cursor_copy_cursor(struct iovec_cursor *dest, struct obstcp_cursor *src) {
  while (!iovec_cursor_full(dest)) {
    struct iovec iov;
    if (!src->get(src, &iov, ULONG_MAX))
      return;

    iovec_cursor_append(dest, iov.iov_base, iov.iov_len);
  }
}
// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// Utility functions for dealing with generic cursors (obstcp_cursor)...

static int
cursor_has(struct obstcp_cursor *c, size_t n) {
  return c->has(c, n);
}

// -----------------------------------------------------------------------------
// See iovec_cursor_read. This assumes that enough bytes are availible
// -----------------------------------------------------------------------------
static const uint8_t *
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


// -----------------------------------------------------------------------------
// Crypto utility functions...

static void
xor(uint8_t *dst, const uint8_t *src, const uint8_t *xorbytes, unsigned l) {
  const unsigned words = l >> 2;
  const unsigned bytes = l & 3;
  uint32_t *dst32 = (uint32_t *) dst;
  const uint32_t *src32 = (uint32_t *) src;
  const uint32_t *xorbytes32 = (uint32_t *) xorbytes;
  unsigned i;

  for (i = 0; i < words; ++i) {
    dst32[i] = src32[i] ^ xorbytes32[i];
  }

  for (i = 0; i < bytes; ++i) {
    dst[words * 4 + i] = src[words * 4 + i] ^ xorbytes[words * 4 + i];
  }
}

static void
encrypt(struct obstcp_half_connection *hc, uint8_t *out,
        const uint8_t *in, size_t len) {
  size_t l = len, j = 0;

  if (hc->used < 64) {
    const size_t m = min_t(size_t, 64u - hc->used, l);
    xor(out, in, hc->keystream + hc->used, m);
    l -= m;
    hc->used += m;
    j += m;
  }
  const unsigned chunks = l >> 6;
  if (chunks) {
    ECRYPT_encrypt_bytes((struct ECRYPT_ctx *) hc->input, in + j, out + j, chunks << 6);
    l -= chunks << 6;
    j += chunks << 6;
  }
  if (l) {
    memset(hc->keystream, 0, 64);
    ECRYPT_encrypt_bytes((struct ECRYPT_ctx *) hc->input, hc->keystream, hc->keystream, 64);
    xor(out + j, in + j, hc->keystream, l);
    hc->used = l;
  }
}
// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// Key set code...

void EXPORTED
obstcp_keys_init(struct obstcp_keys *keys) {
  memset(keys, 0, sizeof(struct obstcp_keys));
}

static uint32_t
key_keyid(const uint8_t *key) {
  uint32_t keyid = 0;
  unsigned i;

  for (i = 0; i < 8; ++i) {
    keyid ^= ((const uint32_t *) key)[i];
  }

  return keyid;
}

int EXPORTED
obstcp_keys_key_add(struct obstcp_keys *keys, const uint8_t *private_key) {
  struct obstcp_keypair *kp, *a;
  static const uint8_t basepoint[32] = {9};

  kp = (struct obstcp_keypair *) malloc(sizeof(struct obstcp_keypair));
  if (!kp) {
    errno = ENOMEM;
    return 0;
  }

  memcpy(kp->private_key, private_key, 32);
  kp->private_key[0] &= 248;
  kp->private_key[31] &= 127;
  kp->private_key[31] |= 64;

  curve25519_donna(kp->public_key, kp->private_key, basepoint);

  kp->keyid = key_keyid(kp->public_key);

  for (a = keys->keys; a; a = a->next) {
    if (a->keyid == kp->keyid) {
      free(kp);
      errno = ENOSPC;
      return 0;
    }
  }


  kp->next = keys->keys;
  keys->keys = kp;

  return 1;
}

void EXPORTED
obstcp_keys_free(struct obstcp_keys *keys) {
  struct obstcp_keypair *kp, *next;

  for (kp = keys->keys; kp; kp = next) {
    next = kp->next;
    free(kp);
  }

  keys->keys = NULL;
}

static const uint8_t *
keys_private_key_get(const struct obstcp_keys *keys, uint32_t keyid) {
  struct obstcp_keypair *kp;

  for (kp = keys->keys; kp; kp = kp->next) {
    if (kp->keyid == keyid) return kp->private_key;
  }

  return NULL;
}

// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// Server side interface...

enum {
  SRV_ST_READING,
  SRV_ST_FIRST_FRAME,
  SRV_ST_2ND_FRAME_PENDING,
  SRV_ST_RUNNING
};

void EXPORTED
obstcp_server_ctx_init(struct obstcp_server_ctx *ctx,
                       const struct obstcp_keys *keys) {
  memset(ctx, 0, sizeof(struct obstcp_server_ctx));
  ctx->state = SRV_ST_READING;
  ctx->keys = keys;
}

static int
client_banner_parse(const uint8_t *banner, unsigned len,
                    uint32_t *keyid, const uint8_t **theirpublic,
                    const uint8_t **random) {
  unsigned j = 0;
  char keyid_found = 0, public_found = 0, random_found = 0;
  uint32_t v;

  for (;;) {
    if (j == len) break;
    if (!varint_get(&v, banner, len, &j)) return 0;
    switch (v >> 1) {
    case OBSTCP_KIND_PUBLIC:
      if (!(v & 1)) return 0;
      if (!varint_get(&v, banner, len, &j)) return 0;
      if (v != 32) return 0;
      if (j + v > len) return 0;
      *theirpublic = banner + j;
      public_found = 1;
      j += 32;
      break;
    case OBSTCP_KIND_KEYID:
      if (!(v & 1)) return 0;
      if (!varint_get(&v, banner, len, &j)) return 0;
      if (v != 4) return 0;
      if (j + v > len) return 0;
      *keyid = ntohl(*((uint32_t *) (banner + j)));
      keyid_found = 1;
      j += 4;
      break;
    case OBSTCP_KIND_NONCE:
      if (!(v & 1)) return 0;
      if (!varint_get(&v, banner, len, &j)) return 0;
      if (v != 16) return 0;
      if (j + v > len) return 0;
      *random = banner + j;
      random_found = 1;
      j += 16;
      break;
    default:
      return 0;
    }
  }

  return keyid_found && public_found && random_found;
}

static void
server_setup(struct obstcp_server_ctx *ctx, const uint8_t *shared,
             const uint8_t *random) {
  uint8_t in_key[32], out_key[32];
  struct sha256_ctx sha;

  sha256_init(&sha);
  sha256_update(&sha, shared, 32);
  sha256_update(&sha, random, 16);
  sha256_final(&sha, in_key);

  sha256_init(&sha);
  sha256_update(&sha, shared, 32);
  sha256_update(&sha, in_key, 32);
  sha256_final(&sha, out_key);

  ctx->state = SRV_ST_FIRST_FRAME;
  memset(&ctx->u.b.in, 0, sizeof(struct obstcp_half_connection));
  memset(&ctx->u.b.out, 0, sizeof(struct obstcp_half_connection));

  ECRYPT_keysetup(ctx->u.b.in.input, in_key, 256, 0);
  ECRYPT_keysetup(ctx->u.b.out.input, out_key, 256, 0);

  ctx->u.b.in.used = 64;
  ctx->u.b.out.used = 64;
}

int EXPORTED
obstcp_server_read(struct obstcp_server_ctx *ctx,
                   struct iovec *outiov, unsigned *outlen, size_t *consumed,
                   struct obstcp_cursor *in) {
  *consumed = 0;

  if (ctx->state == SRV_ST_READING) {
    if (!cursor_has(in, 2)) {
      *outlen = 0;
      return 0;
    }

    uint8_t lenbuf[2];
    const uint8_t *lenbytes = cursor_read(lenbuf, in, 2);
    const uint16_t len = ntohs(*((uint16_t *) lenbytes));

    if (len > 384) {
      *outlen = 0;
      errno = EPROTO;
      return -1;
    }

    if (!cursor_has(in, len)) {
      *outlen = 0;
      return 0;
    }

    uint8_t bannerbuf[384];
    const uint8_t *banner = cursor_read(bannerbuf, in, len);
    const uint8_t *theirpublic = NULL, *nonce = NULL, *secret;
    uint8_t shared[32];
    uint32_t keyid = 0;

    if (!client_banner_parse(banner, len, &keyid, &theirpublic, &nonce)) {
      errno = EPROTO;
      return -1;
    }

    secret = keys_private_key_get(ctx->keys, keyid);
    if (!secret) {
      errno = ENOKEY;
      return -1;
    }

    curve25519_donna(shared, secret, theirpublic);
    server_setup(ctx, shared, nonce);
    *consumed += 2 + len;
  }

  // we don't have any MACs yet, so this is easy.
  struct iovec_cursor out;
  iovec_cursor_init(&out, outiov, *outlen);

  iovec_cursor_copy_cursor(&out, in);

  *outlen = out.i;

  unsigned i;
  for (i = 0; i < out.i; ++i) {
    encrypt(&ctx->u.b.in, outiov[i].iov_base, outiov[i].iov_base, outiov[i].iov_len);
    *consumed += outiov[i].iov_len;
  }

  return 0;
}

int EXPORTED
obstcp_server_ready(const struct obstcp_server_ctx *ctx) {
  return ctx->state > SRV_ST_READING;
}

ssize_t EXPORTED
obstcp_server_encrypt(struct obstcp_server_ctx *ctx, uint8_t *output,
                      const uint8_t *buffer, size_t len) {
  encrypt(&ctx->u.b.out, output, buffer, len);
  if (!ctx->frame_valid && ctx->state == SRV_ST_2ND_FRAME_PENDING) {
    ctx->state = SRV_ST_RUNNING;
  }

  ctx->frame_valid = 1;

  return len;
}

int EXPORTED
obstcp_server_prefix(struct obstcp_server_ctx *ctx, struct iovec *prefix) {
  static const uint8_t banner[2] = {0, 0};

  if (!ctx->frame_valid) return -1;

  if (ctx->state == SRV_ST_FIRST_FRAME) {
    prefix->iov_base = (void *) banner;
    prefix->iov_len = 2;
    ctx->state = SRV_ST_2ND_FRAME_PENDING;
    return 1;
  } else {
    prefix->iov_len = 0;
    return 0;
  }
}

unsigned EXPORTED
obstcp_server_frame_payload_sz(const struct obstcp_server_ctx *ctx) {
  return 65535;
}
// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// Client interfaces....

enum {
  CLI_ST_WRITING = 0,
  CLI_ST_READING,
  CLI_ST_RUNNING
};

static int
client_parse_advert(uint8_t *public, const char *advert, unsigned inlen) {
  uint8_t decoded[384];
  unsigned len, j = 0;
  char public_found = 0;
  uint32_t v;

  if (obs_base64_decode_length(inlen) > 384) return 0;
  if (!obs_base64_decode(decoded, &len, advert, inlen)) return 0;

  for (;;) {
    if (j == len) break;
    if (!varint_get(&v, decoded, len, &j)) return 0;
    switch (v >> 1) {
    case OBSTCP_KIND_PUBLIC:
      if (!(v & 1)) return 0;
      if (!varint_get(&v, decoded, len, &j)) return 0;
      if (v != 32) return 0;
      if (j + v > len) return 0;
      memcpy(public, decoded + j, 32);
      public_found = 1;
      j += 32;
      break;
    default:
      if (v & 1) {
        if (!varint_get(&v, decoded, len, &j)) return 0;
        if (j + v > len) return 0;
        j += v;
      }
    }
  }

  return public_found;
}

static unsigned
client_write_banner(uint8_t *banner, unsigned len, const struct obstcp_keypair *kp,
                    const uint8_t *random, const uint8_t *serverpublic) {
  unsigned j = 2;
  const uint32_t keyid = htonl(key_keyid(serverpublic));

  if (!varint_put(banner, len, &j, OBSTCP_KIND_PUBLIC << 1 | 1)) goto spc;
  if (!varint_put(banner, len, &j, 32)) goto spc;
  if (!buffer_put(banner, len, &j, kp->public_key, 32)) goto spc;

  if (!varint_put(banner, len, &j, OBSTCP_KIND_NONCE << 1 | 1)) goto spc;
  if (!varint_put(banner, len, &j, 16)) goto spc;
  if (!buffer_put(banner, len, &j, random, 16)) goto spc;

  if (!varint_put(banner, len, &j, OBSTCP_KIND_KEYID << 1 | 1)) goto spc;
  if (!varint_put(banner, len, &j, 4)) goto spc;
  if (!buffer_put(banner, len, &j, &keyid, 4)) goto spc;

  const uint16_t blen = j - 2;
  const uint16_t blen_be = htons(blen);
  memcpy(banner, &blen_be, sizeof(blen_be));

  return j;

 spc:
   // This is a programming error in this library
   abort();
}

int EXPORTED
obstcp_client_ctx_init(struct obstcp_client_ctx *ctx, struct obstcp_keys *keys,
                       const char *advert, unsigned len, const uint8_t *random) {
  uint8_t serverpublic[32], shared[32], in_key[32], out_key[32];
  struct sha256_ctx sha;

  if (!keys->keys) {
    errno = EINVAL;
    return 0;
  }

  if (!client_parse_advert(serverpublic, advert, len)) {
    errno = EINVAL;
    return 0;
  }

  curve25519_donna(shared, keys->keys->private_key, serverpublic);

  sha256_init(&sha);
  sha256_update(&sha, shared, 32);
  sha256_update(&sha, random, 16);
  sha256_final(&sha, out_key);

  sha256_init(&sha);
  sha256_update(&sha, shared, 32);
  sha256_update(&sha, out_key, 32);
  sha256_final(&sha, in_key);

  memset(ctx, 0, sizeof(struct obstcp_client_ctx));

  ECRYPT_keysetup(ctx->in.input, in_key, 256, 0);
  ECRYPT_keysetup(ctx->out.input, out_key, 256, 0);

  ctx->in.used = 64;
  ctx->out.used = 64;

  ctx->state = CLI_ST_WRITING;

  ctx->n = client_write_banner(ctx->buffer, sizeof(ctx->buffer),
                               keys->keys, random, serverpublic);

  return 1;
}

void EXPORTED
obstcp_client_banner(struct obstcp_client_ctx *ctx,
                     struct iovec *out) {
  if (ctx->state != CLI_ST_WRITING) abort();
  out->iov_base = (void *) ctx->buffer;
  out->iov_len = ctx->n;
  ctx->n = 0;

  ctx->state = CLI_ST_READING;
}

int EXPORTED
obstcp_client_read(struct obstcp_client_ctx *ctx,
                   struct iovec *outiov, unsigned *outlen, size_t *consumed,
                   struct obstcp_cursor *in) {
  if (ctx->state == CLI_ST_WRITING) {
    errno = EINVAL;
    return -1;
  }

  *consumed = 0;

  if (ctx->state == CLI_ST_READING) {
    // The server first sends us u16be length prefixed banner.
    if (!cursor_has(in, 2)) {
      *outlen = 0;
      return 0;
    }

    uint8_t lenbuf[2];
    const uint8_t *lenbytes = cursor_read(lenbuf, in, 2);
    const uint16_t len = ntohs(*((uint16_t *) lenbytes));

    if (len > 384) {
      *outlen = 0;
      errno = EPROTO;
      return -1;
    }

    if (!cursor_has(in, len)) {
      *outlen = 0;
      return 0;
    }

    uint8_t bannerbuf[384];
    //const uint8_t *bannerbytes = cursor_read(bannerbuf, in, len);
    // We ignore the banner for now.
    cursor_read(bannerbuf, in, len);

    ctx->state = CLI_ST_RUNNING;
    *consumed += len + 2;
  }

  assert(ctx->state == CLI_ST_RUNNING);

  // we don't have any MACs yet, so this is easy.
  struct iovec_cursor out;
  iovec_cursor_init(&out, outiov, *outlen);

  iovec_cursor_copy_cursor(&out, in);

  *outlen = out.i;

  unsigned i;
  for (i = 0; i < out.i; ++i) {
    encrypt(&ctx->in, outiov[i].iov_base, outiov[i].iov_base, outiov[i].iov_len);
    *consumed += outiov[i].iov_len;
  }

  return 0;
}

ssize_t EXPORTED
obstcp_client_encrypt(struct obstcp_client_ctx *ctx, uint8_t *output,
                      const uint8_t *buffer, size_t len) {
  encrypt(&ctx->out, output, buffer, len);

  return len;
}

int EXPORTED
obstcp_client_prefix(struct obstcp_client_ctx *ctx, struct iovec *prefix) {
  prefix->iov_len = 0;
  return 0;
}

unsigned EXPORTED
obstcp_client_frame_payload_sz(const struct obstcp_client_ctx *ctx) {
  return 65535;
}

// -----------------------------------------------------------------------------

static void
obstcp_accum_init(struct obstcp_accum *ac) {
  unsigned i;

  memset(ac, 0, sizeof(struct obstcp_accum));

  for (i = 0; i < OBSTCP_ACCUM_BUFFERS - 1; ++i) {
    ac->buffers[i].next = i + 1;
  }
  ac->buffers[OBSTCP_ACCUM_BUFFERS - 1].next = 0xff;

  ac->free_head = 0;
  ac->data_head = ac->data_tail = 0xff;
}

void EXPORTED
obstcp_client_accum_init(struct obstcp_accum *ac, struct obstcp_client_ctx *ctx) {
  obstcp_accum_init(ac);
  ac->is_server = 0;
  ac->frame_size = obstcp_client_frame_payload_sz(ctx);
  ac->ctx = ctx;
}

void EXPORTED
obstcp_server_accum_init(struct obstcp_accum *ac, struct obstcp_server_ctx *ctx) {
  obstcp_accum_init(ac);
  ac->is_server = 1;
  ac->frame_size = obstcp_server_frame_payload_sz(ctx);
  ac->ctx = ctx;
}

void EXPORTED
obstcp_accum_prepare(struct obstcp_accum *ac,
                     struct iovec *out, unsigned *onumout,
                     const struct iovec *in, unsigned numin) {
  const unsigned numout = *onumout;
  struct iovec_cursor outc, inc, inccopy;
  struct obstcp_accum_buffer *ab = NULL;
  uint8_t c;

  iovec_cursor_init(&outc, out, numout);
  iovec_cursor_init(&inc, (struct iovec *) in, numin);

  // walk the list of buffers and add them to the output list
  for (c = ac->data_head; c != 0xff; c = ab->next) {
    ab = &ac->buffers[c];

    if (iovec_cursor_full(&outc)) goto out;
    if (ab->prefix_used < ab->prefix_len) {
      iovec_cursor_append(&outc,
                          ab->prefix + ab->prefix_used,
                          ab->prefix_len - ab->prefix_used);
    }

    if (iovec_cursor_full(&outc)) goto out;
    iovec_cursor_copy(&outc, &inc, ab->payload_len - ab->payload_used);
  }

  if (iovec_cursor_full(&outc) || iovec_cursor_full(&inc)) goto out;

  // If there are buffers remaining and data still in the input, we might as
  // well encrypt some more.
  while (ac->free_head != 0xff && !iovec_cursor_full(&inc)) {
    unsigned frame_remaining = ac->frame_size;
    struct iovec iov, iniov;

    // save the current cursor so that we can copy from it later
    memcpy(&inccopy, &inc, sizeof(inc));

    // try to fill up a whole frame
    while (frame_remaining && !iovec_cursor_full(&inc)) {
      iovec_cursor_get(&iov, &inc, frame_remaining);
      if (ac->is_server) {
        obstcp_server_encrypt((struct obstcp_server_ctx *) ac->ctx,
                              iov.iov_base, iov.iov_base, iov.iov_len);
      } else {
        obstcp_client_encrypt((struct obstcp_client_ctx *) ac->ctx,
                              iov.iov_base, iov.iov_base, iov.iov_len);
      }
      frame_remaining -= iov.iov_len;
    }

    // pop a buffer from the free list
    const uint8_t buffer_num = ac->free_head;
    ab = &ac->buffers[ac->free_head];
    ac->free_head = ab->next;

    if (ac->data_tail != 0xff) {
      ac->buffers[ac->data_tail].next = buffer_num;
    } else {
      ac->data_head = buffer_num;
    }
    ac->data_tail = buffer_num;

    ab->payload_len = ac->frame_size - frame_remaining;
    ab->payload_used = ab->prefix_used = 0;
    ab->next = 0xff;

    if (ac->is_server) {
      obstcp_server_prefix((struct obstcp_server_ctx *) ac->ctx, &iniov);
    } else {
      obstcp_client_prefix((struct obstcp_client_ctx *) ac->ctx, &iniov);
    }

    assert(iniov.iov_len < OBSTCP_MAX_PREFIX);
    memcpy(ab->prefix, iniov.iov_base, iniov.iov_len);
    ab->prefix_len = iniov.iov_len;

    if (!iovec_cursor_full(&outc)) {
      iovec_cursor_append(&outc, ab->prefix, ab->prefix_len);
    }
    if (!iovec_cursor_full(&outc)) {
      iovec_cursor_copy(&outc, &inccopy, ab->payload_len);
    }
  }

 out:
  *onumout = outc.i;
  return;
}

ssize_t EXPORTED
obstcp_accum_commit(struct obstcp_accum *ac, ssize_t bytes) {
  struct obstcp_accum_buffer *ab = NULL;
  uint8_t c, next;
  ssize_t used = 0;

  if (bytes < 0) {
    errno = EINVAL;
    return -1;
  }

  for (c = ac->data_head; bytes && c != 0xff; c = next) {
    ab = &ac->buffers[c];

    if (ab->prefix_used < ab->prefix_len) {
      size_t a = ab->prefix_len - ab->prefix_used;
      if (a > bytes) a = bytes;
      ab->prefix_used += a;
      bytes -= a;
    }

    size_t a = ab->payload_len - ab->payload_used;
    if (a > bytes) a = bytes;
    ab->payload_used += a;
    bytes -= a;
    used += a;

    next = ab->next;

    if (ab->payload_len == ab->payload_used &&
        ab->prefix_len == ab->prefix_used) {

      ac->data_head = ab->next;
      if (ac->data_head == 0xff) ac->data_tail = 0xff;

      ab->next = ac->free_head;
      ac->free_head = c;
    }
  }

  // The user has claimed to have written more bytes than we've ever given
  // them.
  if (bytes) {
    errno = EINVAL;
    return -1;
  }

  return used;
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
// Copy, at most, @len bytes from @vb to @buffer
// -----------------------------------------------------------------------------
static size_t
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
// Discard, at most, @n bytes from a varbuf and return @n less the number of
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

struct varbuf_cursor {
  struct obstcp_cursor c;
  struct chunk *chunk;
  size_t read;
  uint8_t *extra;
  size_t used;
};

static int
varbuf_cursor_get(void *arg, struct iovec *iov, size_t n) {
  struct varbuf_cursor *c = arg;

  if (c->chunk) {
    size_t todo = c->chunk->used - c->read;
    if (todo > n)
      todo = n;
    iov->iov_base = c->chunk->data + c->read;
    iov->iov_len = todo;

    c->read += todo;
    if (c->read == c->chunk->used) {
      c->chunk = c->chunk->next;
      if (c->chunk) {
        c->read = c->chunk->read;
      } else {
        c->read = 0;
      }
    }

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

static int
varbuf_cursor_has(void *arg, size_t n) {
  struct varbuf_cursor *c = arg;
  size_t found = 0;
  const struct chunk *chunk = c->chunk;

  if (chunk) {
    found += chunk->used - c->read;
    chunk = chunk->next;

    while (found < n && chunk) {
      found += chunk->used;
      chunk = chunk->next;
    }
  } else {
    found += c->used - c->read;
  }

  return found >= n;
}

// -----------------------------------------------------------------------------
// Construct a generic cursor which walks a varbuf (don't modify it
// concurrently!) and, optionally, a single extra buffer.
// -----------------------------------------------------------------------------
static void
varbuf_cursor_init(struct varbuf_cursor *c, const struct varbuf *vb,
                   uint8_t *extra, size_t len) {
  c->c.get = varbuf_cursor_get;
  c->c.has = varbuf_cursor_has;
  c->chunk = vb->head;
  if (c->chunk) {
    c->read = c->chunk->read;
  } else {
    c->read = 0;
  }

  c->extra = extra;
  c->used = len;
  c->read = 0;
}

// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// Read buffers...

void EXPORTED
obstcp_rbuf_client_init(struct obstcp_rbuf *rbuf, struct obstcp_client_ctx *ctx) {
  rbuf->ctx = ctx;
  rbuf->is_server = 0;
  varbuf_init(&rbuf->in);
  varbuf_init(&rbuf->out);
}

void EXPORTED
obstcp_rbuf_server_init(struct obstcp_rbuf *rbuf, struct obstcp_server_ctx *ctx) {
  memset(rbuf, 0, sizeof(struct obstcp_rbuf));
  rbuf->ctx = ctx;
  rbuf->is_server = 1;
}

void EXPORTED
obstcp_rbuf_free(struct obstcp_rbuf *rbuf) {
  varbuf_free(&rbuf->in);
  varbuf_free(&rbuf->out);
}

ssize_t EXPORTED
obstcp_rbuf_read(struct obstcp_rbuf *rbuf, uint8_t *buffer, size_t len,
                 ssize_t (*read) (void *ctx, uint8_t *buffer, size_t len),
                 void *ctx) {

  size_t copied = varbuf_copy_out(buffer, len, &rbuf->out);
  len -= copied;
  off_t j = copied;

  if (!len)
    return j;

  static const size_t rbuflen = OBSTCP_MAX_FRAME + OBSTCP_MAX_PREFIX;
  uint8_t rbuffer[rbuflen];

  const ssize_t n = read(ctx, rbuffer, rbuflen);
  if (n < 1)
    return n;

  struct varbuf_cursor inc;
  varbuf_cursor_init(&inc, &rbuf->in, rbuffer, n);

  size_t consumed;
  struct iovec outiov[8];
  unsigned outlen = 8;

  if (rbuf->is_server) {
    if (obstcp_server_read((struct obstcp_server_ctx *) rbuf->ctx,
                           outiov, &outlen, &consumed,
                           (struct obstcp_cursor *) &inc) == -1)
      return -1;
  } else {
    if (obstcp_client_read((struct obstcp_client_ctx *) rbuf->ctx,
                           outiov, &outlen, &consumed,
                           (struct obstcp_cursor *) &inc) == -1)
      return -1;
  }

  // Walk the output iovec and copy into the output buffer
  struct iovec_cursor outc;
  iovec_cursor_init(&outc, outiov, outlen);

  while (len && !iovec_cursor_full(&outc)) {
    struct iovec iov;
    iovec_cursor_get(&iov, &outc, len);
    memcpy(buffer + j, iov.iov_base, iov.iov_len);
    j += iov.iov_len;
    len -= iov.iov_len;
  }

  // Buffer any remaining output
  if (varbuf_copy_iovec_cursor(&rbuf->out, &outc) == -1)
    return -1;

  // Discard all buffered input that was consumed
  const size_t remaining = varbuf_discard(&rbuf->in, consumed);

  if (remaining < n) {
    // Not all of @buffer was consumed
    varbuf_copy_in(&rbuf->in, rbuffer + remaining, n - remaining);
  }

  return j;
}

static ssize_t
read_wrapper(void *ctx, uint8_t *buffer, size_t len) {
  intptr_t fd = (intptr_t) ctx;
  ssize_t n;

  do {
    n = read(fd, buffer, len);
  } while (n == -1 && errno == EINTR);

  return n;
}

ssize_t EXPORTED
obstcp_rbuf_read_fd(struct obstcp_rbuf *rbuf, int fd,
                    uint8_t *buffer, size_t len) {
  return obstcp_rbuf_read(rbuf, buffer, len, read_wrapper, (void *)((intptr_t) fd));
}
// -----------------------------------------------------------------------------
