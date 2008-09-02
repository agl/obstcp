#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <stdio.h>   // DEBUG ONLY

#include <arpa/inet.h>

#include "libobstcp.h"
#include "sha256.h"
#include "base64.h"
#include "salsa20.h"

#define EXPORTED __attribute__ ((visibility("default")))

#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

extern void curve25519_donna(uint8_t *mypublic, const uint8_t *secret,
                             const uint8_t *basepoint);

static void
print_bytes(const uint8_t *bytes, unsigned len) {
  unsigned i;

  for (i = 0; i < len; ++i) {
    fprintf(stderr, "%02x", bytes[i]);
  }
}

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

ssize_t EXPORTED
obstcp_server_read(int fd, struct obstcp_server_ctx *ctx,
                   uint8_t *buffer, size_t blen, char *ready) {
  ssize_t n;

  if (ctx->state == SRV_ST_READING) {
    if (ctx->u.a.read >= 2) {
      uint16_t len;

      memcpy(&len, ctx->u.a.buffer, 2);
      len = ntohs(len);

      if (len > 384) {
        errno = EPROTO;
        return -1;
      }

      len += 2;  // for the length bytes

      do {
        n = read(fd, ctx->u.a.buffer + ctx->u.a.read, len - ctx->u.a.read);
      } while (n == -1 && errno == EINTR);

      if (n < 1) return n;
      ctx->u.a.read += n;
      if (ctx->u.a.read == len) {
        const uint8_t *theirpublic = NULL, *nonce = NULL, *secret;
        uint8_t shared[32];
        uint32_t keyid = 0;

        // finished reading the client's banner
        if (!client_banner_parse(ctx->u.a.buffer + 2, ctx->u.a.read - 2,
                                 &keyid, &theirpublic, &nonce)) {
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
        return obstcp_server_read(fd, ctx, buffer, blen, ready);
      } else {
        errno = EAGAIN;
        return -1;
      }
    } else {
      do {
        n = read(fd, ctx->u.a.buffer + ctx->u.a.read, 2 - ctx->u.a.read);
      } while (n == -1 && errno == EINTR);

      if (n < 1) return n;
      ctx->u.a.read += n;
      if (ctx->u.a.read == 2) {
        return obstcp_server_read(fd, ctx, buffer, blen, ready);
      } else {
        errno = EAGAIN;
        return -1;
      }
    }
  } else {
    do {
      n = read(fd, buffer, blen);
    } while (n == -1 && errno == EINTR);

    if (n < 1) return n;
    encrypt(&ctx->u.b.in, buffer, buffer, n);
    *ready = 1;
    return n;
  }
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
    return 1;
  } else {
    prefix->iov_len = 0;
    return 0;
  }
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

ssize_t EXPORTED
obstcp_client_in(struct obstcp_client_ctx *ctx,
                 uint8_t *buffer, size_t blen, char *ready,
                 ssize_t (*read) (void *, void *buffer, size_t len), void *ptr) {
  ssize_t n;

  if (ctx->state == CLI_ST_WRITING) {
    errno = EINVAL;
    return -1;
  }

  if (ctx->state == CLI_ST_READING) {
    if (ctx->n >= 2) {
      uint16_t len;

      memcpy(&len, ctx->buffer, 2);
      len = ntohs(len);

      if (len > 384) {
        errno = EPROTO;
        return -1;
      }

      len += 2;  // for the length bytes

      if (ctx->n < len) {
        do {
          n = read(ptr, ctx->buffer + ctx->n, len - ctx->n);
        } while (n == -1 && errno == EINTR);

        if (n < 1) return n;
        ctx->n += n;
      }

      if (ctx->n == len) {
        // we ignore the server's banner for now
        ctx->state = CLI_ST_RUNNING;
        return obstcp_client_in(ctx, buffer, blen, ready, read, ptr);
      } else {
        errno = EAGAIN;
        return -1;
      }
    } else {
      do {
        n = read(ptr, ctx->buffer + ctx->n, 2 - ctx->n);
      } while (n == -1 && errno == EINTR);

      if (n < 1) return n;
      ctx->n += n;
      if (ctx->n == 2) {
        return obstcp_client_in(ctx, buffer, blen, ready, read, ptr);
      } else {
        errno = EAGAIN;
        return -1;
      }
    }
  } else {
    do {
      n = read(ptr, buffer, blen);
    } while (n == -1 && errno == EINTR);

    if (n < 1) return n;
    encrypt(&ctx->in, buffer, buffer, n);
    *ready = 1;
    return n;
  }
}

static ssize_t
read_wrapper(void *fdptr, void *buffer, size_t len) {
  int fd = (intptr_t) fdptr;
  return read(fd, buffer, len);
}

ssize_t PUBLIC
obstcp_client_read(int fd, struct obstcp_client_ctx *ctx,
                   uint8_t *buffer, size_t len, char *ready) {
  intptr_t fdptr = (intptr_t) fd;
  return obstcp_client_in(ctx, buffer, len, ready, read_wrapper, (void *) fdptr);
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


// -----------------------------------------------------------------------------

void EXPORTED
obstcp_accum_init(struct obstcp_accum *ac) {
  ac->head = 0xffff;
}

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

static char
iovec_cursor_full(struct iovec_cursor *c) {
  return c->i == c->count;
};

static void
iovec_cursor_append(struct iovec_cursor *c, const void *a, size_t len) {
  c->iov[c->i].iov_base = (void *) a;
  c->iov[c->i++].iov_len = len;
};

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

void EXPORTED
obstcp_accum_prepare(struct obstcp_accum *ac,
                     struct iovec *out, unsigned *onumout,
                     const struct iovec *in, unsigned numin) {
  const unsigned numout = *onumout;
  struct iovec_cursor outc, inc;
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
      iovec_cursor_append(&outc, iov.iov_base, iov.iov_len);
    }
  }

 out:
  *onumout = outc.i;
  return;
}

int EXPORTED
obstcp_accum_commit(struct obstcp_accum *ac, size_t bytes,
                    unsigned *oiovecs, size_t *oremainder) {
  struct obstcp_accum_buffer *ab = NULL;
  uint8_t c, next;
  unsigned iovecs = 0;
  size_t remainder = 0;

  for (c = ac->data_head; bytes && c != 0xff; c = next) {
    if (ab->prefix_used < ab->prefix_len) {
      size_t a = ab->prefix_len - ab->prefix_used;
      if (a > bytes) a = bytes;
      ab->prefix_len += a;
      bytes -= a;
    }

    size_t a = ab->payload_len - ab->payload_used;
    if (a > bytes) a = bytes;
    ab->payload_used += a;
    bytes -= a;
    remainder = a;

    next = ab->next;

    if (ab->payload_len == ab->payload_used &&
        ab->prefix_len == ab->prefix_used) {

      ac->data_head = ab->next;
      if (ac->data_head == 0xff) ac->data_tail = 0xff;

      ac->free_head = c;
      ab->next = ac->free_head;

      iovecs++;
      remainder = 0;
    }
  }

  // The user has claimed to have written more bytes than we've ever given
  // them.
  if (bytes) {
    errno = EINVAL;
    return -1;
  }

  *oiovecs = iovecs;
  *oremainder = remainder;

  return 0;
}
