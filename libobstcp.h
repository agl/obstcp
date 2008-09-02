#ifndef LIBOBSTCP_H
#define LIBOBSTCP_H

#include <stdint.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PUBLIC __attribute__((visibility("default")))

#define OBSTCP_MAX_PREFIX 64

// -----------------------------------------------------------------------------
// struct obstcp_keypair - a public/private key pair
// keyid: the 32-bit xor folding of the public key
// -----------------------------------------------------------------------------
struct obstcp_keypair {
  uint8_t private_key[32];
  uint8_t public_key[32];
  uint32_t keyid;
  struct obstcp_keypair *next;
};

struct obstcp_keys {
  struct obstcp_keypair *keys;
};

// -----------------------------------------------------------------------------
// Setup a keyset structure. This must be called before any other operations
// on the keyset.
// -----------------------------------------------------------------------------
extern void PUBLIC obstcp_keys_init(struct obstcp_keys *keys);
// -----------------------------------------------------------------------------
// Calculate the public key from a private key and prepend the key pair to the
// list of keys installed in the keyset. This becomes the default key
//
// returns: 1 on success, 0 on error, in which case errno is set:
//   ENOMEM: out of memory
//   ENOSPC: a key with the same keyid is already in the keyset
// -----------------------------------------------------------------------------
extern int PUBLIC obstcp_keys_key_add(struct obstcp_keys *keys,
                                      const uint8_t *private_key);
// -----------------------------------------------------------------------------
// Free all keys contained in the keyset
// -----------------------------------------------------------------------------
extern void PUBLIC obstcp_keys_free(struct obstcp_keys *keys);

// -----------------------------------------------------------------------------
// Keys for the variable arguments part of obstcp_advert_create and
// obstcp_advert_parse
// -----------------------------------------------------------------------------
enum {
  OBSTCP_ADVERT_END = 0,      // no argument
  OBSTCP_ADVERT_OBSPORT,      // takes an int giving the port
  OBSTCP_ADVERT_TLSPORT,      // takes an int giving the port
};

// -----------------------------------------------------------------------------
// Generate a base64 encoded obstcp "advert", this is the data that can be
// included in a DNS TXT record of via other side channels. It takes a variable
// argument list. The variable part of the argument list are a series of pairs
// where the first element of the pair is one of OBSTCP_ADVERT_* and the second
// depends on the value of the first, and may not even exist. The default key
// from the keyset is used for the public value.
//
// The variable list must be terminated with OBSTCP_ADVERT_END.
//
// output: a buffer to which the base64 encoded data is written
// length: number of bytes of space in @output
// returns: on success a value <= to @length is returned. This is the number of
//   bytes written. If @output was too small, a value > @length is returned.
//   This is the number of bytes that is required. Otherwise -1 is returned and
//   errno is set:
//
//   E2BIG: too many options were selected
//   EINVAL: an unknown or invalid pair was found in the arguments
//   ENOKEY: no default key was found in the keyset
// -----------------------------------------------------------------------------
int PUBLIC obstcp_advert_create(char *output, unsigned length,
                                const struct obstcp_keys *keys, ...);

// -----------------------------------------------------------------------------
// Parse a base64 encoded obstcp "advert". This can be used to extract the
// advertised obfuscated and TLS port numbers.
//
// The variable arguments come in pairs. The first of each pair is one of
// OBSTCP_ADVERT_* which are shared with obstcp_advert_create, above. However,
// since this is a parsing function, where, say, OBSTCP_ADVERT_OBSPORT is
// documented as having an int as its second element, for this function is
// would be a pointer to an int.
//
// The variable list must be terminated with OBSTCP_ADVERT_END.
//
// For elements which aren't found a special value is used to denote this. For
// port numbers, this value is 0.
//
// input: the base64 encoded banner
// length: the number of bytes in @input (not inc \n etc)
// returns: 1 on success, 0 on parse error.
// -----------------------------------------------------------------------------
int PUBLIC obstcp_advert_parse(const char *input, unsigned length, ...);

// -----------------------------------------------------------------------------
// This is the crypto context for a given direction of data
// -----------------------------------------------------------------------------
struct obstcp_half_connection {
  uint8_t  keystream[64];  // keystream bytes
  unsigned used;  // number of bytes of @keystream used
  uint32_t input[16];  // salsa20 context
};

// -----------------------------------------------------------------------------
// Server interfaces...
//
// These functions are designed to be used by the 'server' side of the
// connection. It's up to the user of this library to decide which side is the
// server, it doesn't have to correspond to the sockets API notion of a server,
// although it's expected that it usually will.

struct obstcp_server_ctx {
  const struct obstcp_keys *keys;
  union {
    struct {
      uint8_t buffer[386];
      unsigned read;
    } a;
    struct {
      struct obstcp_half_connection in;
      struct obstcp_half_connection out;
    } b;
  } u;

  int state;
  char frame_open, frame_valid;
};

// -----------------------------------------------------------------------------
// Setup a context structure. This must be called before any other operations
// on the context struture.
// -----------------------------------------------------------------------------
void PUBLIC obstcp_server_ctx_init(struct obstcp_server_ctx *ctx,
                                   const struct obstcp_keys *keys);

// -----------------------------------------------------------------------------
// Read from a socket
// fd: the file descriptor to read from
// buffer: buffer to write data to
// len: number of bytes in @buffer
// ready: (output) on success, this is true if a MAC was successfully
//   calculated.
//
// Reading from a socket has two phases:
//   1) setup phase, before key agreement has completed. In this phase this
//      function with return -1 with errno set to EAGAIN until it has enough
//      data to complete key agreement.
//
//      If key agreement is successful, we move to phase two. Otherwise, we
//      return -1 and set errno to EPROTO.
//
//   2) In this phase we are reading application data from the socket. It may
//      be that the data is MAC protected. In this case, the read calls will
//      return positive byte counts, but *ready will be false on return. Once
//      the MAC has been read and checked *ready will be true. This means that
//      all the data since the last time ready returned true is valid and can
//      be processed. There cannot be > 16K of unready data.
//
//      Do not use this for application level framing since MAC may not be in
//      operation - in this case *ready is always set to true.
//
// Otherwise, this call returns like read(2) - i.e. 0 return means EOF etc. One
// exception is that this call will never return -1 with an errno of EINTR. The
// socket can be blocking or non-blocking.
//
// If you wish to know if key agreement has completed after calling this
// function, use obstcp_server_ready.
// -----------------------------------------------------------------------------
ssize_t PUBLIC obstcp_server_read(int fd, struct obstcp_server_ctx *ctx,
                                  uint8_t *buffer, size_t len, char *ready);

// -----------------------------------------------------------------------------
// Returns true iff key agreement has completed.
// -----------------------------------------------------------------------------
int PUBLIC obstcp_server_ready(const struct obstcp_server_ctx *ctx);

// -----------------------------------------------------------------------------
// Write examples:
//
// Simple case: in this case, the application is writing blocks of data to a
// socket. It would normally use a series of write() calls. The socket is
// blocking.
//
// ssize_t write_data(int fd, uint8_t *data, size_t len) {
//   struct iovec[2] iov;
//
//   const unsigned n = obstcp_server_encrypt(ctx, data, data, len);
//
//   switch (obstcp_server_prefix(ctx, &iovec[0])) {
//   case -1:
//     abort();
//   case 0:
//     return write(fd, data, n);
//   default:
//     iovec[1].iov_base = data;
//     iovec[1].iov_len = n;
//     return writev(fd, iovec, 2);
//   }
// }
//
// Note that, for non-blocking sockets it's up to the application to deal with
// feeding the data to the socket. However, obstcp_server_prefix may be called
// repeatedly to get the same data.
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// This library doesn't perform writing as such, instead call this function to
// encrypt the data in preparation for writing.
//
// output: encrypted data is written here (maybe equal to @buffer)
// buffer: data to be encrypted
// len: the length, in bytes, of @buffer and @output.
// returns: the number of bytes encrypted
//
// A frame is finite, so if you repeatedly call this function it may return
// less than @len bytes to denote that the frame is full.
//
// NB that the peer cannot process anything until a frame's worth of data has
// been processed. Thus, if this is the end of a message, and you expect the
// client to answer you, you must close out the frame by calling _prefix.
//
// Before writing anything to a socket you must call obstcp_server_prefix to get
// the prepended data for the frame.
// -----------------------------------------------------------------------------
ssize_t PUBLIC obstcp_server_encrypt(struct obstcp_server_ctx *ctx,
                                     uint8_t *output, const uint8_t *buffer, size_t len);

// -----------------------------------------------------------------------------
// The protocol may need to prepend data to a frame. Call this function to get
// that data.
//
// returns: -1 on error, or the number of iovecs with data.
//
// If this function returns -1 it means there has been a programming error on
// the part of the library user.  Aborting the process is reasonable in this
// case.
//
// Note that some connections may not having framing, thus this function may
// return 0. It's worth detecting this and falling back to a simple write()
// rather than a writev() in this case.
// -----------------------------------------------------------------------------
int PUBLIC obstcp_server_prefix(struct obstcp_server_ctx *ctx, struct iovec *prefix);

// -----------------------------------------------------------------------------



// -----------------------------------------------------------------------------
// Client interfaces...

struct obstcp_client_ctx {
  uint8_t buffer[386];
  unsigned n;

  struct obstcp_half_connection in;
  struct obstcp_half_connection out;

  int state;
  ssize_t frame_size;
  char frame_open;
};

// -----------------------------------------------------------------------------
// keys: a keyset for the client. Only the default key will be uesd.
// advert: a base64-encoded advert for the server. This can be obtained via TXT
//   records in DNS or any other side channel.
// len: length of @advert, in bytes.
// random: 16 random bytes, never to be reused
// returns: 1 on success, 0 on failure (in which case errno is set)
//
// Obviously, the advert can fail to parse, in which case errno is set to
// EINVAL.
// -----------------------------------------------------------------------------
int PUBLIC obstcp_client_ctx_init(struct obstcp_client_ctx *ctx, struct obstcp_keys *keys,
                                  const char *advert, unsigned len,
                                  const uint8_t *random);

// -----------------------------------------------------------------------------
// After connecting the socket you must call this function to get the banner
// that is to be sent to the server. This function must be called exactly once.
// To do otherwise will trigger an assertion failure. The banner returned in
// the iovec must be completed enqueued to the kernel's socket buffer before
// doing anything else with this context object.
// -----------------------------------------------------------------------------
void PUBLIC obstcp_client_banner(struct obstcp_client_ctx *ctx,
                                 struct iovec *out);

// -----------------------------------------------------------------------------
// Same as the server version
// -----------------------------------------------------------------------------
ssize_t PUBLIC obstcp_client_read(int fd, struct obstcp_client_ctx *ctx,
                                  uint8_t *buffer, size_t len, char *ready);

// -----------------------------------------------------------------------------
// FIXME: document
// -----------------------------------------------------------------------------
ssize_t PUBLIC obstcp_client_in(struct obstcp_client_ctx *ctx,
                 uint8_t *buffer, size_t blen, char *ready,
                 ssize_t (*read) (void *, void *buffer, size_t len), void *ptr);

// -----------------------------------------------------------------------------
// Same as the server version
// -----------------------------------------------------------------------------
ssize_t PUBLIC obstcp_client_encrypt(struct obstcp_client_ctx *ctx,
                                     uint8_t *output, const uint8_t *buffer, size_t len);

// -----------------------------------------------------------------------------
// Same as the server version
// -----------------------------------------------------------------------------
int PUBLIC obstcp_client_prefix(struct obstcp_client_ctx *ctx, struct iovec *prefix);

// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// Accumulation buffers.
//
// These are helper functions for dealing with the business of keeping track of
// what data has been encrypted. If you are writing code from scratch you
// should be able to avoid using these. However, if you are modifying existing
// code they may be of use...

struct obstcp_accum_buffer {
  uint16_t payload_len, payload_used;
  uint8_t prefix_len, prefix_used;
  uint8_t next, padding;
  uint8_t prefix[OBSTCP_MAX_PREFIX];
};

struct obstcp_accum {
  void *ctx;
  uint16_t head;
  uint16_t frame_size;
  struct obstcp_accum_buffer buffers[6];
  uint8_t free_head, data_head, data_tail, is_server;
};

// -----------------------------------------------------------------------------
// Init an accum_buffer object using a client context for encryption
// -----------------------------------------------------------------------------
void PUBLIC obstcp_client_accum_init(struct obstcp_accum *,
                                     struct obstcp_client_ctx *ctx);

// -----------------------------------------------------------------------------
// Init an accum_buffer object using a server context for encryption
// -----------------------------------------------------------------------------
void PUBLIC obstcp_server_accum_init(struct obstcp_accum *,
                                     struct obstcp_server_ctx *ctx);

// -----------------------------------------------------------------------------
// Fills in a number of output iovec structures with data that is ready to be
// transmitted. The source of the output is a array of input iovec objects
// that are encrypted in place.
//
// ac: a valid accum_buffer structure
// out: (output) points to the start of an array of iovec structures
// numout: (input/output) on entry, contains the number of iovec structures
//   pointed to by @out. On exit, contains the number of valid structures
// in; an array of iovec structures pointing to application level data that is
//   to be encrypted in place.
// numin: the number of iovecs pointed to by @in
//
// Note that you are expected to call this multiple times since the kernel
// generally won't enqueue all the data you give it unless it's only a small
// amount. After enqueuing data with the kernel you must call _commit (below)
// to tell the accum buffer that some data is done with.
//
// Next time you call this function, you must call it with the correct iovecs.
// That is, if you call it with input iovecs A, B, C, and then commit tells you
// that it's done with one and a half iovecs, next time you call _prepare, it's
// with B[n..], C (and possibly D etc).
// -----------------------------------------------------------------------------
void PUBLIC obstcp_accum_prepare(struct obstcp_accum *ac,
                                 struct iovec *out, unsigned *numout,
                                 const struct iovec *in, unsigned numin);

// -----------------------------------------------------------------------------
// After enqueuing data with the kernel, call this function to find out how
// much application level data has been enqueued.
//
// ac: a valid accum_buffer structure, on which _prepare has just been called
// result: the number of bytes that the kernel enqueued
// iovecs: (output) the number of input iovecs enqueued
// remainder: (output) the number of bytes in the remaining iovec which have
//   been enqueued
// -----------------------------------------------------------------------------
int PUBLIC obstcp_accum_commit(struct obstcp_accum *ac, size_t result,
                               unsigned *iovecs, size_t *remainder);

#ifdef __cplusplus
}
#endif

#endif  // LIBOBSTCP_H
