// Copyright 2008, Google Inc.
// All rights reserved.

#ifndef LIBOBSTCP_H
#define LIBOBSTCP_H

#include <stdint.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PUBLIC __attribute__((visibility("default")))

// Some systems (like OS X) don't define ENOKEY, so we copy the value from
// Linux here.
#ifndef ENOKEY
#define ENOKEY 126
#endif

// Maximum frame prefix size
#define OBSTCP_MAX_PREFIX 64
// Maximum number of payload bytes in a frame
#define OBSTCP_MAX_FRAME 8192
// Maximum banner size
#define OBSTCP_MAX_BANNER 386

// -----------------------------------------------------------------------------
// This is a generic cursor. It's used in the read functions for when clients
// will need to pass in a buffer that they are maintaining. Clients may choose
// to implement this in a fixed size buffer, or dynamically etc.
//
// This would be a iovec[], but translating from the native list structures
// (bucket brigades in Apache, varbufs in this code etc) was a pain, thus this
// abstraction.
// -----------------------------------------------------------------------------
struct obstcp_cursor {
  // ---------------------------------------------------------------------------
  // This function is called with:
  // cursor: a pointer to the struct obstcp_cursor. Usually this will be casted
  //   to reveal a larger structure
  // iov: this should be filled out to point to an array of @n, or less, bytes.
  // n: the number of bytes requested
  // returns: 0 on eof.
  //
  // This function should get the next, contiguous, span of at most @n bytes
  // and return a vector to it in @iov. It should be assemble fragments to make
  // a linear buffer of @n bytes. It should advance its state so that future
  // get calls return successive buffers. On EOF, iov.iov_len should be 0 and
  // the function should return 0, even if @n is 0.
  // ---------------------------------------------------------------------------
  int (*get) (void *cursor, struct iovec *iov, size_t n);

  // ---------------------------------------------------------------------------
  // Call a function for each block of memory in the cursor, without moving the
  // current location of the cursor. If @f returns non-zero, stop the iteration
  // there and return that value. If the fold completes, return 0.
  // ---------------------------------------------------------------------------
  int (*fold) (void *cursor, int (*f) (void *, uint8_t *, size_t len), void *arg);
};

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
// Generate a binary obstcp "advert", this is the data that can be included in
// DNS CNAME or other side channels. It takes a variable argument list. The
// variable part of the argument list is a series of pairs where the first
// element of the pair is one of OBSTCP_ADVERT_* and the second depends on the
// value of the first, and may not even exist. The default key from the keyset
// is used for the public value.
//
// The variable list must be terminated with OBSTCP_ADVERT_END.
//
// output: a buffer to which the data is written
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
extern int PUBLIC obstcp_advert_create(uint8_t *output, unsigned length,
                                       const struct obstcp_keys *keys, ...);

// -----------------------------------------------------------------------------
// This acts exactly the same as the _advert_create function, above, except
// that the output is base32 encoded.
// -----------------------------------------------------------------------------
extern int PUBLIC obstcp_advert_base32_create(char *output, unsigned length,
                                              const struct obstcp_keys *keys, ...);

// -----------------------------------------------------------------------------
// Parse a binary obstcp "advert". This can be used to extract the advertised
// obfuscated and TLS port numbers.
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
// input: banner data
// length: the number of bytes in @input (not inc \n etc)
// returns: 1 on success, 0 on parse error.
// -----------------------------------------------------------------------------
extern int PUBLIC obstcp_advert_parse(const uint8_t *input, unsigned length, ...);

// -----------------------------------------------------------------------------
// This acts exactly the same as the _advert_parse function, above, except
// that the input must be base32 encoded.
// -----------------------------------------------------------------------------
extern int PUBLIC obstcp_advert_base32_parse(const char *input, unsigned length, ...);

// -----------------------------------------------------------------------------
// Extract an advert from a CNAME. The CNAME should be NUL terminated, with
// dots as usual (e.g. 'www.google.com').
//
// output: an output buffer to receive the base32 encoded advert
// outlen: (in/out) on entry, the number of bytes in @output. On successful
//   exit, but number of bytes written to @output
// input: a NUL terminated DNS name
//
// To avoid ENOSPC one can make the output buffer as large as the input. This
// will always work.
//
// Returns 1 on success, 0 on failure. Errno is set
//   ENOSPC: output buffer was too small
//   EEXIST: the name doesn't contain an encoded advert
// -----------------------------------------------------------------------------
extern int PUBLIC obstcp_advert_cname_extract(char *output, unsigned *outlen,
                                              const char *input);

// -----------------------------------------------------------------------------
// Returns the length of the DNS label encoding of a base32 encoded advert a
// given size.
// -----------------------------------------------------------------------------
extern unsigned PUBLIC obstcp_advert_cname_encode_sz(unsigned advertlen);

// -----------------------------------------------------------------------------
// Extract an advert from a hostent structure. This is the structure resulting
// from a gethostbyname(2) call.
//
// output: an output buffer to receive the base32 encoded advert
// outlen: (in/out) on entry, the number of bytes in @output. On successful
//   exit, but number of bytes written to @output
// hent: a hostent resulting from one of the gethostbyname(2) family.
//
// Since the longest DNS name is 256 bytes, that's a sensible size for the
// output buffer to avoid ENOSPC.
//
// Returns 1 on success, 0 on failure. Errno is set
//   ENOSPC: output buffer was too small
//   EEXIST: the name doesn't contain an encoded advert
// -----------------------------------------------------------------------------

struct hostent;
extern int PUBLIC obstcp_advert_hostent_extract(char *output, unsigned *outlen,
                                                const struct hostent *hent);

// -----------------------------------------------------------------------------
// Take a base32 encoded advert and split it into pieces for inclusion in a DNS
// name.
//
// output: an output buffer of sufficient size
// advert: base32 encoded advert
// advertlen: number of bytes in @advert
//
// The output buffer should be at least as large as
// obstcp_advert_cname_encode_sz returns.
//
// The result is a number of DNS labels (and is not NUL terminated). For
// example: "ae0xx12345679.ae0xx12346789."
// -----------------------------------------------------------------------------
extern void PUBLIC obstcp_advert_cname_encode(char *output,
                                              const char *advert, unsigned advertlen);

// -----------------------------------------------------------------------------
// This is the crypto context for a given direction of data
// -----------------------------------------------------------------------------
struct obstcp_half_connection {
  uint8_t  keystream[64];  // keystream bytes
  unsigned used;  // number of bytes of @keystream used
  uint8_t key[32];        // salsa20/8 context
  uint8_t block_ctr[16];  // salsa20/8 context
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
// Process new data from the network
//
// outiov: an array of vectors to put output data in
// outlen: (in/out) the length (in elements) of @outiov
// consumed: (output)
// in: a cursor of data from the network.
// returns: -1 on error, 0 on success
//
// Input from the network is contained in a cursor.  This includes unprocessed
// data from previous calls. The data pointed to by these vectors may be
// mutated by this call.
//
// On successful exit, @outlen contains the number of vectors of processed,
// ready data in @outiov. @consumed contains the number of bytes from the input
// vectors that was consumed. Any unconsumed data must be at the head of the
// input vectors next time that this function is called.
//
// If you wish to know if key agreement has completed after calling this
// function, use obstcp_server_ready.
//
// If this function is a pain to use, see the rbuf stuff below.
// -----------------------------------------------------------------------------
int PUBLIC obstcp_server_read(struct obstcp_server_ctx *ctx,
                              struct iovec *outiov, unsigned *outlen,
                              size_t *consumed,
                              struct obstcp_cursor *in);

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
// Return the maximum number of bytes in a single frame. This will always
// be < 2**16. If the current context doesn't have framing configured, the
// result will be 2**16 - 1.
// -----------------------------------------------------------------------------
unsigned PUBLIC obstcp_server_frame_payload_sz(const struct obstcp_server_ctx *ctx);

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
int PUBLIC obstcp_client_read(struct obstcp_client_ctx *ctx,
                              struct iovec *outiov, unsigned *outlen,
                              size_t *consumed,
                              struct obstcp_cursor *c);

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
// Same as the server version
// -----------------------------------------------------------------------------
unsigned PUBLIC obstcp_client_frame_payload_sz(const struct obstcp_client_ctx *ctx);

// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// Accumulation buffers.
//
// These are helper functions for dealing with the business of keeping track of
// what data has been encrypted. If you are writing code from scratch you
// should be able to avoid using these. However, if you are modifying existing
// code they may be of use...

#define OBSTCP_ACCUM_BUFFERS 6

struct obstcp_accum_buffer {
  uint16_t payload_len, payload_used;
  uint8_t prefix_len, prefix_used;
  uint8_t next, padding;
  uint8_t prefix[OBSTCP_MAX_PREFIX];
};

struct obstcp_accum {
  void *ctx;
  uint16_t frame_size;
  struct obstcp_accum_buffer buffers[OBSTCP_ACCUM_BUFFERS];
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
// result: the number of bytes of data that the kernel enqueued.
// returns: the number of bytes of application level data that the kernel
//   enqueued.
//
// If @result < 0 then this function returns -1 and sets errno to EINVAL. You
// should check for errors from the writev before calling this function. If
// @result is greater than the number of bytes in the output iovecs from
// _prepare, the same thing happens.
// -----------------------------------------------------------------------------
ssize_t PUBLIC obstcp_accum_commit(struct obstcp_accum *ac, ssize_t result);
// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// Read buffers.
//
// These are helper functions which use the lower level functions
// obstcp_[client|server]_read and maintain the queues needed to make
// everything work like a wrapper around a read(2) like function...

// -----------------------------------------------------------------------------
// length: the amount of alloced data at @data
// used: number of bytes written to (<= @length)
// read: number of bytes consumed (<= @used)
// -----------------------------------------------------------------------------

struct chunk;

// -----------------------------------------------------------------------------
// A varbuf is a double-linked list of chunks. We fill the varbuf from the
// tail. Each chunk is a certain minimum size (VARBUF_CHUNK_SIZE) so that a
// peer who is feeding us data one byte at a time cannot cause us to alloc huge
// amount of overhead to keep track of lots of 1 byte buffers.
// -----------------------------------------------------------------------------
struct varbuf {
  struct chunk *head, *tail;
};

// -----------------------------------------------------------------------------
// Note that this structure contains pointers to malloced memory, so you must
// _free it when done.
// -----------------------------------------------------------------------------
struct obstcp_rbuf {
  void *ctx;
  struct varbuf in, out;
  char is_server;
};

// -----------------------------------------------------------------------------
// Setup and clear an rbuf for a client context
// -----------------------------------------------------------------------------
void PUBLIC obstcp_rbuf_client_init(struct obstcp_rbuf *rbuf,
                                    struct obstcp_client_ctx *ctx);

// -----------------------------------------------------------------------------
// Setup and clear an rbuf for a server context
// -----------------------------------------------------------------------------
void PUBLIC obstcp_rbuf_server_init(struct obstcp_rbuf *rbuf,
                                    struct obstcp_server_ctx *ctx);

// -----------------------------------------------------------------------------
// Free all malloced blocks pointed to by @rbuf
// -----------------------------------------------------------------------------
void PUBLIC obstcp_rbuf_free(struct obstcp_rbuf *rbuf);

// -----------------------------------------------------------------------------
// @buffer: (output) a buffer to put the resulting data in
// @len: number of bytes in @buffer
// @read: a read function
// @ctx: the first argument to the read function
// returns: see read(2)
// -----------------------------------------------------------------------------
ssize_t PUBLIC obstcp_rbuf_read
  (struct obstcp_rbuf *rbuf, uint8_t *buffer, size_t len,
   ssize_t (*read) (void *ctx, uint8_t *buffer, size_t len), void *ctx);

// -----------------------------------------------------------------------------
// This is the same as obstcp_rbuf_read, but it uses read(2) to read from the
// file descriptor.
// -----------------------------------------------------------------------------
ssize_t PUBLIC obstcp_rbuf_read_fd(struct obstcp_rbuf *rbuf, int fd,
                                   uint8_t *buffer, size_t len);
// -----------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

#endif  // LIBOBSTCP_H
