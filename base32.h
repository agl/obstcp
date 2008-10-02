#ifndef BASE_32_H
#define BASE_32_H

#include <stdint.h>

// -----------------------------------------------------------------------------
// Note that base32 decoding with this library is truncating - i.e. if a
// parital byte remains at the end of decoding it is dropped rather than
// emitted...

// -----------------------------------------------------------------------------
// Return the number of bytes needed to store the result of decoding the given
// number of base32 bytes.
// -----------------------------------------------------------------------------
unsigned base32_decode_length(unsigned length);

// -----------------------------------------------------------------------------
// output: a buffer large enough to hold the output
// outlen: (output) on success, the number of bytes written
// in: a pointer to the base32 data
// inlen: number of bytes in @in
//
// returns: 1 on success, 0 otherwise.
// -----------------------------------------------------------------------------
int base32_decode(uint8_t *output, const char *in, unsigned inlen);

// -----------------------------------------------------------------------------
// Return the number of bytes needed to store the base32 encoding of the given
// number of byte of binary input.
// -----------------------------------------------------------------------------
unsigned base32_encode_length(unsigned length);

// -----------------------------------------------------------------------------
// output: a buffer large enough to hold the result
// in: binary input
// inlen: number of bytes in @in
// -----------------------------------------------------------------------------
void base32_encode(char *output, const uint8_t *in, unsigned inlen);

// -----------------------------------------------------------------------------

#endif  // BASE_32_H
