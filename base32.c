#include <stdint.h>
#include <errno.h>

#include "base32.h"

static const uint8_t kValues[] = {
99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,0,1,2,3,4,5,6,7,8,9,99,99,99,99,99,99,99,99,10,11,12,99,13,14,15,99,16,17,18,19,20,99,21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99,99,99,10,11,12,99,13,14,15,99,16,17,18,19,20,99,21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99};

unsigned
base32_decode_length(unsigned length) {
  return (length * 5) / 8;
}

int
base32_decode(uint8_t *output, const char *in, unsigned inlen) {
  unsigned i = 0, j = 0;
  unsigned v = 0, bits = 0;

  while (j < inlen) {
    if (in[j] & 0x80)
      goto PROTO;
    const uint8_t b = kValues[(int) in[j++]];
    if (b > 31)
      goto PROTO;

    v |= ((unsigned) b) << bits;
    bits += 5;

    if (bits >= 8) {
      output[i++] = v;
      bits -= 8;
      v >>= 8;
    }
  }

  return 1;

 PROTO:
  errno = EPROTO;
  return 0;
}

unsigned
base32_encode_length(unsigned length) {
  return ((length * 8) + 4) / 5;
}

void
base32_encode(char *output, const uint8_t *in, unsigned inlen) {
  unsigned i = 0, j = 0;
  unsigned v = 0, bits = 0;
  static const char kChars[] = "0123456789bcdfghjklmnpqrstuvwxyz";

  while (j < inlen) {
    v |= ((unsigned) in[j++]) << bits;
    bits += 8;

    while (bits >= 5) {
      output[i++] = kChars[v & 31];
      bits -= 5;
      v >>= 5;
    }
  }

  if (bits)
    output[i++] = kChars[v];
}
