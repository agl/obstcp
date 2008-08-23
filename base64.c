#include <stdint.h>

static const char kEncoding[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsigned obs_base64_encode_length(unsigned length) {
  return ((length + 2) / 3) * 4;
}

unsigned
obs_base64_encode(char *output, const uint8_t *input, unsigned length) {
  char *const orig_output = output;

  while (length >= 3) {
    uint32_t v = (input[0] << 16) |
                 (input[1] << 8) |
                 input[2];
    *output++ = kEncoding[(v >> 18)];
    v <<= 6; v &= 0xffffff;
    *output++ = kEncoding[(v >> 18)];
    v <<= 6; v &= 0xffffff;
    *output++ = kEncoding[(v >> 18)];
    v <<= 6; v &= 0xffffff;
    *output++ = kEncoding[(v >> 18)];
    input += 3;
    length -= 3;
  }

  switch (length) {
    case 0:
      break;
    case 1:
      *output++ = kEncoding[(*input) >> 2];
      *output++ = kEncoding[((*input) & 0x3) << 4];
      *output++ = '=';
      *output++ = '=';
      break;
    case 2:
      *output++ = kEncoding[(*input) >> 2];
      *output++ = kEncoding[(((*input) & 0x3) << 4) |
                            (input[1] >> 4)];
      *output++ = kEncoding[(input[1] & 0xf) << 2];
      *output++ = '=';
  }

  return output - orig_output;
}

unsigned
obs_base64_decode_length(unsigned length) {
  return (length >> 2) * 3;
}

static const uint8_t kDecoding[] = {62,255,255,255,63,52,53,54,55,56,57,58,59,60,61,255,255,255,-2,255,255,255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,255,255,255,255,255,255,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
static const uint8_t kDecodingBias = 43;

int
obs_base64_decode(uint8_t *output, unsigned *out_len, const char *input, unsigned length) {
  uint8_t *const orig_output = output;

  if (length & 3) return 0;

  while (length > 4) {
    if (input[0] < kDecodingBias) return 0;
    const uint8_t v0 = kDecoding[input[0] - kDecodingBias];
    if (v0 == 255) return 0;

    if (input[1] < kDecodingBias) return 0;
    const uint8_t v1 = kDecoding[input[1] - kDecodingBias];
    if (v1 == 255) return 0;

    if (input[2] < kDecodingBias) return 0;
    const uint8_t v2 = kDecoding[input[2] - kDecodingBias];
    if (v2 == 255) return 0;

    if (input[3] < kDecodingBias) return 0;
    const uint8_t v3 = kDecoding[input[3] - kDecodingBias];
    if (v3 == 255) return 0;

    uint32_t v = (v0 << 18) |
                 (v1 << 12) |
                 (v2 << 6) |
                 v3;
    *output++ = v >> 16;
    v <<= 8; v &= 0xffffff;
    *output++ = v >> 16;
    v <<= 8; v &= 0xffffff;
    *output++ = v >> 16;

    input += 4;
    length -= 4;
  }

  if (input[0] < kDecodingBias) return 0;
  const uint8_t v0 = kDecoding[input[0] - kDecodingBias];
  if (v0 == 255) return 0;

  if (input[1] < kDecodingBias) return 0;
  const uint8_t v1 = kDecoding[input[1] - kDecodingBias];
  if (v1 == 255) return 0;

  if (input[3] == '=') {
    if (input[2] == '=') {
      *output++ = (v0 << 2 | v1 >> 4);
    } else {
      if (input[2] < kDecodingBias) return 0;
      const uint8_t v2 = kDecoding[input[2] - kDecodingBias];
      if (v2 == 255) return 0;

      *output++ = (v0 << 2 | v1 >> 4);
      *output++ = (v1 << 4 | v2 >> 2);
    }
  } else {
    if (input[2] < kDecodingBias) return 0;
    const uint8_t v2 = kDecoding[input[2] - kDecodingBias];
    if (v2 == 255) return 0;

    if (input[3] < kDecodingBias) return 0;
    const uint8_t v3 = kDecoding[input[3] - kDecodingBias];
    if (v3 == 255) return 0;

    uint32_t v = (v0 << 18) |
                 (v1 << 12) |
                 (v2 << 6) |
                 v3;
    *output++ = v >> 16;
    v <<= 8; v &= 0xffffff;
    *output++ = v >> 16;
    v <<= 8; v &= 0xffffff;
    *output++ = v >> 16;
  }

  *out_len = output - orig_output;

  return 1;
}
