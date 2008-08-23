#ifndef BASE64_H
#define BASE64_H

// -----------------------------------------------------------------------------
// length: the length of the input which is to be base64 encoded
// returns: the length of the base64 encoded result
// -----------------------------------------------------------------------------
unsigned obs_base64_encode_length(unsigned length);

// -----------------------------------------------------------------------------
// output: a buffer large enough to hold the result
// input: the data to be encoded
// length: the length, in bytes, of @input
// -----------------------------------------------------------------------------
unsigned obs_base64_encode(char *output, const uint8_t *input, unsigned length);

// -----------------------------------------------------------------------------
// length: the length of the base64 encoded input
// returns: the maximum length of the decoded result
// -----------------------------------------------------------------------------
unsigned obs_base64_decode_length(unsigned length);

// -----------------------------------------------------------------------------
// output: a buffer large enough to hold the result
// out_len: (output) on success, the length of the result
// input: the base64 encoded input
// length: the length of @input
// returns: 1 on success, 0 on parse error
// -----------------------------------------------------------------------------
int obs_base64_decode(uint8_t *output, unsigned *out_len, const char *input,
                      unsigned length);

#endif
