#ifndef SALSA20_H
#define SALSA20_H

#include <stdint.h>

struct ECRYPT_ctx {
  uint32_t input[16];
};

extern void ECRYPT_keysetup(void *x, const uint8_t *k, uint32_t kbits, uint32_t ivbits);
extern void ECRYPT_ivsetup(void *x, const uint8_t *iv);
extern void ECRYPT_encrypt_bytes(void *x, const uint8_t *m, uint8_t *c, uint32_t bytes);

#endif
