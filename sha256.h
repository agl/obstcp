#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

struct sha256_ctx {
    uint64_t length;
    uint32_t state[8];
    uint32_t curlen;
    unsigned char buf[64];
};

void sha256_init(struct sha256_ctx *md);
void sha256_update(struct sha256_ctx *md, const uint8_t *in, unsigned inlen);
void sha256_final(struct sha256_ctx *md, uint8_t *hash);

#endif
