#ifndef SALSA20_H
#define SALSA20_H

#include <stdint.h>

extern void salsa208(uint8_t *out, const uint8_t *in, const uint8_t *k, const uint8_t *c);

#endif
