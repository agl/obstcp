#include <stdint.h>
#include <string.h>

extern void curve25519(uint8_t *result, const uint8_t *a, const uint8_t *b);

int
main() {
  uint8_t out[32], a[32], b[32];

  memset(a, 42, sizeof(a));
  memset(b, 64, sizeof(b));
  curve25519(out, a, b);
  return 0 != memcmp(out, "\x0eY\xe5-\xdc|%AV\x9eR\xe0\xba!\xf1T]>\xff\xca\xcaSS\x9c\xc4_\xec`O*\xd6\x03", 32);
}
