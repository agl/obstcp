// Copyright 2008, Google Inc.
// All rights reserved.

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "libobstcp.h"

static char
reada(int fd, void *buffer, size_t count) {
  size_t done = 0;

  while (count) {
    ssize_t n;
    do {
      n = read(fd, ((uint8_t *) buffer) + done, count);
    } while (n == -1 && errno == EINTR);

    if (n < 1)
      return 0;
    done += n;
    count -= n;
  }

  return 1;
}

static int
usage(const char *argv0) {
  fprintf(stderr, "Usage: %s <ObsTCP port number> > /dir/private-key\n", argv0);
  return 1;
}

int
main(int argc, char **argv) {
  if (argc > 2) return usage(argv[0]);

  const int urfd = open("/dev/random", O_RDONLY);
  if (urfd < 0) {
    perror("Cannot open /dev/random");
    return 1;
  }

  uint16_t portnum;

  if (argc == 2) {
    char *endptr;
    const unsigned long p = strtoul(argv[1], &endptr, 10);
    if (*endptr) {
      fprintf(stderr, "Not a valid number: %s\n", argv[1]);
      return 1;
    }

    if (p == 0 || p > 65535) {
      fprintf(stderr, "Not a valid port number (1..65535): %lu\n", p);
      return 1;
    }

    portnum = p;
  } else {
    if (!reada(urfd, &portnum, 2)) {
      perror("Error reading from /dev/random");
      return 1;
    }
    portnum &= 0x3fff;
    portnum += 1024;
  }

  struct obstcp_keys keys;
  obstcp_keys_init(&keys);

  uint8_t private_key[32];

  fprintf(stderr, "Generating random data...\n");
  if (!reada(urfd, private_key, sizeof(private_key))) {
    perror("Error reading from /dev/random");
    return 1;
  }

  if (-1 == obstcp_keys_key_add(&keys, private_key)) {
    perror("Error adding private key to set");
    return 1;
  }

  char output[512];

  const int r =
    obstcp_advert_base32_create(output, sizeof(output), &keys,
                                OBSTCP_ADVERT_OBSPORT, (int) portnum,
                                OBSTCP_ADVERT_END);
  if (r >= sizeof(output)) {
    fprintf(stderr, "Advert too large\n");
    return 1;
  } else if (r < 0) {
    perror("Error creating advert");
    return 1;
  }

  output[r] = 0;
  fprintf(stderr, "Port: %d\n", portnum);
  fprintf(stderr, "Advert: %s\n", output);

  char dnsadvert[512];
  if (obstcp_advert_cname_encode_sz(r) > sizeof(dnsadvert)) {
    fprintf(stderr, "Cannot print DNS advert");
  } else {
    obstcp_advert_cname_encode(dnsadvert, output, r);
    dnsadvert[obstcp_advert_cname_encode_sz(r)] = 0;
    fprintf(stderr, "DNS Advert: %s\n", dnsadvert);
  }

  write(1, private_key, 32);

  return 0;
}
