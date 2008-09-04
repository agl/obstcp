// Copyright 2008, Google Inc.
// All rights reserved.

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "libobstcp.h"

static int
usage(const char *argv0) {
  fprintf(stderr, "Usage: %s <ObsTCP port number> > /dir/private-key\n", argv0);
  return 1;
}

int
main(int argc, char **argv) {
  if (argc != 2) return usage(argv[0]);

  char *endptr;
  const unsigned long portnum = strtoul(argv[1], &endptr, 10);
  if (*endptr) {
    fprintf(stderr, "Not a valid number: %s\n", argv[1]);
    return 1;
  }

  if (portnum == 0 || portnum > 65535) {
    fprintf(stderr, "Not a valid port number (1..65535): %lu\n", portnum);
    return 1;
  }

  struct obstcp_keys keys;
  obstcp_keys_init(&keys);

  const int urfd = open("/dev/random", O_RDONLY);
  if (urfd < 0) {
    perror("Cannot open /dev/random");
    return 1;
  }

  uint8_t private_key[32];

  fprintf(stderr, "Generating random data...\n");
  ssize_t n;
  do {
    n = read(urfd, private_key, sizeof(private_key));
  } while (n == -1 && errno == EINTR);

  if (n != sizeof(private_key)) {
    perror("Error reading from /dev/random");
    return 1;
  }

  if (-1 == obstcp_keys_key_add(&keys, private_key)) {
    perror("Error adding private key to set");
    return 1;
  }

  char output[512];

  const int r = obstcp_advert_create(output, sizeof(output), &keys,
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
  fprintf(stderr, "Advert: %s\n", output);

  write(1, private_key, 32);

  return 0;
}
