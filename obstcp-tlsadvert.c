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
  fprintf(stderr, "Usage: %s <TLS port number>\n", argv0);
  return 1;
}

int
main(int argc, char **argv) {
  if (argc > 2) return usage(argv[0]);

  unsigned long portnum;
  if (argc == 2) {
    char *endptr;
    portnum = strtoul(argv[1], &endptr, 10);
    if (*endptr) {
      fprintf(stderr, "Not a valid number: %s\n", argv[1]);
      return usage(argv[0]);
    }

    if (portnum < 1 || portnum > 65535) {
      fprintf(stderr, "Not a valid port number (1..65535): %d\n", (int) portnum);
      return usage(argv[0]);
    }
  } else {
    portnum = 443;
  }

  char output[512];
  const int r = obstcp_advert_base32_create(output, sizeof(output), NULL,
                                            OBSTCP_ADVERT_TLSPORT, (int) portnum,
                                            OBSTCP_ADVERT_END);
  if (r >= sizeof(output)) {
    fprintf(stderr, "Advert too large\n");
    return 1;
  } else if (r < 0) {
    perror("Error creating advert");
    return 1;
  }

  output[r] = 0;
  fprintf(stderr, "Port: %d\n", (int) portnum);
  fprintf(stderr, "Advert: %s\n", output);

  char dnsadvert[512];
  if (obstcp_advert_cname_encode_sz(r) > sizeof(dnsadvert)) {
    fprintf(stderr, "Cannot print DNS advert");
  } else {
    obstcp_advert_cname_encode(dnsadvert, output, r);
    dnsadvert[obstcp_advert_cname_encode_sz(r)] = 0;
    fprintf(stderr, "DNS Advert: %s\n", dnsadvert);
  }

  return 0;
}
