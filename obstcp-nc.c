#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libobstcp.h"

static int
server() {
  const int urfd = open("/dev/urandom", O_RDONLY);
  if (urfd < 0) {
          perror("opening urandom");
          return 1;
  }

  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
          perror("socket");
          return 1;
  }

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = PF_INET;

  if (bind(fd, (struct sockaddr *) &sin, sizeof(sin))) {
          perror("bind");
          return 1;
  }

  socklen_t sinlen = sizeof(sin);
  if (getsockname(fd, (struct sockaddr *) &sin, &sinlen)) {
          perror("getsockname");
          return 1;
  }

  uint8_t secret[32];
  read(urfd, secret, sizeof(secret));

  struct obstcp_keys keys;
  if (!obstcp_keys_key_add(&keys, secret)) {
    perror("key_add");
    return 1;
  }

  char advert[1024];
  const int advertlen =
    obstcp_advert_create(advert, sizeof(advert), &keys,
                         OBSTCP_ADVERT_OBSPORT, ntohs(sin.sin_port),
                         OBSTCP_ADVERT_END);
  if (advertlen < 0 || advertlen >= sizeof(advert)) {
    perror("advert_create");
    return 1;
  }
  advert[advertlen] = 0;

  fprintf(stderr, "port: %d\nadvert: %s\n", ntohs(sin.sin_port), advert);

  if (listen(fd, 1)) {
    perror("listen");
    return 1;
  }

  const int nfd = accept(fd, NULL, NULL);
  if (nfd < 0) {
    perror("accept");
    return 1;
  }
  close(fd);

  fprintf(stderr, "accepted connection\n");

  struct obstcp_server_ctx ctx;
  obstcp_server_ctx_init(&ctx, &keys);

  char ready;

  do {
    const ssize_t n = obstcp_server_read(nfd, &ctx, NULL, 0, &ready);
    if (n < 0) {
      perror("reading");
      return 1;
    }
  } while (!obstcp_server_ready(&ctx));

  return 0;
}

static int
usage(const char *argv0) {
  return 1;
}

int
main(int argc, char **argv) {
  if (argc == 2) {
    if (strcmp(argv[1], "-l")) {
      return usage(argv[0]);
    } else {
      return server();
    }
  }

  return 0;
}
