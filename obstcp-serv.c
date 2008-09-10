// Copyright 2008, Google Inc.
// All rights reserved.

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
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

  struct obstcp_rbuf rbuf;
  obstcp_rbuf_server_init(&rbuf, &ctx);

  do {
    uint8_t b;
    const ssize_t n = obstcp_rbuf_read_fd(&rbuf, nfd, &b, 1);
    if (n < 0) {
      perror("obstcp_rbuf_read_fd");
      return 1;
    } else if (n == 0) {
      fprintf(stderr, "  * Peer closed connection in handshake\n");
    } else {
      write(1, &b, 1);
    }
  } while (!obstcp_server_ready(&ctx));

  const int efd = epoll_create(2);
  if (efd < 0) {
    perror("epoll_create");
    return 1;
  }

  struct epoll_event eev;
  memset(&eev, 0, sizeof(eev));
  eev.events = EPOLLIN;

  eev.data.fd = 0;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, 0, &eev)) {
    perror("epoll_ctl");
    return 1;
  }

  eev.data.fd = nfd;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, nfd, &eev)) {
    perror("epoll_ctl");
    return 1;
  }

  for (;;) {
    if (epoll_wait(efd, &eev, 1, -1) == -1) {
      perror("epoll_wait");
      return 1;
    }

    if (eev.data.fd == 0) {
      uint8_t buffer[8192];
      ssize_t n;

      do {
        n = read(0, buffer, sizeof(buffer));
      } while (n == -1 && errno == EINTR);

      if (n == 0) {
        fprintf(stderr, " ** Stdin closed\n");
        return 0;
      } else if (n < 0) {
        perror("reading from stdin");
        return 1;
      } else {
        struct iovec iov[2];

        obstcp_server_encrypt(&ctx, buffer, buffer, n);
        const int a = obstcp_server_prefix(&ctx, &iov[0]);
        if (a == -1) {
          perror("obstcp_server_ends");
          return 1;
        } else if (a == 0) {
          write(nfd, buffer, n);
        } else {
          iov[1].iov_base = buffer;
          iov[1].iov_len = n;
          writev(nfd, iov, 2);
        }
      }
    } else {
      uint8_t buffer[8192];

      const ssize_t n = obstcp_rbuf_read_fd(&rbuf, nfd, buffer, sizeof(buffer));
      if (n == 0) {
        fprintf(stderr, "  ** Remote closed\n");
        return 0;
      } else if (n < 0) {
        perror("obstcp_rbuf_read_fd");
        return 1;
      } else {
        write(1, buffer, n);
      }
    }
  }
}

static int
usage(const char *argv0) {
  fprintf(stderr, "Usage: %s\n", argv0);
  return 1;
}

int
main(int argc, char **argv) {
  if (argc != 1) return usage(argv[0]);
  return server();
}
