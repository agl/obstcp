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
client(uint32_t destip, const char *advert) {
  const int urfd = open("/dev/urandom", O_RDONLY);
  if (urfd < 0) {
    perror("opening urandom");
    return 1;
  }

  struct obstcp_keys keys;
  obstcp_keys_init(&keys);
  uint8_t private_key[32];
  if (read(urfd, private_key, sizeof(private_key)) != sizeof(private_key)) {
    perror("reading from /dev/urandom");
    return 1;
  }

  if (!obstcp_keys_key_add(&keys, private_key)) {
    perror("obstcp_keys_key_add");
    return 1;
  }

  uint8_t randbytes[16];
  if (read(urfd, randbytes, sizeof(randbytes)) != sizeof(randbytes)) {
    perror("reading from /dev/urandom");
    return 1;
  }

  struct obstcp_client_ctx ctx;
  if (!obstcp_client_ctx_init(&ctx, &keys, advert, strlen(advert), randbytes)) {
    perror("obstcp_client_ctx_init");
    return 1;
  }

  int port;
  if (!obstcp_advert_parse(advert, strlen(advert),
                           OBSTCP_ADVERT_OBSPORT, &port,
                           OBSTCP_ADVERT_END)) {
    perror("obstcp_advert_parse");
    return 1;
  }

  const int fd = socket(PF_INET, SOCK_STREAM, 0);
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = destip;

  if (connect(fd, (struct sockaddr *) &sin, sizeof(sin))) {
    perror("connect");
    return 1;
  }

  struct iovec iov[3];
  obstcp_client_banner(&ctx, &iov[0]);
  write(fd, iov[0].iov_base, iov[0].iov_len);

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

  eev.data.fd = fd;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &eev)) {
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
        struct iovec iov[3];

        obstcp_client_encrypt(&ctx, buffer, buffer, n, 0);
        const int a = obstcp_client_ends(&ctx, &iov[0], &iov[2]);
        if (a == -1) {
          perror("obstcp_server_ends");
          return 1;
        } else if (a == 0) {
          write(fd, buffer, n);
        } else {
          iov[1].iov_base = buffer;
          iov[1].iov_len = n;
          writev(fd, iov, 3);
        }
      }
    } else {
      char ready;
      uint8_t buffer[8192];

      const ssize_t n = obstcp_client_read(fd, &ctx, buffer, sizeof(buffer), &ready);
      if (n == 0) {
        fprintf(stderr, "  ** Remote closed\n");
        return 0;
      } else if (n < 0) {
        perror("obstcp_server_read");
        return 1;
      } else if (!ready) {
        fprintf(stderr, "  ** Non ready data from remote\n");
        return 1;
      } else {
        write(1, buffer, n);
      }
    }
  }
}

static int
usage(const char *argv0) {
  fprintf(stderr, "Usage: %s <destination ip> <server advert>\n", argv0);
  return 1;
}

int
main(int argc, char **argv) {
  if (argc != 3) return usage(argv[0]);

  struct in_addr inaddr;
  if (inet_aton(argv[1], &inaddr) == 0) return usage(argv[0]);
  return client(inaddr.s_addr, argv[2]);
}
