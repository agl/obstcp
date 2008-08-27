#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <linux/sockios.h>

#include <event.h>
#include "libobstcp.h"

static int
usage(const char *argv0) {
  fprintf(stderr, "Usage: %s <private key file> <listen port> <target ip> <target port>\n",
          argv0);
  return 1;
}

#define CHUNK_PRE 4
#define CHUNK_POST 32
#define QUEUE_MAX 32768
#define CHUNK_OVERHEAD (CHUNK_PRE + CHUNK_POST)

struct chunk {
  struct chunk *next, *last;
  unsigned length, done;
  uint8_t data[0];
};

struct connection {
  struct obstcp_server_ctx ctx;
  int fd;
  int outfd;
  struct event obsevent;
  struct event outevent;
  struct chunk *outqhead, *outqtail;
  struct chunk *obsqhead, *obsqtail;
  struct chunk *pendingqhead, *pendingqtail;
  unsigned outqlen, obsqlen;
};

struct server_config {
  uint32_t target_ip;
  uint16_t target_port;
  struct obstcp_keys *keys;
};

static void
connection_free(struct connection *conn) {
  struct chunk *c, *next;

  if (conn->outevent.ev_events) {
    event_del(&conn->outevent);
  }

  if (conn->obsevent.ev_events) {
    event_del(&conn->obsevent);
  }

  close(conn->fd);
  close(conn->outfd);

  for (c = conn->outqhead; c; c = next) {
    next = c->next;
    free(c);
  }

  for (c = conn->obsqhead; c; c = next) {
    next = c->next;
    free(c);
  }

  free(conn);
}

static void
chunk_nq(struct chunk *c, struct chunk **head, struct chunk **tail) {
  c->last = *tail;
  c->next = NULL;
  *tail = c;
  if (!*head) *head = c;
}

static void
chunk_free(struct chunk **head, struct chunk **tail) {
  if ((*head)->next)
    (*head)->next->last = NULL;

  struct chunk *next = (*head)->next;
  free(*head);

  if (*tail == *head) *tail = NULL;
  *head = next;
}

static void
chunks_move(struct chunk **tohead, struct chunk **totail,
            struct chunk **fromhead, struct chunk **fromtail) {
  struct chunk *c, *next;

  for (c = *fromhead; c; c = next) {
    next = c->next;
    chunk_nq(c, tohead, totail);
  }

  *fromhead = *fromtail = NULL;
}

static void
connection_obs_prepare(struct connection *conn, struct chunk *c) {
  struct iovec iov[2];

  obstcp_server_encrypt(&conn->ctx, c->data + c->done,
                        c->data + c->done, c->length - c->done, 0);
  obstcp_server_ends(&conn->ctx, &iov[0], &iov[1]);
  if (iov[0].iov_len > CHUNK_PRE) abort();
  if (iov[1].iov_len > CHUNK_POST) abort();
  c->done -= iov[0].iov_len;
  c->length += iov[0].iov_len;
  memcpy(c->data + c->done, iov[0].iov_base, iov[0].iov_len);
  memcpy(c->data + c->done + c->length, iov[1].iov_base, iov[1].iov_len);
  c->length += iov[1].iov_len;
}

static int
connection_write(struct chunk *c, int fd) {
  if (c->length == c->done) return 1;

  ssize_t n;
  do {
    n = write(fd, c->data + c->done, c->length - c->done);
  } while (n == -1 && errno == EINTR);

  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return 1;
    return 0;
  } else if (n == 0) {
    return 0;
  } else {
    c->done += n;
    return 1;
  }
}

static void connection_out_cb(int fd, short events, void *arg);
static void connection_obs_cb(int fd, short events, void *arg);

static void
connection_setevents(struct connection *conn) {
  const short outev = (conn->outqlen < QUEUE_MAX ? EV_READ : 0) |
                      EV_PERSIST |
                      (conn->outqhead ? EV_WRITE : 0);
  const short obsev = (conn->obsqlen < QUEUE_MAX ? EV_READ : 0) |
                      EV_PERSIST |
                      (conn->obsqhead ? EV_WRITE : 0);

  if (conn->outevent.ev_events != outev) {
    if (conn->outevent.ev_events) {
      event_del(&conn->outevent);
    }
    event_set(&conn->outevent, conn->outfd, outev, connection_out_cb, conn);
    event_add(&conn->outevent, NULL);
  }

  if (conn->obsevent.ev_events != obsev) {
    if (conn->obsevent.ev_events) {
      event_del(&conn->obsevent);
    }
    event_set(&conn->obsevent, conn->fd, obsev, connection_obs_cb, conn);
    event_add(&conn->obsevent, NULL);
  }
}

static int
connection_obs_write(struct connection *conn) {
  struct chunk *c, *next;
  for (c = conn->obsqhead; c; c = next) {
    next = c->next;
    if (!connection_write(c, conn->fd)) {
      connection_free(conn);
      return 0;
    }
    if (c->done == c->length) {
      conn->obsqlen -= c->length;
      chunk_free(&conn->obsqhead, &conn->obsqtail);
    } else {
      break;
    }
  }

  return 1;
}

static int
connection_out_write(struct connection *conn) {
  struct chunk *c, *next;
  for (c = conn->outqhead; c; c = next) {
    next = c->next;
    if (!connection_write(c, conn->outfd)) {
      connection_free(conn);
      return 0;
    }
    if (c->done == c->length) {
      conn->outqlen -= c->length;
      chunk_free(&conn->outqhead, &conn->outqtail);
    } else {
      break;
    }
  }

  return 1;
}

static void
connection_obs_cb(int fd, short events, void *arg) {
  struct connection *conn = (struct connection *) arg;

  if (EV_READ & events) {
    int queued;
    if (ioctl(conn->fd, SIOCINQ, &queued)) {
      perror("ioctl");
      connection_free(conn);
      return;
    }
    if (!queued) queued = 16;

    struct chunk *c = malloc(sizeof(struct chunk) + queued);
    if (!c) return;
    memset(c, 0, sizeof(struct chunk));

    char ready;
    const ssize_t n =
      obstcp_server_read(conn->fd, &conn->ctx, c->data, queued, &ready);

    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      perror("read");
      free(c);
      connection_free(conn);
      return;
    } else if (n == 0) {
      free(c);
      connection_free(conn);
      return;
    } else {
      c->length = n;
      const char was_empty_q = conn->outqhead ? 0 : 1;

      conn->outqlen += c->length;
      if (!ready) {
        chunk_nq(c, &conn->pendingqhead, &conn->pendingqtail);
      } else {
        if (conn->pendingqhead) {
          chunks_move(&conn->outqhead, &conn->outqtail,
                      &conn->pendingqhead, &conn->pendingqtail);
        }
        chunk_nq(c, &conn->outqhead, &conn->outqtail);
        if (was_empty_q) if (!connection_out_write(conn)) return;
      }
    }
  }

  if (EV_WRITE & events) {
    if (!connection_obs_write(conn)) return;
  }

  connection_setevents(conn);
}

static void
connection_out_cb(int fd, short events, void *arg) {
  struct connection *conn = (struct connection *) arg;

  if (EV_READ & events) {
    int queued;
    if (ioctl(conn->outfd, SIOCINQ, &queued)) {
      perror("ioctl");
      connection_free(conn);
      return;
    }
    if (!queued) queued = 16;

    struct chunk *c = malloc(sizeof(struct chunk) + queued + CHUNK_OVERHEAD);
    if (!c) return;
    memset(c, 0, sizeof(struct chunk));
    c->done = CHUNK_PRE;

    ssize_t n;
    do {
      n = read(conn->outfd, c->data + CHUNK_PRE, queued);
    } while (n == -1 && errno == EINTR);

    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      perror("read");
      free(c);
      connection_free(conn);
      return;
    } else if (n == 0) {
      free(c);
      connection_free(conn);
      return;
    } else {
      c->length = n + c->done;
      const char was_empty_q = conn->obsqhead ? 0 : 1;

      connection_obs_prepare(conn, c);
      chunk_nq(c, &conn->obsqhead, &conn->obsqtail);
      conn->obsqlen += c->length;

      if (was_empty_q) connection_obs_write(conn);
    }
  }

  if (EV_WRITE & events) {
    if (!connection_out_write(conn)) return;
  }

  connection_setevents(conn);
}

static void
connect_cb(int fd, short events, void *arg) {
  struct connection *conn = (struct connection *) arg;

  int err;
  socklen_t errlen = sizeof(err);
  if (getsockopt(conn->outfd, SOL_SOCKET, SO_ERROR, &err, &errlen)) {
    perror("getsockopt for connection result");
    connection_free(conn);
    return;
  }

  if (err) {
    fprintf(stderr, "Connection error: %s\n", strerror(err));
    connection_free(conn);
    return;
  }

  connection_setevents(conn);

  return;
}

static void
accept_cb(int fd, short events, void *arg) {
  struct server_config *cfg = (struct server_config *) arg;

  const int nfd = accept(fd, NULL, NULL);
  if (nfd < 0) {
    perror("accept");
    return;
  }

  struct connection *conn = (struct connection *) calloc(sizeof(struct connection), 1);
  if (!conn) {
    close(nfd);
    return;
  }

  obstcp_server_ctx_init(&conn->ctx, cfg->keys);
  conn->fd = nfd;

  conn->outfd = socket(PF_INET, SOCK_STREAM, 0);
  if (conn->outfd < 0) {
    perror("socket");
    goto out;
  }

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_addr.s_addr = cfg->target_ip;
  sin.sin_port = htons(cfg->target_port);
  sin.sin_family = AF_INET;

  fcntl(conn->outfd, F_SETFL, O_NONBLOCK);
  fcntl(conn->fd, F_SETFL, O_NONBLOCK);

  int n;
  do {
    n = connect(conn->outfd, (struct sockaddr *) &sin, sizeof(sin));
  } while (n == -1 && errno == EINTR);

  if (n < 0) {
    if (errno != EINPROGRESS) {
      perror("connect");
      close(conn->outfd);
      goto out;
    }

    event_set(&conn->outevent, conn->outfd, EV_WRITE, connect_cb, conn);
    event_add(&conn->outevent, NULL);
  } else {
    connection_setevents(conn);
  }

  return;

out:
  close(nfd);
  free(conn);
}

static int
server_listen(struct obstcp_keys *keys, unsigned port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    return -1;
  }

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = PF_INET;
  sin.sin_port = htons(port);

  static const int t = 1;
  static const socklen_t t_len = sizeof(t);
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &t, t_len);

  if (bind(fd, (struct sockaddr *) &sin, sizeof(sin))) {
    perror("bind");
    return -1;
  }

  char advert[1024];
  const int advertlen =
    obstcp_advert_create(advert, sizeof(advert), keys,
                         OBSTCP_ADVERT_OBSPORT, port,
                         OBSTCP_ADVERT_END);
  if (advertlen < 0 || advertlen >= sizeof(advert)) {
    perror("advert_create");
    return -1;
  }
  advert[advertlen] = 0;

  fprintf(stderr, "advert: %s\n", advert);

  if (listen(fd, 1)) {
    perror("listen");
    return -1;
  }

  return fd;
}

int
main(int argc, char **argv) {
  if (argc != 5) return usage(argv[0]);

  uint8_t private_key[32];
  const int pkfd = open(argv[1], O_RDONLY);
  if (pkfd < 0) {
    perror("opening private key file");
    return 1;
  }

  if (read(pkfd, private_key, 32) != 32) {
    perror("reading private key");
    return 1;
  }
  close(pkfd);

  struct obstcp_keys keys;
  obstcp_keys_init(&keys);
  if (!obstcp_keys_key_add(&keys, private_key)) {
    perror("obstcp_keys_key_add");
    return 1;
  }

  char *endptr;

  const unsigned listen_port = strtoul(argv[2], &endptr, 10);
  if (*endptr || listen_port < 1 || listen_port > 65535) {
    fprintf(stderr, "Invalid listen port\n");
    return 1;
  }

  const unsigned target_port = strtoul(argv[4], &endptr, 10);
  if (*endptr || target_port < 1 || target_port > 65535) {
    fprintf(stderr, "Invalid target port\n");
    return 1;
  }

  struct in_addr ina;
  if (!inet_aton(argv[3], &ina)) {
    fprintf(stderr, "Invalid target IP addresss\n");
    return 1;
  }

  event_init();

  const int lfd = server_listen(&keys, listen_port);
  if (lfd < 0) {
    fprintf(stderr, "Error creating listening socket\n");
    return 1;
  }

  struct server_config cfg;
  cfg.target_ip = ina.s_addr;
  cfg.target_port = target_port;
  cfg.keys = &keys;

  struct event acceptevent;
  event_set(&acceptevent, lfd, EV_READ | EV_PERSIST, accept_cb, &cfg);
  event_add(&acceptevent, NULL);

  event_loop(0);

  return 0;
}
