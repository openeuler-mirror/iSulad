/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2016 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>

#include <nghttp2/nghttp2.h>

#include "http_parser.h"

#define ARRLEN(A) (sizeof(A) / sizeof(A[0]))

#define MAKE_NV_LL(N, V)                                                       \
  {                                                                            \
    (uint8_t *)(N), (uint8_t *)(V), sizeof(N) - 1, sizeof(V) - 1,              \
        NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE           \
  }
#define MAKE_NV_L(N, V, VLEN)                                                  \
  { (uint8_t *)(N), (V), sizeof(N) - 1, (VLEN), NGHTTP2_NV_FLAG_NO_COPY_NAME }

static struct iovec make_iovec(const void *base, size_t len) {
  uint8_t *p;

  p = malloc(len + 1);
  memcpy(p, base, len);
  p[len] = '\0';

  return (struct iovec){p, len};
}

static void *cpymem(void *dst, const void *src, size_t len) {
  memcpy(dst, src, len);
  return (uint8_t *)dst + len;
}

struct buffer {
  void *base;
  size_t len;
  size_t capacity;
};

struct request {
  struct iovec scheme;
  struct iovec authority;
  struct iovec path;
};

struct connection {
  struct iovec host;
  struct iovec service;
  int fd;
  uint32_t events;
  /* in this example program, we only handles 1 request. */
  struct request *req;
  nghttp2_session *ngh2;
  struct buffer ini_txbuf;
  struct iovec txbuf;
};

static int parse_uri(struct connection *conn, struct request *req,
                     const char *uri, size_t urilen) {
  struct http_parser_url up;
  size_t authoritylen, pathlen;
  int ipv6;
  int port_given, path_given, query_given;

  http_parser_url_init(&up);
  if (http_parser_parse_url(uri, urilen, 0, &up) != 0) {
    fprintf(stderr, "error: could not parse URI %s\n", uri);
    return -1;
  }

  if ((up.field_set & (1 << UF_SCHEMA)) == 0) {
    fprintf(stderr, "error: scheme not found\n");
    return -1;
  }

  if ((up.field_set & (1 << UF_HOST)) == 0) {
    fprintf(stderr, "error: host not found\n");
    return -1;
  }

  conn->host =
      make_iovec(uri + up.field_data[UF_HOST].off, up.field_data[UF_HOST].len);

  authoritylen = conn->host.iov_len;
  ipv6 = strchr(conn->host.iov_base, ':') != NULL;

  if (ipv6) {
    authoritylen += 2;
  }

  port_given = (up.field_set & (1 << UF_PORT)) != 0;

  if (port_given) {
    conn->service = make_iovec(uri + up.field_data[UF_PORT].off,
                               up.field_data[UF_PORT].len);
    authoritylen += conn->service.iov_len + 1;
  } else {
    conn->service = make_iovec("80", 2);
  }

  req->authority.iov_base = malloc(authoritylen + 1);
  req->authority.iov_len = authoritylen;
  {
    uint8_t *dst = req->authority.iov_base;
    if (ipv6) {
      *dst++ = '[';
    }

    dst = cpymem(dst, conn->host.iov_base, conn->host.iov_len);

    if (ipv6) {
      *dst++ = ']';
    }

    if (port_given) {
      *dst++ = ':';
      dst = cpymem(dst, conn->service.iov_base, conn->service.iov_len);
    }

    *dst = '\0';
  }

  req->scheme = make_iovec(uri + up.field_data[UF_SCHEMA].off,
                           up.field_data[UF_SCHEMA].len);

  path_given = (up.field_set & (1 << UF_PATH));
  query_given = (up.field_set & (1 << UF_QUERY));

  pathlen = path_given ? up.field_data[UF_PATH].len : 1;

  if (query_given) {
    pathlen += 1 + up.field_data[UF_QUERY].len;
  }

  req->path.iov_base = malloc(pathlen + 1);
  req->path.iov_len = pathlen;
  {
    uint8_t *dst = req->path.iov_base;
    if (path_given) {
      dst = cpymem(dst, uri + up.field_data[UF_PATH].off,
                   up.field_data[UF_PATH].len);
    } else {
      *dst++ = '/';
    }
    if (query_given) {
      *dst++ = '?';
      dst = cpymem(dst, uri + up.field_data[UF_QUERY].off,
                   up.field_data[UF_QUERY].len);
    }
    *dst = '\0';
  }

  return 0;
}

static int connect_to_host(struct connection *conn) {
  struct addrinfo hints;
  struct addrinfo *rp, *res;
  int rv;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;

  rv = getaddrinfo(conn->host.iov_base, conn->service.iov_base, &hints, &res);
  if (rv != 0) {
    fprintf(stderr, "error: (getaddrinfo) %s\n", gai_strerror(rv));
    return -1;
  }

  rv = 0;

  for (rp = res; rp; rp = rp->ai_next) {
    int fd;

    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }

    if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1) {
      conn->fd = fd;
      goto end;
    }

    close(fd);
  }

end:
  freeaddrinfo(res);

  return rv;
}

static int append_buf(struct buffer *buf, const void *data, size_t datalen) {
  if (buf->len + datalen > buf->capacity) {
    void *p;
    size_t new_size = buf->capacity;

    if (new_size == 0) {
      new_size = 16384;
    }

    while (new_size < buf->len + datalen) {
      new_size *= 2;
    }

    p = realloc(buf->base, new_size);
    if (!p) {
      fprintf(stderr, "error: (realloc) %s\n", strerror(errno));
      return -1;
    }
    buf->base = p;
    buf->capacity = new_size;
  }

  memcpy((uint8_t *)buf->base + buf->len, data, datalen);
  buf->len += datalen;

  return 0;
}

static int should_stop_h2(struct connection *conn) {
  return nghttp2_session_want_read(conn->ngh2) == 0 &&
         nghttp2_session_want_write(conn->ngh2) == 0;
}

static int fill_txbuf(struct connection *conn) {
  const uint8_t *data;
  ssize_t datalen;

  if (conn->ini_txbuf.len > 0) {
    return 0;
  }

  if (should_stop_h2(conn)) {
    return -1;
  }

  for (;;) {
    datalen = nghttp2_session_mem_send(conn->ngh2, &data);
    if (datalen < 0) {
      fprintf(stderr, "error: (nghttp2_session_mem_send) %s\n",
              nghttp2_strerror((int)datalen));
      return -1;
    }
    if (datalen == 0) {
      goto end;
    }
    if (append_buf(&conn->ini_txbuf, data, (size_t)datalen) != 0) {
      return -1;
    }
    if (conn->ini_txbuf.len >= 16384) {
      goto end;
    }
  }
end:
  conn->txbuf.iov_base = conn->ini_txbuf.base;
  conn->txbuf.iov_len = conn->ini_txbuf.len;

  if (conn->txbuf.iov_len == 0 && should_stop_h2(conn)) {
    return -1;
  }

  return 0;
}

static int writecb(struct connection *conn) {
  ssize_t n;

  for (;;) {
    if (fill_txbuf(conn) != 0) {
      return -1;
    }

    if (conn->txbuf.iov_len == 0) {
      conn->events &= (unsigned int)~EPOLLOUT;
      return 0;
    }

    while ((n = write(conn->fd, conn->txbuf.iov_base, conn->txbuf.iov_len)) ==
               -1 &&
           errno == EINTR)
      ;
    if (n == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        conn->events |= EPOLLOUT;
        return 0;
      }
      fprintf(stderr, "error: (write) %s\n", strerror(errno));
      return -1;
    }

    conn->txbuf.iov_base = (uint8_t *)conn->txbuf.iov_base + n;
    conn->txbuf.iov_len -= (size_t)n;

    if (conn->txbuf.iov_len == 0) {
      conn->ini_txbuf.len = 0;
    }
  }
}

static int readcb(struct connection *conn) {
  ssize_t n;
  ssize_t rv;
  uint8_t buf[16384];

  for (;;) {
    while ((n = read(conn->fd, buf, sizeof(buf))) == -1 && errno == EINTR)
      ;
    if (n == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      fprintf(stderr, "error: (read) %s\n", strerror(errno));
      return -1;
    }
    if (n == 0) {
      fprintf(stderr, "connection closed by remote host\n");
      return -1;
    }
    rv = nghttp2_session_mem_recv(conn->ngh2, buf, (size_t)n);
    if (rv < 0) {
      fprintf(stderr, "error: (nghttp2_session_mem_recv) %s\n",
              nghttp2_strerror((int)rv));
      return -1;
    }
    assert(n == rv);
  }

  if (writecb(conn) != 0) {
    return -1;
  }

  return 0;
}

static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data) {
  struct request *req;

  (void)flags;
  (void)user_data;

  if (frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }

  req = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
  if (!req) {
    return 0;
  }

  fprintf(stdout, "%.*s: %.*s\n", (int)namelen, name, (int)valuelen, value);

  return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  struct request *req;

  (void)user_data;

  if (frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }

  req = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
  if (!req) {
    return 0;
  }

  fputc('\n', stdout);

  return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
  struct request *req;
  int rv;

  (void)user_data;

  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!req) {
    return 0;
  }

  if (error_code != NGHTTP2_NO_ERROR) {
    fprintf(stderr, "stream %d closed with HTTP/2 error code %d\n", stream_id,
            error_code);
  }

  rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
  if (rv != 0) {
    fprintf(stderr, "error: (nghttp2_session_terminate_session) %s\n",
            nghttp2_strerror(rv));
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data) {
  struct request *req;

  (void)flags;
  (void)user_data;

  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!req) {
    return 0;
  }

  fwrite(data, 1, len, stdout);

  return 0;
}

static int start_h2(struct connection *conn) {
  int rv;
  nghttp2_session_callbacks *callbacks;
  nghttp2_settings_entry settings[1];

  rv = nghttp2_session_callbacks_new(&callbacks);
  if (rv != 0) {
    fprintf(stderr, "error: (nghttp2_session_callbacks_new) %s\n",
            nghttp2_strerror(rv));
    return -1;
  }

  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                   on_header_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, on_data_chunk_recv_callback);

  rv = nghttp2_session_client_new(&conn->ngh2, callbacks, conn);
  nghttp2_session_callbacks_del(callbacks);
  if (rv != 0) {
    fprintf(stderr, "error: (nghttp2_session_client_new) %s\n",
            nghttp2_strerror(rv));
    return -1;
  }

  settings[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  settings[0].value = 100;

  rv = nghttp2_submit_settings(conn->ngh2, NGHTTP2_FLAG_NONE, settings,
                               ARRLEN(settings));
  if (rv != 0) {
    fprintf(stderr, "error: (nghttp2_submit_settings) %s\n",
            nghttp2_strerror(rv));
    return -1;
  }

  return 0;
}

static void stop_h2(struct connection *conn) {
  nghttp2_session_del(conn->ngh2);
}

static int send_request(struct connection *conn, struct request *req) {
  nghttp2_nv nva[] = {
      MAKE_NV_LL(":method", "GET"),
      MAKE_NV_L(":scheme", req->scheme.iov_base, req->scheme.iov_len),
      MAKE_NV_L(":authority", req->authority.iov_base, req->authority.iov_len),
      MAKE_NV_L(":path", req->path.iov_base, req->path.iov_len)};
  int rv;

  rv = nghttp2_submit_request(conn->ngh2, NULL, nva, ARRLEN(nva), NULL, req);
  if (rv < 0) {
    fprintf(stderr, "error: (nghttp2_submit_requset) %s\n",
            nghttp2_strerror(rv));
    return -1;
  }

  return 0;
}

static int loop(struct connection *conn) {
  int rv;
  int epfd;
  struct epoll_event ev;
  struct epoll_event evout[1];

  epfd = epoll_create(1);
  if (epfd == -1) {
    fprintf(stderr, "error: (epoll_create) %s\n", strerror(errno));
    return -1;
  }

  ev.events = conn->events = EPOLLIN;
  ev.data.ptr = conn;

  if (epoll_ctl(epfd, EPOLL_CTL_ADD, conn->fd, &ev) != 0) {
    fprintf(stderr, "error: (epoll_ctl) %s\n", strerror(errno));
    rv = -1;
    goto fail;
  }

  if (start_h2(conn) != 0) {
    rv = -1;
    goto fail;
  }

  if (send_request(conn, conn->req) != 0) {
    rv = -1;
    goto fail;
  }

  if (writecb(conn) != 0) {
    rv = -1;
    goto fail;
  }
  if (conn->events != ev.events) {
    ev.events = conn->events;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->fd, &ev) != 0) {
      fprintf(stderr, "error: (epoll_ctl) %s\n", strerror(errno));
      rv = -1;
      goto fail;
    }
  }

  for (;;) {
    rv = epoll_wait(epfd, evout, sizeof(evout), -1);
    if (rv == -1) {
      fprintf(stderr, "error: (epoll_wait) %s\n", strerror(errno));
      rv = -1;
      goto fail;
    }

    if (rv == 0) {
      continue;
    }

    if (evout[0].events & (EPOLLERR | EPOLLHUP)) {
      fprintf(stderr, "connection closed by remote host\n");
      break;
    }

    if (evout[0].events & EPOLLIN) {
      if (readcb(evout[0].data.ptr) != 0) {
        rv = -1;
        goto fail;
      }
    } else if (evout[0].events & EPOLLOUT) {
      if (writecb(evout[0].data.ptr) != 0) {
        rv = -1;
        goto fail;
      }
    }

    if (conn->events != ev.events) {
      ev.events = conn->events;
      if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->fd, &ev) != 0) {
        fprintf(stderr, "error: (epoll_ctl) %s\n", strerror(errno));
        rv = -1;
        goto fail;
      }
    }
  }

fail:
  stop_h2(conn);
  close(epfd);

  return rv;
}

static int make_fd_nonblocking(int fd) {
  int flags;
  int rv;

  while ((flags = fcntl(fd, F_GETFL)) == -1 && errno == EINTR)
    ;

  if (flags == -1) {
    fprintf(stderr, "error: (fcntl) %s\n", strerror(errno));
    return -1;
  }

  while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
    ;

  if (rv != 0) {
    fprintf(stderr, "error: (fcntl) %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

static int run(const char *uri, size_t urilen) {
  struct request req = {{NULL, 0}, {NULL, 0}, {NULL, 0}};
  struct connection conn = {
      {NULL, 0}, {NULL, 0}, -1, 0, &req, NULL, {NULL, 0, 0}, {NULL, 0}};
  int rv = 0;

  if (parse_uri(&conn, &req, uri, urilen) != 0) {
    return -1;
  }

  if (connect_to_host(&conn) != 0) {
    rv = -1;
    goto fail;
  }

  if (make_fd_nonblocking(conn.fd) != 0) {
    rv = -1;
    goto fail;
  }

  if (loop(&conn) != 0) {
    rv = -1;
    goto fail;
  }

fail:
  free(req.scheme.iov_base);
  free(req.authority.iov_base);
  free(req.path.iov_base);
  free(conn.host.iov_base);
  free(conn.service.iov_base);
  if (conn.fd != -1) {
    close(conn.fd);
  }
  free(conn.ini_txbuf.base);

  return rv;
}

int main(int argc, char **argv) {
  const char *uri;
  size_t urilen;

  if (argc < 2) {
    fprintf(stderr, "Usage: tcp-client URI\n");
    exit(EXIT_FAILURE);
  }

  uri = argv[1];
  urilen = strlen(uri);

  if (run(uri, urilen) != 0) {
    exit(EXIT_FAILURE);
  }

  return 0;
}
