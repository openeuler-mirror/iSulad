#include "session.h"
#include <netinet/tcp.h>
#include <event2/buffer.h>
#include "ioevent.h"
#include "server.h"
#include "log.h"
#include "stream_context.h"
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

static void append_to_list(struct session *ses, struct stream_context *strm_ctx);
static void remove_from_list(struct session *ses, struct stream_context *strm_ctx);
static int session_recv(struct session *ses);
static int session_send(struct session *ses);
static void readcb(struct bufferevent *bev, void *ptr);
static void eventcb(struct bufferevent *bev, short events, void *ptr);
static void writecb(struct bufferevent *bev, void *ptr);
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data);
static int on_begin_headers_callback(nghttp2_session *ngsession, const nghttp2_frame *frame, void *user_data);
static char *percent_decode(const uint8_t *value, size_t valuelen);
static void print_header(const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen);
static int on_header_callback(nghttp2_session *ngsession, const nghttp2_frame *frame,
                              const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              uint8_t flags, void *user_data);
static int check_path(const char *path);
static int error_reply(nghttp2_session *session, struct stream_context *strm_ctx);
static int send_response(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, int fd);
static int on_request_recv(nghttp2_session *session,
                           struct session *ses,
                           struct stream_context *strm_ctx);
static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);
static int on_data_chunk_recv_callback(nghttp2_session *ses, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data);
static int on_stream_close_callback(nghttp2_session *ses, int32_t stream_id, uint32_t error_code, void *user_data);

// TODO: error handling when create bev failed!
struct session *
session_create(struct server *svr, int fd, struct sockaddr *addr, int addrlen)
{
  struct session *ses;
  struct bufferevent *bev;
  int val = 1;
  int ret;
  char host[NI_MAXHOST];

  ses = malloc(sizeof(struct session));
  memset(ses, 0, sizeof(struct session));
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
  // bev = apply_bufferevent(svr->eg, fd, readcb, writecb, eventcb, (void *)ses);
  bev = apply_bufferevent(svr->eg, fd, readcb, writecb, eventcb, (void *)ses);
  ses->bev = bev;

  ret = getnameinfo(addr, (socklen_t)addrlen, host, sizeof(host), NULL, 0,
                    NI_NUMERICHOST);
  if (ret != 0)
  {
    ses->client_addr = strdup("(unknown)");
  }
  else
  {
    ses->client_addr = strdup(host);
  }
  return ses;
}

// TODO: other callbacks like on_frame_not_send_callback
int initialize_nghttp2_session(struct session *ses)
{
  nghttp2_session_callbacks *callbacks;
  int ret;

  nghttp2_session_callbacks_new(&callbacks);

  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);

  if ((ret = nghttp2_session_server_new(&ses->ngsession, callbacks, ses)) != 0)
  {
    log_info("nghttp2_session_server_new failed");
    return -1;
  }

  // TODO setting session with nghttp2_setting_entry
  return 0;
}

// TODO: be sure to free all the stream_ctx in the session;
void session_destroy(struct session *ses)
{
  struct stream_context *strm_ctx;
  // TODO free all the stream_context stored in the map
  bufferevent_free(ses->bev);
  nghttp2_session_del(ses->ngsession);

  for (strm_ctx = ses->strm_ctx_root.next; strm_ctx;)
  {
    struct stream_context *tmp = strm_ctx->next;
    stream_context_destroy(strm_ctx);
    strm_ctx = tmp;
  }
  free(ses->client_addr);
  free(ses);
}

static void append_to_list(struct session *ses, struct stream_context *strm_ctx)
{
  strm_ctx->next = ses->strm_ctx_root.next;
  ses->strm_ctx_root.next = strm_ctx;
  strm_ctx->prev = &ses->strm_ctx_root;
  if (strm_ctx->next)
  {
    strm_ctx->next->prev = strm_ctx;
  }
}

static void remove_from_list(struct session *ses, struct stream_context *strm_ctx)
{
  strm_ctx->prev->next = strm_ctx->next;
  if (strm_ctx->next)
  {
    strm_ctx->next->prev = strm_ctx->prev;
  }
}

struct stream_context *hold_stream_context(struct session *ses, int stream_id)
{
  struct stream_context *stream_ctx;
  stream_ctx = stream_context_create(stream_id);
  // TODO a map to put the stream context in
  append_to_list(ses, stream_ctx);
  return stream_ctx;
}

int release_stream_context(struct session *ses, struct stream_context *strm_ctx)
{
  remove_from_list(ses, strm_ctx);
  stream_context_destroy(strm_ctx);

  return 0;
}

static int session_recv(struct session *ses)
{
  ssize_t readlen;
  struct evbuffer *input = bufferevent_get_input(ses->bev);
  size_t datalen = evbuffer_get_length(input);
  unsigned char *data = evbuffer_pullup(input, -1);

  readlen = nghttp2_session_mem_recv(ses->ngsession, data, datalen);
  if (readlen < 0)
  {
    log_err("Fatal error: %s", nghttp2_strerror((int)readlen));
    return -1;
  }
  if (evbuffer_drain(input, (size_t)readlen) != 0)
  {
    log_err("Fatal error: evbuffer_drain failed");
    return -1;
  }
  if (session_send(ses) != 0)
  {
    return -1;
  }
  return 0;
}

static int session_send(struct session *ses)
{
  int rv;
  rv = nghttp2_session_send(ses->ngsession);
  if (rv != 0)
  {
    log_err("Fatal error: %s, %d", nghttp2_strerror(rv), rv);
    return -1;
  }
  return 0;
}

static void readcb(struct bufferevent *bev, void *ptr)
{
  struct session *ses = (struct session *)ptr;
  (void)bev;
  if (ses->ngsession == NULL) {
    eventcb(bev, BEV_EVENT_CONNECTED, ptr);
  }

  if (session_recv(ses) != 0)
  {
    session_destroy(ses);
    return;
  }
}

static void writecb(struct bufferevent *bev, void *ptr)
{
  struct session *ses = (struct session *)ptr;
  if (ses->ngsession == NULL) {
    eventcb(bev, BEV_EVENT_CONNECTED, ptr);
  }
  if (evbuffer_get_length(bufferevent_get_output(bev)) > 0)
  {
    return;
  }
  if (nghttp2_session_want_read(ses->ngsession) == 0 &&
      nghttp2_session_want_write(ses->ngsession) == 0)
  {
    session_destroy(ses);
    return;
  }
  if (session_send(ses) != 0)
  {
    session_destroy(ses);
    return;
  }
}

/* Send HTTP/2 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
static int send_server_connection_header(struct session *ses) {
  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv;

  rv = nghttp2_submit_settings(ses->ngsession, NGHTTP2_FLAG_NONE, iv,
                               ARRLEN(iv));
  if (rv != 0) {
    log_err("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

static void eventcb(struct bufferevent *bev, short events, void *ptr)
{
  struct session *ses = (struct session *)ptr;
  if (events & BEV_EVENT_CONNECTED)
  {
    // TODO: error handling
    if (ses->ngsession) {
      return;
    }

    initialize_nghttp2_session(ses);
    log_info("%s connected", ses->client_addr);
    if (send_server_connection_header(ses) != 0 ||
        session_send(ses) != 0)
    {
      session_destroy(ses);
      return;
    }

    return;
  }

  if (events & BEV_EVENT_EOF)
  {
    log_info("%s EOF", ses->client_addr);
  }
  else if (events & BEV_EVENT_ERROR)
  {
    log_info("%s network error", ses->client_addr);
  }
  else if (events & BEV_EVENT_TIMEOUT)
  {
    log_info("%s timeout", ses->client_addr);
  }

  session_destroy(ses);
}

// These are callback needed by nghttps_session

/*
** send_callback will be called when nghttp2_session_send be called, it can be called automatically,
** that is why we need send_callback to send response frame.
** send_callback here do real I/O to bufferevent.
*/
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
  struct session *ses = (struct session *)user_data;
  struct bufferevent *bev = ses->bev;
  (void)session;
  (void)flags;

  /* Avoid excessive buffering in server side. */
  if (evbuffer_get_length(bufferevent_get_output(ses->bev)) >=
      OUTPUT_WOULDBLOCK_THRESHOLD)
  {
    return NGHTTP2_ERR_WOULDBLOCK;
  }
  int ret = bufferevent_write(bev, data, length);
  if (ret != 0) {
    log_err("bufferevent_write error");
  }
  return (ssize_t)length;
}

/*
** on_begin_headers_callback will be called when the first header arrived in ngsession
** this will cause session to create new stream_ctx
*/
static int on_begin_headers_callback(nghttp2_session *ngsession, const nghttp2_frame *frame, void *user_data)
{
  struct session *ses = (struct session *)user_data;
  // TODO: fullfill struct stream_context
  struct stream_context *stream_ctx;

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST)
  {
    return 0;
  }

  stream_ctx = hold_stream_context(ses, frame->hd.stream_id);
  // set stream_ctx for later callback for stream(id) on this session.
  nghttp2_session_set_stream_user_data(ngsession, frame->hd.stream_id,
                                       stream_ctx);
  return 0;
}

/* Returns int value of hex string character |c| */
static uint8_t hex_to_uint(uint8_t c) {
  if ('0' <= c && c <= '9') {
    return (uint8_t)(c - '0');
  }
  if ('A' <= c && c <= 'F') {
    return (uint8_t)(c - 'A' + 10);
  }
  if ('a' <= c && c <= 'f') {
    return (uint8_t)(c - 'a' + 10);
  }
  return 0;
}

/* Decodes percent-encoded byte string |value| with length |valuelen|
   and returns the decoded byte string in allocated buffer. The return
   value is NULL terminated. The caller must free the returned
   string. */
static char *percent_decode(const uint8_t *value, size_t valuelen)
{
  char *res;

  res = malloc(valuelen + 1);
  if (valuelen > 3)
  {
    size_t i, j;
    for (i = 0, j = 0; i < valuelen - 2;)
    {
      if (value[i] != '%' || !isxdigit(value[i + 1]) ||
          !isxdigit(value[i + 2]))
      {
        res[j++] = (char)value[i++];
        continue;
      }
      res[j++] =
          (char)((hex_to_uint(value[i + 1]) << 4) + hex_to_uint(value[i + 2]));
      i += 3;
    }
    memcpy(&res[j], &value[i], 2);
    res[j + 2] = '\0';
  }
  else
  {
    memcpy(res, value, valuelen);
    res[valuelen] = '\0';
  }
  return res;
}

static void print_header(const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen)
{
  size_t i;
  char *name_string = malloc((1 + namelen) * sizeof(uint8_t));
  for (i = 0; i < namelen; i++)
  {
    name_string[i] = name[i];
  }
  name_string[namelen] = '\0';

  char *value_string = malloc((1 + valuelen) * sizeof(uint8_t));
  for (i = 0; i < valuelen; i++)
  {
    value_string[i] = value[i];
  }
  value_string[valuelen] = '\0';

  log_info("HEADERS--> %10s: %s", name_string, value_string);
}

/*
** on_header_callback will be called if a full header received.
** for one kind header, coressponding request field will be set.
*/
static int
on_header_callback(nghttp2_session *ngsession, const nghttp2_frame *frame,
                   const uint8_t *name, size_t namelen,
                   const uint8_t *value, size_t valuelen,
                   uint8_t flags, void *user_data)
{
  struct stream_context *strm_ctx;

  // TODO: for every kind of header
  // method scheme authority path host...
  // set request's field.

  // for now, we just handle path and print every kinds of headers.

  const char PATH[] = ":path";

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST)
  {
    return 0;
  }

  strm_ctx = nghttp2_session_get_stream_user_data(ngsession, frame->hd.stream_id);
  if (!strm_ctx || strm_ctx->request_path)
  {
    return 0;
  }

  if (namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0)
  {
    size_t j;
    for (j = 0; j < valuelen && value[j] != '?'; ++j)
      ;
    strm_ctx->request_path = percent_decode(value, j);
  }

  print_header(name, namelen, value, valuelen);
  return 0;
}

static int ends_with(const char *s, const char *sub) {
  size_t slen = strlen(s);
  size_t sublen = strlen(sub);
  if (slen < sublen) {
    return 0;
  }
  return memcmp(s + slen - sublen, sub, sublen) == 0;
}


static int check_path(const char *path)
{
  /* We don't like '\' in url. */
  return path[0] && path[0] == '/' && strchr(path, '\\') == NULL &&
         strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
         !ends_with(path, "/..") && !ends_with(path, "/.");
}

static const char ERROR_HTML[] = "<html><head><title>404</title></head>"
                                 "<body><h1>404 Not Found</h1></body></html>";

static int error_reply(nghttp2_session *session,
                       struct stream_context *strm_ctx)
{
  int rv;
  ssize_t writelen;
  int pipefd[2];
  nghttp2_nv hdrs[] = {MAKE_NV(":status", "404")};

  rv = pipe(pipefd);
  if (rv != 0)
  {
    log_err("Could not create pipe");
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                   strm_ctx->stream_id,
                                   NGHTTP2_INTERNAL_ERROR);
    if (rv != 0)
    {
      log_err("Fatal error: %s", nghttp2_strerror(rv));
      return -1;
    }
    return 0;
  }

  writelen = write(pipefd[1], ERROR_HTML, sizeof(ERROR_HTML) - 1);
  close(pipefd[1]);

  if (writelen != sizeof(ERROR_HTML) - 1)
  {
    close(pipefd[0]);
    return -1;
  }

  strm_ctx->fd = pipefd[0];

  if (send_response(session, strm_ctx->stream_id, hdrs, ARRLEN(hdrs),
                    pipefd[0]) != 0)
  {
    close(pipefd[0]);
    return -1;
  }
  return 0;
}

static ssize_t file_read_callback(nghttp2_session *session, int32_t stream_id,
                                  uint8_t *buf, size_t length,
                                  uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data)
{
  int fd = source->fd;
  ssize_t r;
  (void)session;
  (void)stream_id;
  (void)user_data;

  while ((r = read(fd, buf, length)) == -1 && errno == EINTR)
    ;
  
  if (r == -1)
  {
    log_sys_err("sys error:");
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }
  if (r == 0)
  {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  return r;
}

static int send_response(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, int fd)
{
  int rv;
  nghttp2_data_provider data_prd;
  data_prd.source.fd = fd;
  data_prd.read_callback = file_read_callback;

  rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
  if (rv != 0)
  {
    log_err("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  log_info("submit response succeed!");
  return 0;
}

static int on_request_recv(nghttp2_session *session,
                           struct session *ses,
                           struct stream_context *strm_ctx)
{
  log_info("on request recv");
  int fd;
  nghttp2_nv hdrs[] = {MAKE_NV(":status", "200")};
  char *rel_path;

  if (!strm_ctx->request_path)
  {
    if (error_reply(session, strm_ctx) != 0)
    {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }
  fprintf(stderr, "%s GET %s\n", ses->client_addr,
          strm_ctx->request_path);
  if (!check_path(strm_ctx->request_path))
  {
    if (error_reply(session, strm_ctx) != 0)
    {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }
  for (rel_path = strm_ctx->request_path; *rel_path == '/'; ++rel_path)
    ;
  fd = open(rel_path, O_RDONLY);
  log_info("fd is: %d", fd);
  if (fd == -1)
  {
    if (error_reply(session, strm_ctx) != 0)
    {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }
  strm_ctx->fd = fd;

  if (send_response(session, strm_ctx->stream_id, hdrs, ARRLEN(hdrs), fd) !=
      0)
  {
    close(fd);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
/*
** on_frame_recv_callback will be called if one kind of frame is received
** there are two kinds of frame: NGHTTP2_DATA and NGHTTP2_HEADERS
** NGHTTP2_DATA means data fully received? no
** NGHTTP2_HEADERS means headers fully received? yes
** so we can call mux to get endpoint handler to handle(register cb)
** since http2 has one headers frame and multiple data frame
*/
static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
  struct session *ses = (struct session *)user_data;
  struct stream_context *strm_ctx;
  switch (frame->hd.type)
  {
  case NGHTTP2_DATA:
  case NGHTTP2_HEADERS:
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
    {
      strm_ctx =
          nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      /* For DATA and HEADERS frame, this callback may be called after
         on_stream_close_callback. Check that stream still alive. */
      if (!strm_ctx)
      {
        return 0;
      }
      return on_request_recv(session, ses, strm_ctx);
    }
    break;
  default:
    break;
  }

  return 0;
}

/*
** on_data_chunk_recv_callback will be called if a data chunk in data frame be received
** req with registerd callback will be called with fixed length byte array
*/
static int on_data_chunk_recv_callback(nghttp2_session *ses, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
  struct stream_context *strm_ctx = nghttp2_session_get_stream_user_data(ses, stream_id);

  // TODO: use stram_ctx to get the request, and call req.call_on_data(data, len);
  return 0;
}

static int on_stream_close_callback(nghttp2_session *ses, int32_t stream_id, uint32_t error_code, void *user_data)
{
  struct session *ses_ctx = (struct session *)user_data;
  struct stream_context *strm_ctx = nghttp2_session_get_stream_user_data(ses, stream_id);
  if (!strm_ctx) {
    return 0;
  }

  release_stream_context(ses_ctx, strm_ctx);
  return 0;
  // TODO: user strm_ctx to get the response, and call resp.call_on_close(err_code);

  // TODO: unhold the strm_ctx from session, and free the strm_ctx
}
