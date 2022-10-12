#ifndef SESSION_H
#define SESSION_H

#include<nghttp2/nghttp2.h>
#include <event2/bufferevent.h>
#include "stream_context.h"

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)

struct session {
    nghttp2_session *ngsession;
    char *client_addr;
    struct bufferevent *bev;
    struct stream_context strm_ctx_root;
};

#include "server.h"
struct session *session_create(struct server *svr, int fd, struct sockaddr *addr, int addrlen);

void session_destroy(struct session *ses);

struct stream_context* hold_stream_context(struct session *ses, int stream_id);

int release_stream_context(struct session *ses, struct stream_context *strm_ctx);

int initialize_nghttp2_session(struct session *ses);

#endif

