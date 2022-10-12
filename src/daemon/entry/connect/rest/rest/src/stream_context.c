#include "stream_context.h"
#include <string.h>
#include <stdlib.h>

struct stream_context *stream_context_create(int streamid)
{
    struct stream_context *stream_ctx;

    stream_ctx = malloc(sizeof(struct stream_context));
    memset(stream_ctx, 0, sizeof(struct stream_context));
    stream_ctx->stream_id = streamid;

    return stream_ctx;
}

void stream_context_destroy(struct stream_context* strm_ctx)
{
    free(strm_ctx);
}