#ifndef MUX_H
#define MUX_H

#include "request.h"
#include "response.h"
#include <string.h>

#define MAXHANDLERS 128

typedef void(*handler)(struct request *req, struct response *resp, void *handler_ctx);

struct mux {
    char *paths[MAXHANDLERS];
    handler handlers[MAXHANDLERS];
    int count; 
};

void mux_as_handler(struct request *req, struct response *resp, void *handler_ctx);

handler get_target_handler(struct mux *mx, struct request *req);

int register_handler(struct mux *mx, char *pattern, handler h);


struct http_err_not_found {

};

void not_found_as_handler(struct request *req, struct response *resp, void *handler_ctx);

#endif