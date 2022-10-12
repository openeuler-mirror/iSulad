#include "mux.h"
#include <string.h>


void mux_as_handler(struct request *req, struct response *resp, void *handler_ctx)
{
    struct mux *mx = (struct mux *)handler_ctx;

}


handler get_target_handler(struct mux *mx, struct request *req)
{
    char * target_path = req -> path;
    int i = 0;

    for (i = 0; i < mx->count; i++) {
        if (strcmp(mx->paths[i], target_path) == 0) {
            return mx->handlers[i];
        }
    }

    return not_found_as_handler;
}

int register_handler(struct mux *mx, char *pattern, handler h)
{
    mx->paths[mx->count] = pattern;
    mx->handlers[mx->count] = h;
    mx->count++;
}

void not_found_as_handler(struct request *req, struct response *resp, void *handler_ctx)
{
    char *resp_string = "404 not found";
}