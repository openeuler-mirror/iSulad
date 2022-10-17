#include "ioevent.h"
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "log.h"


struct evconnlistener *
apply_listener(struct io_engine *eg, const char *host, const char *listen_addr, evconnlistener_cb acceptcb, void *arg)
{
    int ret;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
    hints.ai_flags |= AI_ADDRCONFIG;
#endif

    ret = getaddrinfo(host, listen_addr, &hints, &res);
    if (ret != 0) {
        log_sys_err("could resolve server listen addr: ");
        return NULL;
    }
    struct evconnlistener *listener = NULL;
    for (rp = res; rp; rp = rp->ai_next) {
        // log_info("listen on: %s:%d", rp->ai_addr, (int)rp->ai_addrlen);
        struct sockaddr_in *addr = (struct sockaddr_in *)rp->ai_addr;
        // log_info("addr: %d: %d", (int)addr->sin_addr.s_addr, (int)addr->sin_port);
        char *ip = inet_ntoa(addr->sin_addr);
        uint16_t port = htons(addr->sin_port);
        log_info("addr: %s:%d", ip, port);
        listener = evconnlistener_new_bind(
            eg->evbase, acceptcb, arg, LEV_OPT_CLOSE_ON_FREE| LEV_OPT_REUSEABLE, \
            16, rp->ai_addr, (int)rp->ai_addrlen);
        if (listener) {
            break;
        }
    } 

    freeaddrinfo(res);
    return listener;
}

// TODO: error handling!
struct bufferevent *
apply_bufferevent(struct io_engine *eg, int fd, bufferevent_data_cb readcb, bufferevent_data_cb writecb, bufferevent_event_cb eventcb, void *ctx)
{
    struct bufferevent * bev = NULL;
    bev = bufferevent_socket_new(eg->evbase, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    // bufferevent_enable(bev, 0);
    bufferevent_setcb(bev, readcb, writecb, eventcb, ctx);
    return bev;
}


struct io_engine *io_engine_create()
{
    struct io_engine *eg;
    eg = (struct io_engine *)malloc(sizeof(struct io_engine));
    eg->evbase = event_base_new();
    return eg;
}

void io_engine_destroy(void *ptr)
{
    struct io_engine *eg = (struct io_engine *)ptr;
    event_base_free(eg->evbase);
    free(ptr);
}