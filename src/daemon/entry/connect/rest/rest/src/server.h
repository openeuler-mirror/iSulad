#ifndef SERVER_H
#define SERVER_H

#include "log.h"
#include "ioevent.h"

struct server {
    struct io_engine *eg;
    char *port;
    char *host;
};

#include "session.h"

struct server *server_create(char *host, char *port);

void server_destroy(void *ptr);

int server_listen_and_serve(struct server *svr); 

void acceptcb(struct evconnlistener *listener, int fd,
                     struct sockaddr *addr, int addrlen, void *arg);

#endif