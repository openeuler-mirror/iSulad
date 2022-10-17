#include "server.h"


void acceptcb(struct evconnlistener *listener, int fd,
                     struct sockaddr *addr, int addrlen, void *arg) {
  struct server *svr = (struct server *)arg;
  (void)listener;
  log_info("accepted on fd: %d", fd);
  session_create(svr, fd, addr, addrlen);
  log_info("session created for fd: %d", fd);
}

struct server *server_create(char *host, char *port)
{
  struct server *svr = malloc(sizeof(struct server));
  svr->host = host;
  svr->port = port;
  svr->eg = io_engine_create();
  return svr;
}

int server_listen_and_serve(struct server *svr)
{
  apply_listener(svr->eg, svr->host, svr->port, acceptcb, svr);

  event_base_loop(svr->eg->evbase, 0);
  // struct event_base *evbase;
  // evbase = event_base_new();
  // event_base_loop(evbase, 0); 
  return 0;
}

void server_destroy(void *ptr)
{
  struct server *svr = (struct server *)ptr;
  io_engine_destroy((void *)(svr->eg));
  free(ptr);
}