#include "server.h"


int main(int argc, char *argv[])
{
    if (argc < 2) {
        log_err("usage: ./server <host> <port>");
        return -1;
    }
    struct server *svr = server_create(argv[1], argv[2]);
    server_listen_and_serve(svr);

    return 0;
}