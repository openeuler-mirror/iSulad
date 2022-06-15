/******************************************************************************
 * Author: xiangli
 * Create: 2022-6-10
 * Description: provide search image
 ********************************************************************************/

#ifndef CMD_ISULA_IMAGES_SEARCH_H
#define CMD_ISULA_IMAGES_SEARCH_H

#include "client_arguments.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned int name_length;
    unsigned int tag_length;
} lengths;

extern const char g_cmd_search_desc[];
extern const char g_cmd_search_usage[];
extern struct client_arguments g_cmd_search_args;
int client_search(const struct client_arguments *args);

int cmd_search_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_IMAGES_SEARCH_H
