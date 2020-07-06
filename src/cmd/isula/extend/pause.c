/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide container pause functions
 ******************************************************************************/
#include "pause.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "command_parser.h"
#include "connect.h"
#include "libisula.h"

const char g_cmd_pause_desc[] = "Pause all processes within one or more containers";
const char g_cmd_pause_usage[] = "pause [OPTIONS] CONTAINER [CONTAINER...]";

struct client_arguments g_cmd_pause_args = {};

/*
 * Create a pause request message and call RPC
 */
static int client_pause(const struct client_arguments *args)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_pause_request request = { 0 };
    struct isula_pause_response *response = NULL;
    client_connect_config_t config = { 0 };

    response = util_common_calloc_s(sizeof(struct isula_pause_response));
    if (response == NULL) {
        ERROR("Pause: Out of memory");
        return -1;
    }

    request.name = args->name;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.pause) {
        ERROR("Unimplemented pause op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.pause(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
    }
out:
    isula_pause_response_free(response);
    return ret;
}

int cmd_pause_main(int argc, const char **argv)
{
    int i = 0;
    int status = 0;
    struct isula_libutils_log_config lconf = { 0 };

    lconf.name = argv[0];
    lconf.quiet = true;
    lconf.file = NULL;
    lconf.priority = "ERROR";
    lconf.driver = "stdout";
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        exit(ECOMMON);
    }
    command_t cmd;
    if (client_arguments_init(&g_cmd_pause_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_pause_args.progname = argv[0];
    struct command_option options[] = { COMMON_OPTIONS(g_cmd_pause_args) };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_pause_desc,
                 g_cmd_pause_usage);
    if (command_parse_args(&cmd, &g_cmd_pause_args.argc, &g_cmd_pause_args.argv)) {
        exit(EINVALIDARGS);
    }

    if (g_cmd_pause_args.argc == 0) {
        COMMAND_ERROR("Pause requires at least 1 container names");
        exit(EINVALIDARGS);
    }

    if (g_cmd_pause_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many containers to pause.");
        exit(EINVALIDARGS);
    }

    for (i = 0; i < g_cmd_pause_args.argc; i++) {
        g_cmd_pause_args.name = g_cmd_pause_args.argv[i];
        if (client_pause(&g_cmd_pause_args)) {
            ERROR("Container \"%s\" pause failed", g_cmd_pause_args.name);
            status = -1;
            continue;
        }

        printf("%s\n", g_cmd_pause_args.name);
    }

    if (status) {
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
