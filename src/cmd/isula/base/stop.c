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
 * Description: provide container stop functions
 ******************************************************************************/
#include "stop.h"

#include <stdio.h>
#include <stdlib.h>

#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "isula_connect.h"
#include "connect.h"
#include "libisula.h"

const char g_cmd_stop_desc[] = "Stop one or more containers";
const char g_cmd_stop_usage[] = "stop [OPTIONS] CONTAINER [CONTAINER...]";

struct client_arguments g_cmd_stop_args = {
    .force = false,
    .time = 10,
};

/*
 * Create a stop request message and call RPC
 */
static int client_stop(const struct client_arguments *args)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_stop_request request = { 0 };
    struct isula_stop_response *response = NULL;
    client_connect_config_t config = { 0 };

    response = util_common_calloc_s(sizeof(struct isula_stop_response));
    if (response == NULL) {
        ERROR("Stop: Out of memory");
        return -1;
    }

    request.name = args->name;
    request.force = args->force;
    request.timeout = args->time;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.stop) {
        ERROR("Unimplemented stop op");
        ret = -1;
        goto out;
    }
    config = get_connect_config(args);
    ret = ops->container.stop(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
    }
out:
    isula_stop_response_free(response);
    return ret;
}

int cmd_stop_main(int argc, const char **argv)
{
    int i = 0;
    int status = 0;
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf), COMMON_OPTIONS(g_cmd_stop_args),
               STOP_OPTIONS(g_cmd_stop_args)
    };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_stop_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_stop_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_stop_desc,
                 g_cmd_stop_usage);
    if (command_parse_args(&cmd, &g_cmd_stop_args.argc, &g_cmd_stop_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_stop_args.force) {
        g_cmd_stop_args.time = 0;
    }

    if (g_cmd_stop_args.argc == 0) {
        COMMAND_ERROR("Stop requires minimum of 1 container name");
        exit(EINVALIDARGS);
    }

    if (g_cmd_stop_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many containers to stop.");
        exit(EINVALIDARGS);
    }

    for (i = 0; i < g_cmd_stop_args.argc; i++) {
        g_cmd_stop_args.name = g_cmd_stop_args.argv[i];
        if (client_stop(&g_cmd_stop_args)) {
            ERROR("Container \"%s\" stop failed", g_cmd_stop_args.name);
            status = -1;
            continue;
        }
        printf("%s\n", g_cmd_stop_args.name);
    }
    if (status) {
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
