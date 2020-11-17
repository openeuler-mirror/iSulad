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
 * Description: provide container restart functions
 ******************************************************************************/
#include "restart.h"
#include <stdio.h>
#include <stdlib.h>

#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "isula_connect.h"
#include "connect.h"

const char g_cmd_restart_desc[] = "Restart one or more containers";
const char g_cmd_restart_usage[] = "restart [OPTIONS] CONTAINER [CONTAINER...]";

struct client_arguments g_cmd_restart_args = {
    .force = false,
    .time = 10,
};

static int client_restart(const struct client_arguments *args)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_restart_request request = { 0 };
    struct isula_restart_response *response = NULL;
    client_connect_config_t config = { 0 };

    response = util_common_calloc_s(sizeof(struct isula_restart_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    request.name = args->name;
    request.timeout = (unsigned int)args->time;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.restart) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.restart(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
    }
out:
    isula_restart_response_free(response);
    return ret;
}

int cmd_restart_main(int argc, const char **argv)
{
    int i = 0;
    int status = 0;
    command_t cmd;
    struct isula_libutils_log_config lconf = { 0 };
    struct command_option options[] = { LOG_OPTIONS(lconf) COMMON_OPTIONS(g_cmd_restart_args)
        RESTART_OPTIONS(g_cmd_restart_args)
    };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_restart_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_restart_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_restart_desc,
                 g_cmd_restart_usage);

    if (command_parse_args(&cmd, &g_cmd_restart_args.argc, &g_cmd_restart_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Restart: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_restart_args.argc == 0) {
        COMMAND_ERROR("Restart requires at least 1 container names");
        exit(EINVALIDARGS);
    }

    if (g_cmd_restart_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many containers to restart.");
        exit(EINVALIDARGS);
    }

    for (i = 0; i < g_cmd_restart_args.argc; i++) {
        g_cmd_restart_args.name = g_cmd_restart_args.argv[i];
        if (client_restart(&g_cmd_restart_args)) {
            status = -1;
            continue;
        }

        printf("%s\n", g_cmd_restart_args.name);
    }

    if (status != 0) {
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
