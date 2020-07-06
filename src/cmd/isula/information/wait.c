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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container wait functions
 ******************************************************************************/
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "wait.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "command_parser.h"
#include "connect.h"
#include "constants.h"
#include "libisula.h"
#include "utils.h"

const char g_cmd_wait_desc[] = "Block until one or more containers stop, then print their exit codes";
const char g_cmd_wait_usage[] = "wait [OPTIONS] CONTAINER [CONTAINER...]";

struct client_arguments g_cmd_wait_args = {};

/*
* Create a delete request message and call RPC
*/
int client_wait(const struct client_arguments *args, unsigned int *exit_code)
{
    isula_connect_ops *ops = NULL;
    struct isula_wait_request request = { 0 };
    struct isula_wait_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_wait_response));
    if (response == NULL) {
        ERROR("Wait: Out of memory");
        return -1;
    }

    request.id = args->name;
    if (args->custom_conf.auto_remove == false) {
        request.condition = WAIT_CONDITION_STOPPED;
    } else {
        request.condition = WAIT_CONDITION_REMOVED;
    }

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.wait) {
        ERROR("Unimplemented wait op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.wait(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        if (response->cc) {
            ret = ESERVERERROR;
        } else {
            ret = ECOMMON;
        }
        goto out;
    }
    if (exit_code != NULL) {
        *exit_code = (unsigned int)response->exit_code;
    }

out:
    isula_wait_response_free(response);
    return ret;
}

int cmd_wait_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    unsigned int exit_code = 0;
    int i = 0;
    int status = 0;
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf), COMMON_OPTIONS(g_cmd_wait_args) };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_wait_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_wait_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_wait_desc,
                 g_cmd_wait_usage);
    if (command_parse_args(&cmd, &g_cmd_wait_args.argc, &g_cmd_wait_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Wait: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_wait_args.socket == NULL) {
        COMMAND_ERROR("Missing --host,-H option");
        exit(EINVALIDARGS);
    }

    if (g_cmd_wait_args.argc == 0) {
        COMMAND_ERROR("Wait requires at least 1 container names");
        exit(EINVALIDARGS);
    }

    if (g_cmd_wait_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many containers to wait.");
        exit(EINVALIDARGS);
    }

    for (i = 0; i < g_cmd_wait_args.argc; i++) {
        g_cmd_wait_args.name = g_cmd_wait_args.argv[i];
        if (client_wait(&g_cmd_wait_args, &exit_code)) {
            ERROR("Container \"%s\" wait failed", g_cmd_wait_args.name);
            status = -1;
            continue;
        }
        printf("%u\n", exit_code);
    }

    if (status) {
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
