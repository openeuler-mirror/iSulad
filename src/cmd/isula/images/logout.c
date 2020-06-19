/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangfengtu
 * Create: 2019-6-18
 * Description: provide logout
 ********************************************************************************/
#include "logout.h"

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_connect.h"
#include "isula_libutils/log.h"

const char g_cmd_logout_desc[] = "Log out from a Docker registry";
const char g_cmd_logout_usage[] = "logout SERVER";

struct client_arguments g_cmd_logout_args = {};

/*
 * Logout from a docker registry.
 */
int client_logout(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_logout_request request = { 0 };
    struct isula_logout_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_logout_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return ECOMMON;
    }

    // Support type oci only currently.
    request.type = "oci";
    request.server = args->server;

    ops = get_connect_client_ops();
    if (ops == NULL || ops->image.logout == NULL) {
        ERROR("Unimplemented ops");
        ret = ECOMMON;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->image.logout(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = ESERVERERROR;
        goto out;
    }

    COMMAND_ERROR("Logout Succeeded");

out:
    isula_logout_response_free(response);
    return ret;
}

int cmd_logout_main(int argc, const char **argv)
{
    int ret = 0;
    struct isula_libutils_log_config lconf = { 0 };
    int exit_code = 1; /* exit 1 if failed to logout */
    command_t cmd;
    struct command_option options[] = { COMMON_OPTIONS(g_cmd_logout_args) };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_logout_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_logout_args.progname = argv[0];

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_logout_desc,
                 g_cmd_logout_usage);
    if (command_parse_args(&cmd, &g_cmd_logout_args.argc, &g_cmd_logout_args.argv)) {
        exit(exit_code);
    }

    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("logout: log init failed");
        exit(exit_code);
    }

    if (g_cmd_logout_args.argc != 1) {
        COMMAND_ERROR("logout requires 1 argument.");
        exit(exit_code);
    }

    g_cmd_logout_args.server = g_cmd_logout_args.argv[0];
    ret = client_logout(&g_cmd_logout_args);
    if (ret != 0) {
        exit(exit_code);
    }

    exit(EXIT_SUCCESS);
}
