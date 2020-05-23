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
 * Description: provide container remove functions
 ******************************************************************************/
#include "top.h"
#include <limits.h>
#include "arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "commands.h"
#include "console.h"
#include "utils.h"
#include "isula_libutils/container_inspect.h"
#include "attach.h"
#include "commander.h"

const char g_cmd_top_desc[] = "Display the running processes of a container";
const char g_cmd_top_usage[] = "top [OPTIONS] CONTAINER [ps OPTIONS]";

struct client_arguments g_cmd_top_args = {};
static void client_top_info_server(const struct isula_top_response *response)
{
    size_t i;

    if (response->titles != NULL) {
        printf("%s\n", response->titles);
    }

    if (response->processes_len == 0 || response->processes == NULL) {
        return;
    }

    for (i = 0; i < response->processes_len; i++) {
        printf("%s\n", response->processes[i]);
    }
}

/*
* Create a rm request message and call RPC
*/
static int client_top(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_top_request request = { 0 };
    struct isula_top_response *response = NULL;
    container_inspect *inspect_data = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_top_response));
    if (response == NULL) {
        ERROR("TOP: Out of memory");
        return -1;
    }

    if (inspect_container(args, &inspect_data)) {
        ERROR("inspect data error");
        ret = -1;
        goto out;
    }

    if (inspect_data == NULL) {
        ERROR("inspect data is null");
        ret = -1;
        goto out;
    }

    if (inspect_data->state != NULL && !inspect_data->state->running) {
        COMMAND_ERROR("You cannot attach to a stopped container, start it first");
        ret = -1;
        goto out;
    }

    if (inspect_data->state != NULL && inspect_data->state->restarting) {
        COMMAND_ERROR("You cannot attach to a restarting container, wait until it is running");
        ret = -1;
        goto out;
    }

    request.name = args->name;
    request.ps_argc = args->argc;
    request.ps_args = (char **)args->argv;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.top) {
        ERROR("Unimplemented top op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);

    ret = ops->container.top(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
    }
    client_top_info_server(response);

out:
    free_container_inspect(inspect_data);
    isula_top_response_free(response);
    return ret;
}

int cmd_top_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf), COMMON_OPTIONS(g_cmd_top_args) };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_top_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_top_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_top_desc,
                 g_cmd_top_usage);

    if (command_parse_args(&cmd, &g_cmd_top_args.argc, &g_cmd_top_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Top: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_top_args.argc < 1) {
        COMMAND_ERROR("\"%s top\" requires at least 1 argument(s).", g_cmd_top_args.progname);
        COMMAND_ERROR("See '%s top --help'.", g_cmd_top_args.progname);
        exit(EINVALIDARGS);
    } else {
        g_cmd_top_args.name = g_cmd_top_args.argv[0];
        g_cmd_top_args.argc--;
        g_cmd_top_args.argv++;
    }

    if (client_top(&g_cmd_top_args) != 0) {
        ERROR("Container \"%s\" top failed", g_cmd_top_args.name);
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
