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
 * Description: provide container logs functions
 ******************************************************************************/
#define _GNU_SOURCE /* See feature_test_macros(7) */
#include <fcntl.h> /* Obtain O_* constant definitions */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
#include "error.h"

#include "logs.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"

const char g_cmd_logs_desc[] = "Fetch the logs of a container";
const char g_cmd_logs_usage[] = "logs [OPTIONS] CONTAINER";

struct client_arguments g_cmd_logs_args = {
    .follow = false,
    .tail = -1,
};

static int do_logs(const struct client_arguments *args)
{
#define DISABLE_ERR_MESSAGE "disable console log"
    isula_connect_ops *ops = NULL;
    struct isula_logs_request *request = NULL;
    struct isula_logs_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_logs_response));
    if (response == NULL) {
        ERROR("Log: Out of memory");
        return -1;
    }
    request = util_common_calloc_s(sizeof(struct isula_logs_request));
    if (request == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ops = get_connect_client_ops();
    if (ops == NULL || ops->container.logs == NULL) {
        ERROR("Unimplemented logs op");
        ret = -1;
        goto out;
    }

    request->id = util_strdup_s(args->name);
    request->runtime = util_strdup_s(args->runtime);
    request->follow = args->follow;
    request->tail = (int64_t)args->tail;

    config = get_connect_config(args);
    ret = ops->container.logs(request, response, &config);
    if (ret != 0) {
        if (strncmp(response->errmsg, DISABLE_ERR_MESSAGE, strlen(DISABLE_ERR_MESSAGE)) == 0) {
            fprintf(stdout, "[WARNING]: Container %s disable console log!\n", args->name);
            ret = 0;
            goto out;
        }
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = -1;
        goto out;
    }

out:
    isula_logs_response_free(response);
    isula_logs_request_free(request);
    return ret;
}

int callback_tail(command_option_t *option, const char *arg)
{
    if (util_safe_llong(arg, option->data)) {
        *(long long *)option->data = -1;
    }
    return 0;
}

static int cmd_logs_init(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;

    if (client_arguments_init(&g_cmd_logs_args)) {
        COMMAND_ERROR("client arguments init failed\n");
        return ECOMMON;
    }
    g_cmd_logs_args.progname = argv[0];
    struct command_option options[] = { LOG_OPTIONS(lconf), LOGS_OPTIONS(g_cmd_logs_args),
                                        COMMON_OPTIONS(g_cmd_logs_args) };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_logs_desc,
                 g_cmd_logs_usage);
    if (command_parse_args(&cmd, &g_cmd_logs_args.argc, &g_cmd_logs_args.argv)) {
        return EINVALIDARGS;
    }
    isula_libutils_default_log_config(argv[0], &lconf);
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed\n");
        g_cmd_logs_args.name = g_cmd_logs_args.argv[0];
        return ECOMMON;
    }

    if (g_cmd_logs_args.argc != 1) {
        COMMAND_ERROR("Logs needs one container name");
        return ECOMMON;
    }

    return 0;
}

int cmd_logs_main(int argc, const char **argv)
{
    int ret = 0;

    ret = cmd_logs_init(argc, argv);
    if (ret != 0) {
        exit(ret);
    }

    g_cmd_logs_args.name = g_cmd_logs_args.argv[0];
    ret = do_logs(&g_cmd_logs_args);
    if (ret != 0) {
        exit(ECOMMON);
    }
    return 0;
}
