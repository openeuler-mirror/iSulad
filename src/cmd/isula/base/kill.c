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
 * Description: provide container kill functions
 ******************************************************************************/
#include "error.h"
#include "client_arguments.h"
#include "kill.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"

const char g_cmd_kill_desc[] = "Kill one or more  running containers";
const char g_cmd_kill_usage[] = "kill [OPTIONS] CONTAINER [CONTAINER...]";

struct client_arguments g_cmd_kill_args = {
    .signal = "SIGKILL",
};

static int client_kill(const struct client_arguments *args)
{
    int ret = 0;
    int signal = -1;
    isula_connect_ops *ops = NULL;
    struct isula_kill_request request = { 0 };
    struct isula_kill_response *response = NULL;
    client_connect_config_t config = { 0 };

    response = util_common_calloc_s(sizeof(struct isula_kill_response));
    if (response == NULL) {
        ERROR("Kill: Out of memory");
        return -1;
    }

    request.name = args->name;

    signal = util_sig_parse(args->signal);
    if (signal < 0) {
        ERROR("Invalid signal number");
        ret = -1;
        goto out;
    }
    request.signal = (uint32_t)signal;

    ops = get_connect_client_ops();
    if (ops == NULL || ops->container.kill == NULL) {
        ERROR("Unimplemented kill op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.kill(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        goto out;
    }

out:
    isula_kill_response_free(response);
    return ret;
}

int cmd_kill_main(int argc, const char **argv)
{
    int signo;
    int i = 0;
    int status = 0;
    command_t cmd;
    struct isula_libutils_log_config lconf = { 0 };

    if (client_arguments_init(&g_cmd_kill_args)) {
        COMMAND_ERROR("client arguments init failed\n");
        exit(ECOMMON);
    }
    g_cmd_kill_args.progname = argv[0];
    struct command_option options[] = { LOG_OPTIONS(lconf), COMMON_OPTIONS(g_cmd_kill_args),
               KILL_OPTIONS(g_cmd_kill_args)
    };
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_kill_desc,
                 g_cmd_kill_usage);
    if (command_parse_args(&cmd, &g_cmd_kill_args.argc, &g_cmd_kill_args.argv)) {
        exit(ECOMMON);
    }
    isula_libutils_default_log_config(argv[0], &lconf);
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed\n");
        exit(ECOMMON);
    }

    signo = util_sig_parse(g_cmd_kill_args.signal);
    if (signo == -1) {
        COMMAND_ERROR("Invalid signal: %s", g_cmd_kill_args.signal);
        exit(ECOMMON);
    }

    if (!util_valid_signal(signo)) {
        COMMAND_ERROR("The Linux daemon does not support signal %d", signo);
        exit(ECOMMON);
    }

    if (g_cmd_kill_args.argc == 0) {
        COMMAND_ERROR("Kill requires at least 1 container names");
        exit(EINVALIDARGS);
    }

    if (g_cmd_kill_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many containers to kill.");
        exit(EINVALIDARGS);
    }

    for (i = 0; i < g_cmd_kill_args.argc; i++) {
        g_cmd_kill_args.name = g_cmd_kill_args.argv[i];
        if (client_kill(&g_cmd_kill_args)) {
            ERROR("Container \"%s\" kill failed", g_cmd_kill_args.name);
            status = -1;
            continue;
        }

        printf("%s\n", g_cmd_kill_args.name);
    }

    if (status) {
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
