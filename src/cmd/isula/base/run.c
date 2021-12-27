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
 * Description: provide container run functions
 ******************************************************************************/
#include "run.h"
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "isula_connect.h"
#include "console.h"
#include "error.h"
#include "connect.h"
#include "create.h"

#include "start.h"
#include "wait.h"

const char g_cmd_run_desc[] = "Run a command in a new container";
const char g_cmd_run_usage[] = "run [OPTIONS] ROOTFS|IMAGE [COMMAND] [ARG...]";
static int run_checker(struct client_arguments *args);
struct client_arguments g_cmd_run_args = {
    .runtime = "",
    .restart = "no",
    .pull = "missing"
};

static int local_cmd_start(const struct client_arguments *args)
{
    int ret = 0;
    bool reset_tty = false;
    struct termios oldtios;
    struct command_fifo_config *console_fifos = NULL;
    unsigned int exit_code = 0;

    ret = client_start(args, &reset_tty, &oldtios, &console_fifos);
    if (ret != 0) {
        goto free_out;
    }

    if (!args->detach) {
        ret = client_wait(args, &exit_code);
        if (ret != 0) {
            goto free_out;
        }
        ret = (int)exit_code;
    }

    client_wait_fifo_exit(args);

free_out:
    client_restore_console(reset_tty, &oldtios, console_fifos);
    return ret;
}

static int remote_cmd_start(const struct client_arguments *args)
{
    int ret = 0;
    unsigned int exit_code = 0;

    ret = client_remote_start(&g_cmd_run_args);
    if (ret != 0) {
        goto out;
    }

    if (!args->detach) {
        ret = client_wait(args, &exit_code);
        if (ret != 0) {
            goto out;
        }
        ret = (int)exit_code;
    }

out:
    return ret;
}

static int do_resize_run_console(const struct client_arguments *args, unsigned int height, unsigned int width)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_resize_request request = { 0 };
    struct isula_resize_response *response = NULL;
    client_connect_config_t config = { 0 };

    ops = get_connect_client_ops();
    if (ops == NULL || ops->container.resize == NULL) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }

    request.id = args->name;
    request.height = height;
    request.width = width;

    response = util_common_calloc_s(sizeof(struct isula_resize_response));
    if (response == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.resize(&request, response, &config);
    if (ret != 0) {
        ERROR("Failed to call resize");
        goto out;
    }

out:
    isula_resize_response_free(response);
    return ret;
}

int cmd_run_main(int argc, const char **argv)
{
    int ret = 0;
    command_t cmd = { 0 };
    struct isula_libutils_log_config lconf = { 0 };

    if (client_arguments_init(&g_cmd_run_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_run_args.custom_conf.attach_stdout = true;
    g_cmd_run_args.custom_conf.attach_stderr = true;
    g_cmd_run_args.resize_cb = do_resize_run_console;

    g_cmd_run_args.progname = argv[0];
    g_cmd_run_args.subcommand = argv[1];
    struct command_option options[] = { LOG_OPTIONS(lconf) COMMON_OPTIONS(g_cmd_run_args) CREATE_OPTIONS(g_cmd_run_args)
        CREATE_EXTEND_OPTIONS(g_cmd_run_args) RUN_OPTIONS(g_cmd_run_args)
#ifdef ENABLE_NATIVE_NETWORK
        CREATE_NETWORK_OPTIONS(g_cmd_run_args)
#endif
    };
    isula_libutils_default_log_config(argv[0], &lconf);
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_run_desc,
                 g_cmd_run_usage);
    if (command_parse_args(&cmd, &g_cmd_run_args.argc, &g_cmd_run_args.argv) || run_checker(&g_cmd_run_args)) {
        exit(EINVALIDARGS);
    }

    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        exit(ECOMMON);
    }

    ret = client_create(&g_cmd_run_args);
    if (ret) {
        ERROR("Container \"%s\" create failed", g_cmd_run_args.name);
        exit(ret);
    }

    if (g_cmd_run_args.detach) {
        printf("%s\n", g_cmd_run_args.name);
    }

    if (g_cmd_run_args.custom_conf.tty && isatty(STDIN_FILENO)) {
        (void)start_client_console_resize_thread(&g_cmd_run_args);
    }

    if (strncmp(g_cmd_run_args.socket, "tcp://", strlen("tcp://")) == 0) {
        ret = remote_cmd_start(&g_cmd_run_args);
        if (ret != 0) {
            ERROR("Failed to execute command with remote run");
            goto free_out;
        }
    } else {
        ret = local_cmd_start(&g_cmd_run_args);
        if (ret != 0) {
            ERROR("Failed to execute command with local run");
            goto free_out;
        }
    }

free_out:
    exit(ret);
}

static int run_checker(struct client_arguments *args)
{
    int ret = 0;

    ret = create_checker(args);
    if (ret) {
        goto out;
    }

    /* Make detach option a high priority than terminal */
    if (args->detach) {
        args->custom_conf.attach_stdin = false;
        args->custom_conf.attach_stdout = false;
        args->custom_conf.attach_stderr = false;
    }

    if (args->custom_conf.auto_remove && ((args->restart != NULL) && (strcmp("no", args->restart) != 0))) {
        COMMAND_ERROR("Conflicting options: --restart and --rm");
        ret = -1;
        goto out;
    }

out:
    return ret;
}
