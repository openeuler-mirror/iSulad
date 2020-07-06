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
 * Author: maoweiyong
 * Create: 2018-11-08
 * Description: provide container start  functions
 ******************************************************************************/
#include <semaphore.h>
#include <termios.h> // IWYU pragma: keep
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "error.h"
#include "client_arguments.h"
#include "start.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "console.h"
#include "utils.h"
#include "isula_commands.h"
#include "command_parser.h"
#include "connect.h"
#include "libisula.h"

const char g_cmd_start_desc[] = "Start one or more stopped containers";
const char g_cmd_start_usage[] = "start [OPTIONS] CONTAINER [CONTAINER...]";

sem_t g_console_waitopen_sem;
sem_t g_console_waitexit_sem;

struct client_arguments g_cmd_start_args = {};

static int start_cmd_init(const struct client_arguments *args)
{
    if (sem_init(&g_console_waitopen_sem, 0, 0)) {
        ERROR("Container %s Semaphore initialization failed", args->name);
        return ECOMMON;
    }

    if (sem_init(&g_console_waitexit_sem, 0, 0)) {
        ERROR("Container %s Semaphore initialization failed", args->name);
        sem_destroy(&g_console_waitopen_sem);
        return ECOMMON;
    }

    return 0;
}

static int start_prepare_console(const struct client_arguments *args, struct termios *oldtios, bool *reset_tty,
                                 struct command_fifo_config **console_fifos)
{
    int ret = 0;
    int istty = 0;

    istty = isatty(0);
    if (istty && args->custom_conf.tty && args->custom_conf.attach_stdin) {
        if (setup_tios(0, oldtios)) {
            ERROR("Failed to setup terminal properties");
            ret = ECOMMON;
            goto out;
        }
        *reset_tty = true;
    }
    if (!istty) {
        INFO("The input device is not a TTY");
    }

    if (args->custom_conf.attach_stdin || args->custom_conf.attach_stdout || args->custom_conf.attach_stderr) {
        if (create_console_fifos(args->custom_conf.attach_stdin, args->custom_conf.attach_stdout,
                                 args->custom_conf.attach_stderr, args->name, "start", console_fifos)) {
            ERROR("Container \"%s\" create console FIFO failed", args->name);
            ret = ECOMMON;
            goto out;
        }

        (*console_fifos)->wait_open = &g_console_waitopen_sem;
        (*console_fifos)->wait_exit = &g_console_waitexit_sem;
        if (start_client_console_thread(*console_fifos, args->custom_conf.tty)) {
            ERROR("Container \"%s\" start console thread failed", args->name);
            ret = ECOMMON;
            goto out;
        }
    }

out:
    return ret;
}

static int do_client_start(const struct client_arguments *args, struct command_fifo_config **console_fifos)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_start_request request = { 0 };
    struct isula_start_response *response = NULL;
    client_connect_config_t config = { 0 };

    ops = get_connect_client_ops();
    if (ops == NULL || ops->container.start == NULL) {
        ERROR("Unimplemented ops");
        ret = ECOMMON;
        goto out;
    }

    request.name = args->name;
    if (console_fifos != NULL && *console_fifos != NULL) {
        request.stdin = (*console_fifos)->stdin_name;
        request.stdout = (*console_fifos)->stdout_name;
        request.stderr = (*console_fifos)->stderr_name;
    }
    request.attach_stdin = args->custom_conf.attach_stdin;
    request.attach_stdout = args->custom_conf.attach_stdout;
    request.attach_stderr = args->custom_conf.attach_stderr;

    response = util_common_calloc_s(sizeof(struct isula_start_response));
    if (response == NULL) {
        ERROR("Out of memory");
        ret = ECOMMON;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.start(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        if (response->server_errono ||
            (response->errmsg && !strcmp(response->errmsg, errno_to_error_message(ISULAD_ERR_CONNECT)))) {
            ret = ESERVERERROR;
            util_contain_errmsg(response->errmsg, &ret);
        } else {
            ret = ECOMMON;
        }
        goto out;
    }

out:
    isula_start_response_free(response);
    response = NULL;
    return ret;
}

/*
* Create a create request message and call RPC
*/
int client_start(const struct client_arguments *args, bool *reset_tty, struct termios *oldtios,
                 struct command_fifo_config **console_fifos)
{
    int ret = 0;

    ret = start_cmd_init(args);
    if (ret != 0) {
        return ret;
    }

    if (oldtios != NULL && console_fifos != NULL && reset_tty != NULL) {
        ret = start_prepare_console(args, oldtios, reset_tty, console_fifos);
        if (ret != 0) {
            goto out;
        }
    }

    ret = do_client_start(args, console_fifos);
    if (ret != 0) {
        goto out;
    }

out:
    return ret;
}

void client_wait_fifo_exit(const struct client_arguments *args)
{
    if (args->custom_conf.attach_stdin || args->custom_conf.attach_stdout || args->custom_conf.attach_stderr) {
        sem_wait(&g_console_waitexit_sem);
    }
}

void client_restore_console(bool reset_tty, const struct termios *oldtios, struct command_fifo_config *console_fifos)
{
    if (reset_tty && tcsetattr(0, TCSAFLUSH, oldtios) < 0) {
        WARN("Failed to reset terminal properties: %s.", strerror(errno));
    }
    free_command_fifo_config(console_fifos);
    sem_destroy(&g_console_waitopen_sem);
    sem_destroy(&g_console_waitexit_sem);
}

int cmd_start_main(int argc, const char **argv)
{
    int ret = 0;
    int i = 0;
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf), COMMON_OPTIONS(g_cmd_start_args) };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_start_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_start_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_start_desc,
                 g_cmd_start_usage);
    if (command_parse_args(&cmd, &g_cmd_start_args.argc, &g_cmd_start_args.argv)) {
        exit(EINVALIDARGS);
    }

    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Start: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_start_args.argc == 0) {
        COMMAND_ERROR("\"start\" requires at least 1 argument");
        exit(EINVALIDARGS);
    }

    if (g_cmd_start_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many containers to start.");
        exit(EINVALIDARGS);
    }

    for (i = 0; i < g_cmd_start_args.argc; i++) {
        g_cmd_start_args.name = g_cmd_start_args.argv[i];
        if (client_start(&g_cmd_start_args, NULL, NULL, NULL)) {
            ERROR("Container \"%s\" start failed", g_cmd_start_args.name);
            ret = ECOMMON;
            continue;
        }
        if (g_cmd_start_args.detach) {
            printf("Container \"%s\" started\n", g_cmd_start_args.name);
        }
    }

    return ret;
}
