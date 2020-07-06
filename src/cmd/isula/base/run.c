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
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>
#include <termios.h> // IWYU pragma: keep
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "run.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "isula_connect.h"
#include "console.h"
#include "error.h"
#include "connect.h"
#include "create.h"
#include "libisula.h"
#include "start.h"
#include "wait.h"

const char g_cmd_run_desc[] = "Run a command in a new container";
const char g_cmd_run_usage[] = "run [OPTIONS] ROOTFS|IMAGE [COMMAND] [ARG...]";
static int run_checker(struct client_arguments *args);
struct client_arguments g_cmd_run_args = {
    .runtime = "",
    .restart = "no",
};

static int local_cmd_start(struct client_arguments *args, uint32_t *exit_code)
{
    int ret = 0;
    bool reset_tty = false;
    struct termios oldtios;
    struct command_fifo_config *console_fifos = NULL;

    ret = client_start(&g_cmd_run_args, &reset_tty, &oldtios, &console_fifos);
    if (ret != 0) {
        goto free_out;
    }

    if (!g_cmd_run_args.detach) {
        ret = client_wait(&g_cmd_run_args, exit_code);
        if (ret != 0) {
            goto free_out;
        }
        ret = (int)(*exit_code);
    }

    client_wait_fifo_exit(&g_cmd_run_args);
free_out:
    client_restore_console(reset_tty, &oldtios, console_fifos);
    return ret;
}

static int remote_cmd_start_set_tty(const struct client_arguments *args, bool *reset_tty, struct termios *oldtios)
{
    int istty = 0;

    istty = isatty(0);
    if (istty && args->custom_conf.tty && args->custom_conf.attach_stdin) {
        if (setup_tios(0, oldtios)) {
            ERROR("Failed to setup terminal properties");
            return -1;
        }
        *reset_tty = true;
    }
    return 0;
}

static int remote_cmd_start(const struct client_arguments *args, uint32_t *exit_code)
{
    int ret = 0;
    bool reset_tty = false;
    isula_connect_ops *ops = NULL;
    struct isula_start_request request = { 0 };
    struct isula_start_response *response = NULL;
    client_connect_config_t config = { 0 };
    struct termios oldtios;

    ops = get_connect_client_ops();
    if (ops == NULL || ops->container.remote_start == NULL) {
        ERROR("Unimplemented ops");
        ret = ECOMMON;
        goto out;
    }

    if (remote_cmd_start_set_tty(args, &reset_tty, &oldtios) != 0) {
        ret = ECOMMON;
        goto out;
    }

    request.name = args->name;
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
    ret = ops->container.remote_start(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = ECOMMON;
        if (response->server_errono ||
            (response->errmsg && !strcmp(response->errmsg, errno_to_error_message(ISULAD_ERR_CONNECT)))) {
            ret = ESERVERERROR;
        }
        goto out;
    }

out:
    isula_start_response_free(response);
    if (reset_tty && tcsetattr(0, TCSAFLUSH, &oldtios) < 0) {
        ERROR("Failed to reset terminal properties");
        return -1;
    }
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

static void *run_console_resize_thread(void *arg)
{
    int ret = 0;
    const struct client_arguments *args = arg;
    static struct winsize s_pre_wsz;
    struct winsize wsz;

    if (!isatty(STDIN_FILENO)) {
        goto out;
    }

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        CRIT("Start: set thread detach fail");
        goto out;
    }

    while (true) {
        sleep(1); // check the windows size per 1s
        ret = ioctl(STDIN_FILENO, TIOCGWINSZ, &wsz);
        if (ret < 0) {
            WARN("Failed to get window size");
            continue;
        }
        if (wsz.ws_row == s_pre_wsz.ws_row && wsz.ws_col == s_pre_wsz.ws_col) {
            continue;
        }
        ret = do_resize_run_console(args, wsz.ws_row, wsz.ws_col);
        if (ret != 0) {
            continue;
        }
        s_pre_wsz.ws_row = wsz.ws_row;
        s_pre_wsz.ws_col = wsz.ws_col;
    }

out:
    return NULL;
}

int run_client_console_resize_thread(struct client_arguments *args)
{
    int res = 0;
    pthread_t a_thread;

    res = pthread_create(&a_thread, NULL, run_console_resize_thread, (void *)(args));
    if (res != 0) {
        CRIT("Thread creation failed");
        return -1;
    }

    return 0;
}

int cmd_run_main(int argc, const char **argv)
{
    int ret = 0;
    unsigned int exit_code = 0;
    command_t cmd = { 0 };
    struct isula_libutils_log_config lconf = { 0 };

    if (client_arguments_init(&g_cmd_run_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_run_args.custom_conf.attach_stdout = true;
    g_cmd_run_args.custom_conf.attach_stderr = true;

    g_cmd_run_args.progname = argv[0];
    g_cmd_run_args.subcommand = argv[1];
    struct command_option options[] = { LOG_OPTIONS(lconf), COMMON_OPTIONS(g_cmd_run_args),
               CREATE_OPTIONS(g_cmd_run_args), CREATE_EXTEND_OPTIONS(g_cmd_run_args),
               RUN_OPTIONS(g_cmd_run_args)
    };
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_run_desc,
                 g_cmd_run_usage);
    if (command_parse_args(&cmd, &g_cmd_run_args.argc, &g_cmd_run_args.argv) || run_checker(&g_cmd_run_args)) {
        exit(EINVALIDARGS);
    }

    isula_libutils_default_log_config(argv[0], &lconf);
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
        (void)run_client_console_resize_thread(&g_cmd_run_args);
    }

    if (strncmp(g_cmd_run_args.socket, "tcp://", strlen("tcp://")) == 0) {
        ret = remote_cmd_start(&g_cmd_run_args, &exit_code);
        if (ret != 0) {
            ERROR("Failed to execute command with remote run");
            goto free_out;
        }
    } else {
        ret = local_cmd_start(&g_cmd_run_args, &exit_code);
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
