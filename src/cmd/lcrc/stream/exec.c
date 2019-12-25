/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide container exec functions
 ******************************************************************************/
#include <semaphore.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>

#include "securec.h"
#include "arguments.h"
#include "exec.h"
#include "log.h"
#include "lcrc_connect.h"
#include "console.h"
#include "utils.h"
#include "commands.h"
#include "container_inspect.h"

const char g_cmd_exec_desc[] = "Run a command in a running container";
const char g_cmd_exec_usage[] = "exec [OPTIONS] CONTAINER COMMAND [ARG...]";

sem_t g_command_waitopen_sem;
sem_t g_command_waitexit_sem;

struct client_arguments g_cmd_exec_args = {};

static int client_exec(const struct client_arguments *args, const struct command_fifo_config *fifos,
                       uint32_t *exit_code)
{
    lcrc_connect_ops *ops = NULL;
    struct lcrc_exec_request request = { 0 };
    struct lcrc_exec_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct lcrc_exec_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return ECOMMON;
    }

    request.name = args->name;
    request.tty = args->custom_conf.tty;
    request.open_stdin = args->custom_conf.open_stdin;
    request.attach_stdin = args->custom_conf.attach_stdin;
    request.attach_stdout = args->custom_conf.attach_stdout;
    request.attach_stderr = args->custom_conf.attach_stderr;
    if (fifos != NULL) {
        request.stdin = fifos->stdin_name;
        request.stdout = fifos->stdout_name;
        request.stderr = fifos->stderr_name;
    }

    request.user = args->custom_conf.user;
    request.argc = args->argc;
    request.argv = (char **)args->argv;

    /* environment variables */
    request.env_len = util_array_len((const char **)(args->extra_env));
    request.env = args->extra_env;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.exec) {
        ERROR("Unimplemented ops");
        ret = ECOMMON;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.exec(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = ECOMMON;
        goto out;
    }
out:
    if (response->exit_code) {
        *exit_code = response->exit_code;
    }

    lcrc_exec_response_free(response);
    return ret;
}

static int exec_cmd_init(int argc, const char **argv)
{
    command_t cmd;
    struct log_config lconf = { 0 };

    struct command_option options[] = {
        LOG_OPTIONS(lconf),
        COMMON_OPTIONS(g_cmd_exec_args),
        EXEC_OPTIONS(g_cmd_exec_args)
    };

    set_default_command_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_exec_args)) {
        COMMAND_ERROR("client arguments init failed\n");
        exit(ECOMMON);
    }
    g_cmd_exec_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_exec_desc,
                 g_cmd_exec_usage);

    if (command_parse_args(&cmd, &g_cmd_exec_args.argc, &g_cmd_exec_args.argv)) {
        return EINVALIDARGS;
    }
    if (log_init(&lconf)) {
        COMMAND_ERROR("Exec: log init failed");
        return ECOMMON;
    }

    if (g_cmd_exec_args.argc < 1) {
        COMMAND_ERROR("Exec needs a container name");
        return ECOMMON;
    } else {
        g_cmd_exec_args.name = g_cmd_exec_args.argv[0];
        g_cmd_exec_args.argc--;
        g_cmd_exec_args.argv++;
    }

    if (sem_init(&g_command_waitopen_sem, 0, 0)) {
        ERROR("Semaphore initialization failed");
        return ECOMMON;
    }

    if (sem_init(&g_command_waitexit_sem, 0, 0)) {
        ERROR("Semaphore initialization failed");
        sem_destroy(&g_command_waitopen_sem);
        return ECOMMON;
    }

    return 0;
}

static int exec_prepare_console(struct command_fifo_config **command_fifos, bool *reset_tty, struct termios *oldtios,
                                struct custom_configs *custom_cfg)
{
    int ret = 0;
    int istty = 0;
    container_inspect *inspect_data = NULL;

    if (inspect_container(&g_cmd_exec_args, &inspect_data)) {
        ERROR("inspect data error");
        ret = ECOMMON;
        goto out;
    }

    if (inspect_data->id != NULL) {
        g_cmd_exec_args.name = util_strdup_s(inspect_data->id);
    }

    istty = isatty(0);
    if (istty && custom_cfg->tty && custom_cfg->attach_stdin) {
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

    if (custom_cfg->attach_stdin || custom_cfg->attach_stdout || custom_cfg->attach_stderr) {
        if (create_console_fifos(custom_cfg->attach_stdin, custom_cfg->attach_stdout, custom_cfg->attach_stderr,
                                 g_cmd_exec_args.name, "exec", command_fifos)) {
            ERROR("Container \"%s\" create console FIFO failed", g_cmd_exec_args.name);
            ret = ECOMMON;
            goto out;
        }

        (*command_fifos)->wait_open = &g_command_waitopen_sem;
        (*command_fifos)->wait_exit = &g_command_waitexit_sem;
        if (start_client_console_thread((*command_fifos), custom_cfg->tty && (istty != 0))) {
            ERROR("Container \"%s\" start console thread failed", g_cmd_exec_args.name);
            ret = ECOMMON;
            goto out;
        }
    }

out:
    free_container_inspect(inspect_data);
    return ret;
}

static int remote_cmd_exec_setup_tty(const struct client_arguments *args, bool *reset_tty,
                                     struct termios *oldtios)
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
    if (!istty) {
        INFO("The input device is not a TTY");
    }
    return 0;
}

static int remote_cmd_exec(const struct client_arguments *args, uint32_t *exit_code)
{
    int ret = 0;
    lcrc_connect_ops *ops = NULL;
    struct lcrc_exec_request request = { 0 };
    struct lcrc_exec_response *response = NULL;
    client_connect_config_t config = { 0 };
    struct termios oldtios;
    bool reset_tty = false;
    container_inspect *inspect_data = NULL;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.remote_exec) {
        ERROR("Unimplemented ops");
        return ECOMMON;
    }

    response = util_common_calloc_s(sizeof(struct lcrc_exec_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return ECOMMON;
    }

    if (inspect_container(args, &inspect_data)) {
        ERROR("inspect data error");
        ret = ECOMMON;
        goto out;
    }

    g_cmd_exec_args.name = util_strdup_s(inspect_data->id);

    request.name = args->name;
    request.tty = args->custom_conf.tty;
    request.open_stdin = args->custom_conf.open_stdin;
    request.attach_stdin = args->custom_conf.attach_stdin;
    request.attach_stdout = args->custom_conf.attach_stdout;
    request.attach_stderr = args->custom_conf.attach_stderr;

    request.argc = args->argc;
    request.argv = (char **)args->argv;

    /* environment variables */
    request.env_len = util_array_len((const char **)(args->extra_env));
    request.env = args->extra_env;

    if (remote_cmd_exec_setup_tty(args, &reset_tty, &oldtios) < 0) {
        ret = ECOMMON;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.remote_exec(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = ECOMMON;
        goto out;
    }

out:
    free_container_inspect(inspect_data);
    if (reset_tty && tcsetattr(0, TCSAFLUSH, &oldtios) < 0) {
        WARN("Failed to reset terminal properties: %s.", strerror(errno));
    }
    if (response->exit_code != 0) {
        *exit_code = response->exit_code;
    }
    lcrc_exec_response_free(response);
    return ret;
}

static int local_cmd_exec(struct client_arguments *args, uint32_t *exit_code)
{
    bool reset_tty = false;
    int ret = 0;
    struct termios oldtios = { 0 };
    struct command_fifo_config *command_fifos = NULL;

    ret = exec_prepare_console(&command_fifos, &reset_tty, &oldtios, &args->custom_conf);
    if (ret) {
        goto out;
    }

    ret = client_exec(args, command_fifos, exit_code);
    if (!ret &&
        (args->custom_conf.attach_stdin || args->custom_conf.attach_stdout || args->custom_conf.attach_stderr)) {
        sem_wait(&g_command_waitexit_sem);
    }
out:
    delete_command_fifo(command_fifos);
    sem_destroy(&g_command_waitopen_sem);
    sem_destroy(&g_command_waitexit_sem);
    if (reset_tty && tcsetattr(0, TCSAFLUSH, &oldtios) < 0) {
        WARN("Failed to reset terminal properties: %s.", strerror(errno));
    }
    return ret;
}

int cmd_exec_main(int argc, const char **argv)
{
    int ret = 0;
    uint32_t exit_code = 0;
    struct custom_configs *custom_cfg = NULL;

    ret = exec_cmd_init(argc, argv);
    if (ret) {
        goto out;
    }

    custom_cfg = &g_cmd_exec_args.custom_conf;

    custom_cfg->tty = true;
    custom_cfg->open_stdin = true;
    custom_cfg->attach_stdout = true;
    custom_cfg->attach_stderr = false;
    custom_cfg->attach_stdin = custom_cfg->open_stdin;

    if (g_cmd_exec_args.detach) {
        custom_cfg->attach_stdin = false;
        custom_cfg->attach_stdout = false;
        custom_cfg->attach_stderr = false;
        custom_cfg->open_stdin = false;
    }

    if (strncmp(g_cmd_exec_args.socket, "tcp://", strlen("tcp://")) == 0) {
        ret = remote_cmd_exec(&g_cmd_exec_args, &exit_code);
        if (ret != 0) {
            ERROR("Failed to execute command with remote exec");
            goto out;
        }
    } else {
        ret = local_cmd_exec(&g_cmd_exec_args, &exit_code);
        if (ret != 0) {
            ERROR("Failed to execute command with local exec");
            goto out;
        }
    }

out:
    exit(exit_code ? (int)exit_code : ret);
}

