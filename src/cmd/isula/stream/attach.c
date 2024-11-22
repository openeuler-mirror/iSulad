/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2017-11-22
 * Description: provide container attach functions
 ******************************************************************************/
#include "attach.h"
#include <semaphore.h>
#include <unistd.h>
#include <pthread.h>
#include <termios.h> // IWYU pragma: keep
#include <errno.h>
#include <isula_libutils/container_inspect.h>
#include <isula_libutils/json_common.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <time.h>

#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "console.h"
#include "utils.h"
#include "command_parser.h"
#include "connect.h"
#include "constants.h"
#include "client_helpers.h"
#ifndef GRPC_CONNECTOR
#include "client_console.h"
#endif

const char g_cmd_attach_desc[] = "Attach to a running container";
const char g_cmd_attach_usage[] = "attach [OPTIONS] CONTAINER";

#ifndef GRPC_CONNECTOR
sem_t g_attach_waitopen_sem;
sem_t g_attach_waitexit_sem;
#endif

struct client_arguments g_cmd_attach_args = {
    .time = INSPECT_TIMEOUT_SEC,
};


static int check_tty(bool tty, struct termios *oldtios, bool *reset_tty)
{
    int istty = 0;

    if (!tty) {
        return 0;
    }

    istty = isatty(0);
    if (istty) {
        if (setup_tios(0, oldtios)) {
            ERROR("Failed to setup terminal properties");
            return -1;
        }
        *reset_tty = true;
    } else {
        INFO("the input device is not a TTY");
        return 0;
    }

    return 0;
}

#ifndef GRPC_CONNECTOR
static int attach_prepare_console(bool tty, struct isula_attach_request *request,
                                  struct command_fifo_config **attach_fifos)
{
    if (create_console_fifos(request->attach_stdin, request->attach_stdout, request->attach_stderr,
                             request->name, "attach", attach_fifos)) {
        ERROR("Container \"%s\" create console FIFO failed", request->name);
        return -1;
    }

    (*attach_fifos)->wait_open = &g_attach_waitopen_sem;
    (*attach_fifos)->wait_exit = &g_attach_waitexit_sem;
    if (start_client_console_thread((*attach_fifos), tty && (isatty(0) != 0))) {
        ERROR("Container \"%s\" start console thread failed", request->name);
        return -1;
    }

    return 0;
}
#endif

static int inspect_container_and_check_state(const struct client_arguments *args,
                                             container_inspect **container_inspect_data)
{
    int ret = 0;
    container_inspect *inspect_data = NULL;

    if (args->name == NULL || container_inspect_data == NULL) {
        ERROR("input name or inspect_data is null");
        ret = -1;
        goto out;
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

    if (inspect_data->state != NULL && inspect_data->state->paused) {
        COMMAND_ERROR("You cannot attach to a paused container, unpause it first");
        ret = -1;
        goto out;
    }

    if (inspect_data->state != NULL && inspect_data->state->restarting) {
        COMMAND_ERROR("You cannot attach to a restarting container, wait until it is running");
        ret = -1;
        goto out;
    }
    *container_inspect_data = inspect_data;

out:
    return ret;
}

static int attach_cmd_init(int argc, const char **argv)
{
    command_t cmd;
    struct isula_libutils_log_config lconf = { 0 };

    if (client_arguments_init(&g_cmd_attach_args)) {
        COMMAND_ERROR("client arguments init failed\n");
        exit(ECOMMON);
    }
    g_cmd_attach_args.progname = argv[0];
    struct command_option options[] = {
        LOG_OPTIONS(lconf)
        COMMON_OPTIONS(g_cmd_attach_args)
    };

    isula_libutils_default_log_config(argv[0], &lconf);
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_attach_desc,
                 g_cmd_attach_usage);
    if (command_parse_args(&cmd, &g_cmd_attach_args.argc, &g_cmd_attach_args.argv)) {
        return EINVALIDARGS;
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        return ECOMMON;
    }

    if (g_cmd_attach_args.argc != 1) {
        COMMAND_ERROR("\"%s attach\" requires exactly 1 argument(s).", g_cmd_attach_args.progname);
        return ECOMMON;
    }
    g_cmd_attach_args.name = util_strdup_s(g_cmd_attach_args.argv[0]);

#ifndef GRPC_CONNECTOR
    if (sem_init(&g_attach_waitopen_sem, 0, 0)) {
        ERROR("Semaphore initialization failed");
        return ECOMMON;
    }

    if (sem_init(&g_attach_waitexit_sem, 0, 0)) {
        ERROR("Semaphore initialization failed");
        sem_destroy(&g_attach_waitopen_sem);
        return ECOMMON;
    }
#endif

    return 0;
}

struct wait_thread_arg {
    struct client_arguments *client_args;
    client_connect_config_t *config;
    uint32_t *exit_code;
    sem_t *sem_started;
    sem_t *sem_exited;
};

static void *container_wait_thread_main(void *thread_arg)
{
    int ret = -1;
    isula_connect_ops *ops = NULL;
    struct isula_wait_request request = { 0 };
    struct isula_wait_response *response = NULL;
    struct wait_thread_arg *arg = (struct wait_thread_arg *)thread_arg;
    client_connect_config_t config = { 0 };

    request.id = arg->client_args->name;
    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        CRIT("Set thread detach fail");
        goto cleanup;
    }
    prctl(PR_SET_NAME, "AttachWaitThread");

    response = util_common_calloc_s(sizeof(struct isula_wait_response));
    if (response == NULL) {
        ERROR("Wait: Out of memory");
        goto cleanup;
    }

    request.condition = WAIT_CONDITION_STOPPED;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.wait) {
        ERROR("Unimplemented wait op");
        goto cleanup;
    }

    config = get_connect_config(arg->client_args);
    (void)sem_post(arg->sem_started);
    arg->sem_started = NULL;
    ret = ops->container.wait(&request, response, &config);
    if (ret != 0) {
        ERROR("Wait failed");
        goto cleanup;
    }

    *arg->exit_code = (uint32_t)response->exit_code;

cleanup:
    if (arg->sem_started != NULL) {
        (void)sem_post(arg->sem_started);
    }
    if (ret == 0) {
        (void)sem_post(arg->sem_exited);
    }
    isula_wait_response_free(response);
    free(arg);
    return NULL;
}

static int container_wait_thread(struct client_arguments *args, uint32_t *exit_code, sem_t *sem_exited)
{
    int ret = 0;
    pthread_t tid;
    struct wait_thread_arg *arg = NULL;
    sem_t sem_started;

    arg = util_common_calloc_s(sizeof(struct wait_thread_arg));
    if (arg == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    if (sem_init(&sem_started, 0, 0) != 0) {
        COMMAND_ERROR("Can not init sem");
        free(arg);
        return -1;
    }
    arg->client_args = args;
    arg->exit_code = exit_code;
    arg->sem_started = &sem_started;
    arg->sem_exited = sem_exited;
    ret = pthread_create(&tid, NULL, container_wait_thread_main, arg);
    if (ret != 0) {
        free(arg);
        (void)sem_destroy(&sem_started);
        return -1;
    }
    while(sem_wait(&sem_started) == -1 && errno == EINTR) {
        continue;
    }
    (void)sem_destroy(&sem_started);
    return 0;
}

static int client_attach(struct client_arguments *args, uint32_t *exit_code)
{
    isula_connect_ops *ops = NULL;
    struct isula_attach_request request = { 0 };
    struct isula_attach_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;
    struct termios oldtios = { 0 };
    bool reset_tty = false;
    container_inspect *inspect_data = NULL;
    sem_t sem_exited;
    struct timespec ts;
#ifndef GRPC_CONNECTOR
    struct command_fifo_config *attach_fifos = NULL;
#endif

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.attach) {
        COMMAND_ERROR("Unimplemented attach operation");
        ret = ECOMMON;
        goto out;
    }

    if (inspect_container_and_check_state(args, &inspect_data)) {
        ERROR("Failed to get inspect info!");
        ret = ECOMMON;
        goto out;
    }

    if (sem_init(&sem_exited, 0, 0) != 0) {
        COMMAND_ERROR("Can not init sem");
        ret = ECOMMON;
        goto out;
    }

    response = util_common_calloc_s(sizeof(struct isula_attach_response));
    if (response == NULL) {
        ERROR("Attach: Out of memory");
        ret = ECOMMON;
        goto out;
    }

    free(args->name);
    args->name = util_strdup_s(inspect_data->id);

    request.name = args->name;
    request.attach_stdin = true;
    request.attach_stdout = true;
    request.attach_stderr = true;

    if (check_tty(inspect_data->config->tty, &oldtios, &reset_tty) != 0) {
        ret = ECOMMON;
        goto out;
    }

#ifndef GRPC_CONNECTOR
    if (attach_prepare_console(inspect_data->config->tty, &request, &attach_fifos) != 0) {
        ret = ECOMMON;
        goto out;
    }
    request.stdin = util_strdup_s(attach_fifos->stdin_name);
    request.stdout = util_strdup_s(attach_fifos->stdout_name);
    request.stderr = util_strdup_s(attach_fifos->stderr_name);
#endif

    config = get_connect_config(args);
    container_wait_thread(args, exit_code, &sem_exited);
    ret = ops->container.attach(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = ECOMMON;
        goto out;
    }

#ifndef GRPC_CONNECTOR
    while(sem_wait(&g_attach_waitexit_sem) == -1 && errno == EINTR) {
        continue;
    }
#endif

    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        ERROR("Failed to get real time");
        ret = ECOMMON;
        goto out;
    }
    ts.tv_sec++;

    if (sem_timedwait(&sem_exited, &ts) != 0) {
        if (errno == ETIMEDOUT) {
            COMMAND_ERROR("Wait container status timeout.");
        } else {
            CMD_SYSERROR("Failed to wait sem");
        }
        ret = ECOMMON;
        goto out;
    }
out:
#ifndef GRPC_CONNECTOR
    delete_command_fifo(attach_fifos);
    sem_destroy(&g_attach_waitopen_sem);
    sem_destroy(&g_attach_waitexit_sem);
#endif
    (void)sem_destroy(&sem_exited);
    free_container_inspect(inspect_data);
    isula_attach_response_free(response);
    if (reset_tty) {
        if (tcsetattr(0, TCSAFLUSH, &oldtios) < 0) {
            ERROR("Failed to reset terminal properties");
            return -1;
        }
    }
    return ret;
}

int cmd_attach_main(int argc, const char **argv)
{
    int ret = 0;
    unsigned int exit_code = 0;

    ret = attach_cmd_init(argc, argv);
    if (ret != 0) {
        goto out;
    }

    ret = client_attach(&g_cmd_attach_args, &exit_code);
    if (ret != 0) {
        ERROR("Failed to execute command attach");
        goto out;
    }

out:
    exit((exit_code != 0) ? (int)exit_code : ret);
}
