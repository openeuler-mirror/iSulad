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
#include <semaphore.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>

#include "client_arguments.h"
#include "exec.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "console.h"
#include "utils.h"
#include "attach.h"
#include "isula_commands.h"

const char g_cmd_attach_desc[] = "Attach to a running container";
const char g_cmd_attach_usage[] = "attach [OPTIONS] CONTAINER";

struct client_arguments g_cmd_attach_args = { 0 };

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

int inspect_container(const struct client_arguments *args, container_inspect **inspect_data)
{
    int ret = 0;
    struct isula_inspect_request inspect_request = { 0 };
    struct isula_inspect_response *inspect_response = NULL;
    client_connect_config_t config = { 0 };
    isula_connect_ops *ops = NULL;
    parser_error perr = NULL;

    inspect_response = util_common_calloc_s(sizeof(struct isula_inspect_response));
    if (inspect_response == NULL) {
        COMMAND_ERROR("Out of memory");
        return -1;
    }

    inspect_request.name = args->name;
    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.inspect) {
        COMMAND_ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.inspect(&inspect_request, inspect_response, &config);
    if (ret) {
        client_print_error(inspect_response->cc, inspect_response->server_errono, inspect_response->errmsg);
        goto out;
    }

    /* parse oci container json */
    if (inspect_response == NULL || inspect_response->json == NULL) {
        COMMAND_ERROR("Inspect data is empty");
        ret = -1;
        goto out;
    }

    *inspect_data = container_inspect_parse_data(inspect_response->json, NULL, &perr);
    if (*inspect_data == NULL) {
        COMMAND_ERROR("Can not parse inspect json: %s", perr);
        ret = -1;
        goto out;
    }

out:
    isula_inspect_response_free(inspect_response);
    free(perr);
    return ret;
}
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
    struct command_option options[] = { LOG_OPTIONS(lconf), COMMON_OPTIONS(g_cmd_attach_args) };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_attach_desc,
                 g_cmd_attach_usage);
    if (command_parse_args(&cmd, &g_cmd_attach_args.argc, &g_cmd_attach_args.argv)) {
        return EINVALIDARGS;
    }
    isula_libutils_default_log_config(argv[0], &lconf);
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        return ECOMMON;
    }

    if (g_cmd_attach_args.argc != 1) {
        COMMAND_ERROR("\"%s attach\" requires exactly 1 argument(s).", g_cmd_attach_args.progname);
        return ECOMMON;
    }
    g_cmd_attach_args.name = util_strdup_s(g_cmd_attach_args.argv[0]);

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
    (void)sem_wait(&sem_started);
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

    config = get_connect_config(args);
    container_wait_thread(args, exit_code, &sem_exited);
    ret = ops->container.attach(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = ECOMMON;
        goto out;
    }

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
            COMMAND_ERROR("Failed to wait sem: %s", strerror(errno));
        }
        ret = ECOMMON;
        goto out;
    }
out:
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
