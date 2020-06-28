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
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container list callback function definition
 ********************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <lcr/lcrcontainer.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <malloc.h>

#include "constants.h"
#include "isula_libutils/log.h"
#include "io_wrapper.h"
#include "isulad_config.h"
#include "config.h"
#include "image.h"
#include "execution.h"
#include "verify.h"
#include "isula_libutils/container_inspect.h"
#include "containers_store.h"
#include "execution_extend.h"
#include "execution_information.h"
#include "execution_stream.h"
#include "execution_create.h"
#include "io_handler.h"
#include "plugin.h"
#include "execution_network.h"
#include "runtime.h"
#include "specs_extend.h"
#include "utils.h"
#include "error.h"
#include "event_sender.h"
#include "specs.h"
#include "container_operator.h"

static int filter_by_label(const container_t *cont, const container_get_id_request *request)
{
    int ret = 0;
    size_t i, len_key, len_val;
    char *p_equal = NULL;
    json_map_string_string *labels = NULL;

    if (request->label == NULL) {
        ret = 0;
        goto out;
    }

    if (cont->common_config->config == NULL || cont->common_config->config->labels == NULL ||
        cont->common_config->config->labels->len == 0) {
        ERROR("No such container: %s", request->id_or_name);
        isulad_set_error_message("No such container: %s", request->id_or_name);
        ret = -1;
        goto out;
    }
    p_equal = strchr(request->label, '=');
    if (p_equal == NULL) {
        ERROR("Invalid label: %s", request->label);
        isulad_set_error_message("Invalid label: %s", request->label);
        ret = -1;
        goto out;
    }
    len_key = (size_t)(p_equal - request->label);
    len_val = (strlen(request->label) - len_key) - 1;
    labels = cont->common_config->config->labels;
    for (i = 0; i < labels->len; i++) {
        if (strlen(labels->keys[i]) == len_key && strncmp(labels->keys[i], request->label, len_key) == 0 &&
            strlen(labels->values[i]) == len_val && strncmp(labels->values[i], p_equal + 1, len_val) == 0) {
            ret = 0;
            goto out;
        }
    }
    ret = -1;
    ERROR("No such container: %s", request->id_or_name);
    isulad_set_error_message("No such container: %s", request->id_or_name);

out:
    return ret;
}

static void pack_get_id_response(container_get_id_response *response, const char *id, uint32_t cc)
{
    if (response == NULL) {
        return;
    }

    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static void pack_get_runtime_response(container_get_runtime_response *response, const char *runtime, uint32_t cc)
{
    if (response == NULL) {
        return;
    }

    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (runtime != NULL) {
        response->runtime = util_strdup_s(runtime);
    }
}

/*
 * This function gets long id of container by name or short id
 */
static int container_get_id_cb(const container_get_id_request *request, container_get_id_response **response)
{
    char *id = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_get_id_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(request->id_or_name)) {
        ERROR("Invalid container name: %s", request->id_or_name ? request->id_or_name : "");
        isulad_set_error_message("Invalid container name: %s", request->id_or_name ? request->id_or_name : "");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(request->id_or_name);
    if (cont == NULL) {
        cc = ISULAD_ERR_EXEC;
        ERROR("No such container: %s", request->id_or_name);
        isulad_set_error_message("No such container: %s", request->id_or_name);
        goto pack_response;
    }

    if (filter_by_label(cont, request) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    id = cont->common_config->id;

pack_response:
    pack_get_id_response(*response, id, cc);

    container_unref(cont);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int container_get_runtime_cb(const char *real_id, container_get_runtime_response **response)
{
    char *runtime = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (real_id == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_get_runtime_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(real_id)) {
        ERROR("Invalid container name: %s", real_id);
        isulad_set_error_message("Invalid container name: %s", real_id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(real_id);
    if (cont == NULL) {
        cc = ISULAD_ERR_EXEC;
        ERROR("No such container: %s", real_id);
        isulad_set_error_message("No such container: %s", real_id);
        goto pack_response;
    }

    runtime = cont->runtime;

pack_response:
    pack_get_runtime_response(*response, runtime, cc);

    container_unref(cont);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int start_request_check(const container_start_request *h)
{
    int ret = 0;

    if (h == NULL || h->id == NULL) {
        ERROR("recive NULL Request id");
        ret = -1;
        goto out;
    }

    if (!util_valid_container_id_or_name(h->id)) {
        ERROR("Invalid container name %s", h->id);
        isulad_set_error_message("Invalid container name %s", h->id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int prepare_start_io(container_t *cont, const container_start_request *request, char **fifopath, char *fifos[],
                            int stdinfd, struct io_write_wrapper *stdout_handler,
                            struct io_write_wrapper *stderr_handler)
{
    int ret = 0;
    char *id = NULL;
    pthread_t tid = 0;

    id = cont->common_config->id;

    if (request->attach_stdin || request->attach_stdout || request->attach_stderr) {
        if (create_daemon_fifos(id, cont->runtime, request->attach_stdin, request->attach_stdout,
                                request->attach_stderr, "start", fifos, fifopath)) {
            ret = -1;
            goto out;
        }

        if (ready_copy_io_data(-1, true, request->stdin, request->stdout, request->stderr, stdinfd, stdout_handler,
                               stderr_handler, (const char **)fifos, &tid)) {
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static void pack_start_response(container_start_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }

    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static int container_start_prepare(container_t *cont, const container_start_request *request, int stdinfd,
                                   struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler,
                                   char **fifopath, char *fifos[])
{
    const char *id = cont->common_config->id;

    if (container_to_disk_locking(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        isulad_set_error_message("Failed to save container \"%s\" to disk", id);
        return -1;
    }

    if (prepare_start_io(cont, request, fifopath, fifos, stdinfd, stdout_handler, stderr_handler) != 0) {
        return -1;
    }

    return 0;
}

static int container_start_cb(const container_start_request *request, container_start_response **response, int stdinfd,
                              struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler)
{
    uint32_t cc = ISULAD_SUCCESS;
    char *id = NULL;
    char *fifos[3] = { NULL, NULL, NULL };
    char *fifopath = NULL;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_start_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    if (start_request_check(request)) {
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    cont = containers_store_get(request->id);
    if (cont == NULL) {
        cc = ISULAD_ERR_EXEC;
        ERROR("No such container:%s", request->id);
        isulad_set_error_message("No such container:%s", request->id);
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: Starting}", id);

    state_set_starting(cont->state);

    if (is_running(cont->state)) {
        INFO("Container is already running");
        goto pack_response;
    }

    if (container_start_prepare(cont, request, stdinfd, stdout_handler, stderr_handler, &fifopath, fifos) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (start_container(cont, (const char **)fifos, true) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Running}", id);
    (void)isulad_monitor_send_container_event(id, START, -1, 0, NULL, NULL);

pack_response:
    delete_daemon_fifos(fifopath, (const char **)fifos);
    free(fifos[0]);
    free(fifos[1]);
    free(fifos[2]);
    free(fifopath);
    pack_start_response(*response, cc, id);
    if (cont != NULL) {
        state_reset_starting(cont->state);
        container_unref(cont);
    }
    isula_libutils_free_log_prefix();
    malloc_trim(0);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int restart_container(container_t *cont)
{
    int ret = 0;
    char timebuffer[512] = { 0 };
    const char *id = cont->common_config->id;
    const char *runtime = cont->runtime;
    const char *rootpath = cont->root_path;
    rt_restart_params_t params = { 0 };

    container_lock(cont);

    if (is_removal_in_progress(cont->state) || is_dead(cont->state)) {
        ERROR("Container is marked for removal and cannot be started.");
        isulad_set_error_message("Container is marked for removal and cannot be started.");
        goto out;
    }

    (void)get_now_time_buffer(timebuffer, sizeof(timebuffer));

    params.rootpath = rootpath;

    ret = runtime_restart(id, runtime, &params);
    if (ret == -2) {
        goto out;
    }

    if (ret == 0) {
        update_start_and_finish_time(cont->state, timebuffer);
    }

    if (container_to_disk(cont)) {
        ERROR("Failed to save container \"%s\" to disk", cont->common_config->id);
        ret = -1;
        goto out;
    }
out:
    container_unlock(cont);
    return ret;
}

static uint32_t stop_and_start(container_t *cont, int timeout)
{
    int ret = 0;
    uint32_t cc = ISULAD_SUCCESS;
    const char *console_fifos[3] = { NULL, NULL, NULL };
    const char *id = cont->common_config->id;

    ret = stop_container(cont, timeout, false, true);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
        goto out;
    }

    /* begin start container */
    state_set_starting(cont->state);
    if (container_to_disk_locking(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        cc = ISULAD_ERR_EXEC;
        isulad_set_error_message("Failed to save container \"%s\" to disk", id);
        goto out;
    }

    if (is_running(cont->state)) {
        INFO("Container is already running");
        goto out;
    }

    if (start_container(cont, console_fifos, true) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }
out:
    state_reset_starting(cont->state);
    return cc;
}

static void pack_restart_response(container_restart_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static uint32_t do_restart_container(container_t *cont, int timeout)
{
    int ret = 0;

    ret = restart_container(cont);
    if (ret == -1) {
        container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
        return ISULAD_ERR_EXEC;
    } else if (ret == RUNTIME_NOT_IMPLEMENT_RESET) {
        /* runtime don't implement restart, use stop and start */
        return stop_and_start(cont, timeout);
    }

    return ISULAD_SUCCESS;
}

static int container_restart_cb(const container_restart_request *request, container_restart_response **response)
{
    int timeout = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *name = NULL;
    char *id = NULL;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_restart_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;
    timeout = request->timeout;

    if (!util_valid_container_id_or_name(name)) {
        cc = ISULAD_ERR_EXEC;
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        goto pack_response;
    }

    cont = containers_store_get(name);
    if (cont == NULL) {
        cc = ISULAD_ERR_EXEC;
        ERROR("No such container: %s", name);
        isulad_set_error_message("No such container:%s", name);
        goto pack_response;
    }

    id = cont->common_config->id;

    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: restarting}", id);

    if (container_in_gc_progress(id)) {
        isulad_set_error_message("You cannot restart container %s in garbage collector progress.", id);
        ERROR("You cannot restart container %s in garbage collector progress.", id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cc = do_restart_container(cont, timeout);
    if (cc != ISULAD_SUCCESS) {
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Restarted}", id);
    (void)isulad_monitor_send_container_event(id, RESTART, -1, 0, NULL, NULL);

pack_response:
    pack_restart_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static void pack_stop_response(container_stop_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static int container_stop_cb(const container_stop_request *request, container_stop_response **response)
{
    int timeout = 0;
    bool force = false;
    char *name = NULL;
    char *id = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_stop_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;
    force = request->force;
    timeout = request->timeout;

    if (name == NULL) {
        ERROR("Stop: receive NULL id");
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(name);
    if (cont == NULL) {
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: Stopping}", id);

    if (container_in_gc_progress(id)) {
        isulad_set_error_message("You cannot stop container %s in garbage collector progress.", id);
        ERROR("You cannot stop container %s in garbage collector progress.", id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (stop_container(cont, timeout, force, false)) {
        cc = ISULAD_ERR_EXEC;
        container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
        goto pack_response;
    }

    INFO("Stoped Container:%s", id);
    (void)isulad_monitor_send_container_event(id, STOP, -1, 0, NULL, NULL);

pack_response:
    pack_stop_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static void pack_kill_response(container_kill_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static int container_kill_cb(const container_kill_request *request, container_kill_response **response)
{
    int ret = 0;
    char *name = NULL;
    char *id = NULL;
    uint32_t signal = 0;
    uint32_t cc = ISULAD_SUCCESS;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_kill_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;
    signal = request->signal;

    if (name == NULL) {
        ERROR("Kill: receive NULL id");
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(name)) {
        isulad_set_error_message("Invalid container name %s", name);
        ERROR("Invalid container name %s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (!util_check_signal_valid((int)signal)) {
        isulad_set_error_message("Not supported signal %d", signal);
        ERROR("Not supported signal %d", signal);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(name);
    if (cont == NULL) {
        cc = ISULAD_ERR_EXEC;
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: Killing, Signal:%u}", id, signal);

    if (container_in_gc_progress(id)) {
        isulad_set_error_message("You cannot kill container %s in garbage collector progress.", id);
        ERROR("You cannot kill container %s in garbage collector progress.", id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    ret = kill_container(cont, signal);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Killed, Signal:%u}", id, signal);

pack_response:
    pack_kill_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static void pack_delete_response(container_delete_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
}

static int container_delete_cb(const container_delete_request *request, container_delete_response **response)
{
    bool force = false;
    uint32_t cc = ISULAD_SUCCESS;
    char *name = NULL;
    char *id = NULL;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_delete_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;
    force = request->force;

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    cont = containers_store_get(name);
    if (cont == NULL) {
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: Deleting}", id);

    container_lock(cont);
    int nret = set_container_to_removal(cont);
    container_unlock(cont);
    if (nret != 0) {
        ERROR("Failed to set container %s state to removal", id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (delete_container(cont, force)) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Deleted}", id);

pack_response:
    pack_delete_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

void container_callback_init(service_container_callback_t *cb)
{
    cb->get_id = container_get_id_cb;
    cb->get_runtime = container_get_runtime_cb;
    cb->create = container_create_cb;
    cb->start = container_start_cb;
    cb->stop = container_stop_cb;
    cb->restart = container_restart_cb;
    cb->kill = container_kill_cb;
    cb->remove = container_delete_cb;

    container_information_callback_init(cb);
    container_stream_callback_init(cb);
    container_extend_callback_init(cb);
}
