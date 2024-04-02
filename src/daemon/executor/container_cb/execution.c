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

#include "execution.h"
#include <stdio.h>
#include <pthread.h>
#include <malloc.h>
#include <sys/eventfd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include <isula_libutils/container_config.h>
#include <isula_libutils/container_config_v2.h>
#include <isula_libutils/container_delete_request.h>
#include <isula_libutils/container_delete_response.h>
#include <isula_libutils/container_get_id_request.h>
#include <isula_libutils/container_get_id_response.h>
#include <isula_libutils/container_get_runtime_response.h>
#include <isula_libutils/container_kill_request.h>
#include <isula_libutils/container_kill_response.h>
#include <isula_libutils/container_restart_request.h>
#include <isula_libutils/container_restart_response.h>
#include <isula_libutils/container_start_request.h>
#include <isula_libutils/container_start_response.h>
#include <isula_libutils/container_stop_request.h>
#include <isula_libutils/container_stop_response.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/log.h>

#include "isulad_config.h"
#include "sysinfo.h"
#include "container_api.h"
#include "constants.h"
#include "specs_api.h"
#include "execution_extend.h"
#include "execution_information.h"
#include "execution_stream.h"
#include "execution_create.h"
#include "io_handler.h"
#include "runtime_api.h"
#include "utils.h"
#include "error.h"
#include "events_sender_api.h"
#include "service_container_api.h"
#include "err_msg.h"
#include "event_type.h"
#include "utils_timestamp.h"
#include "utils_verify.h"
#include "mailbox.h"
#ifdef ENABLE_NATIVE_NETWORK
#include "service_network_api.h"

#define STOP_TIMEOUT 10
#endif

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
                            struct io_write_wrapper *stderr_handler, int *sync_fd, pthread_t *thread_id)
{
    int ret = 0;
    char *id = NULL;

    id = cont->common_config->id;

    if (request->attach_stdin || request->attach_stdout || request->attach_stderr) {
        if (create_daemon_fifos(id, cont->runtime, request->attach_stdin, request->attach_stdout,
                                request->attach_stderr, "start", fifos, fifopath)) {
            ret = -1;
            goto out;
        }

        *sync_fd = eventfd(0, EFD_CLOEXEC);
        if (*sync_fd < 0) {
            SYSERROR("Failed to create eventfd.");
            ret = -1;
            goto out;
        }

        if (ready_copy_io_data(*sync_fd, false, request->stdin, request->stdout, request->stderr, stdinfd,
                               stdout_handler, stderr_handler, (const char **)fifos, thread_id)) {
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

static int do_init_cpurt_cgroups_path(const char *path, int recursive_depth, const char *mnt_root,
                                      int64_t cpu_rt_period, int64_t cpu_rt_runtime);

/* maybe create cpu realtime file */
static int maybe_create_cpu_realtime_file(int64_t value, const char *file, const char *path)
{
    int ret;
    __isula_auto_close int fd = -1;
    ssize_t nwrite;
    char fpath[PATH_MAX] = { 0 };
    char buf[ISULAD_NUMSTRLEN64] = { 0 };

    if (value == 0) {
        return 0;
    }

    ret = util_mkdir_p(path, DEFAULT_CGROUP_DIR_MODE);
    if (ret != 0) {
        ERROR("Failed to mkdir: %s", path);
        return -1;
    }

    ret = snprintf(fpath, sizeof(fpath), "%s/%s", path, file);
    if (ret < 0 || (size_t)ret >= sizeof(fpath)) {
        ERROR("Failed to print string");
        return -1;
    }
    ret = snprintf(buf, sizeof(buf), "%lld", (long long int)value);
    if (ret < 0 || (size_t)ret >= sizeof(buf)) {
        ERROR("Failed to print string");
        return -1;
    }

    fd = util_open(fpath, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0700);
    if (fd < 0) {
        SYSERROR("Failed to open file: %s.", fpath);
        isulad_set_error_message("Failed to open file: %s.", fpath);
        return -1;
    }
    nwrite = util_write_nointr(fd, buf, strlen(buf));
    if (nwrite < 0 || (size_t)nwrite != strlen(buf)) {
        SYSERROR("Failed to write %s to %s.", buf, fpath);
        isulad_set_error_message("Failed to write '%s' to '%s'.", buf, fpath);
        return -1;
    }

    return 0;
}

static int recursively_create_cgroup(const char *path, const char *mnt_root, int recursive_depth, int64_t cpu_rt_period,
                                     int64_t cpu_rt_runtime)
{
    int ret = 0;
    __isula_auto_free char *dup = NULL;
    char *dirpath = NULL;
    char fpath[PATH_MAX] = { 0 };

    dup = util_strdup_s(path);
    dirpath = dirname(dup);
    ret = do_init_cpurt_cgroups_path(dirpath, (recursive_depth + 1), mnt_root, cpu_rt_period, cpu_rt_runtime);
    if (ret != 0) {
        return ret;
    }

    int nret = snprintf(fpath, sizeof(fpath), "%s/%s", mnt_root, path);
    if (nret < 0 || (size_t)nret >= sizeof(fpath)) {
        ERROR("Failed to print string");
        return ret;
    }

    ret = maybe_create_cpu_realtime_file(cpu_rt_period, "cpu.rt_period_us", fpath);
    if (ret != 0) {
        return ret;
    }

    return maybe_create_cpu_realtime_file(cpu_rt_runtime, "cpu.rt_runtime_us", fpath);
}

/* init cgroups path */
static int do_init_cpurt_cgroups_path(const char *path, int recursive_depth, const char *mnt_root,
                                      int64_t cpu_rt_period, int64_t cpu_rt_runtime)
{
    if ((recursive_depth + 1) > MAX_PATH_DEPTH) {
        ERROR("Reach the max cgroup depth:%s", path);
        return -1;
    }

    if (path == NULL || strcmp(path, "/") == 0 || strcmp(path, ".") == 0) {
        return 0;
    }

    // Recursively create cgroup to ensure that the system and all parent cgroups have values set
    // for the period and runtime as this limits what the children can be set to.
    return recursively_create_cgroup(path, mnt_root, recursive_depth, cpu_rt_period, cpu_rt_runtime);
}

// TODO: maybe we should adapt to cgroup v2
static int cpurt_controller_init(const char *id, const host_config *host_spec)
{
    __isula_auto_free char *mnt_root = NULL;
    __isula_auto_free char *cgroups_path = NULL;
    char *dirpath = NULL;
    int64_t cpu_rt_period = 0;
    int64_t cpu_rt_runtime = 0;
    int cgroup_version = 0;

    // cgroup v2 is not support cpurt
    cgroup_version = common_get_cgroup_version();
    if (cgroup_version == CGROUP_VERSION_2) {
        return 0;
    }

    cgroups_path = merge_container_cgroups_path(id, host_spec);
    if (cgroups_path == NULL || strcmp(cgroups_path, "/") == 0 || strcmp(cgroups_path, ".") == 0) {
        return 0;
    }

    if (conf_get_cgroup_cpu_rt(&cpu_rt_period, &cpu_rt_runtime)) {
        return -1;
    }

    if (cpu_rt_period == 0 && cpu_rt_runtime == 0) {
        return 0;
    }

    if (conf_get_systemd_cgroup()) {
        __isula_auto_free char *converted_cgroup = common_convert_cgroup_path(cgroups_path);
        if (converted_cgroup == NULL) {
            ERROR("Failed to convert cgroup path");
            return -1;
        }

        __isula_auto_free char *init_cgroup = common_get_init_cgroup_path("cpu");
        if (init_cgroup == NULL) {
            ERROR("Failed to get init cgroup");
            return -1;
        }
        // make sure that the own cgroup path for cpu existed
        __isula_auto_free char *own_cgroup = common_get_own_cgroup_path("cpu");
        if (own_cgroup == NULL) {
            ERROR("Failed to get own cgroup");
            return -1;
        }
        char *new_cgroups_path = util_path_join(init_cgroup, converted_cgroup);
        if (new_cgroups_path == NULL) {
            ERROR("Failed to join path");
            return -1;
        }
        free(cgroups_path);
        cgroups_path = new_cgroups_path;
    }

    mnt_root = sysinfo_get_cpurt_mnt_path();
    if (mnt_root == NULL) {
        ERROR("Failed to get cpu rt controller mnt root path");
        return -1;
    }

    dirpath = dirname(cgroups_path);

    return do_init_cpurt_cgroups_path(dirpath, 0, mnt_root, cpu_rt_period, cpu_rt_runtime);
}

static int container_start_prepare(container_t *cont, const container_start_request *request, int stdinfd,
                                   struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler,
                                   char **fifopath, char *fifos[], int *sync_fd, pthread_t *thread_id)
{
    const char *id = cont->common_config->id;

    if (container_state_to_disk_locking(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        isulad_set_error_message("Failed to save container \"%s\" to disk", id);
        return -1;
    }

    // init cgroup path for cpu_rt_runtime and cpu_rt_period
    // we should do this in start container, not create container
    // because, in scenarios:
    // 1. enable cpu-rt of isulad;
    // 2. then run container with --cpu-rt-runtime
    // 3. then reboot machine;
    // 4. finally, start before container, it will failed...
    // cause of no one to set value into cgroup/isulad/cpu-rt-runtime and cpu-rt-period.
    if (cpurt_controller_init(id, cont->hostconfig) != 0) {
        isulad_set_error_message("Failed to init controller of cpu-rt for container \"%s\".", id);
        return -1;
    }

    if (prepare_start_io(cont, request, fifopath, fifos, stdinfd, stdout_handler, stderr_handler, sync_fd, thread_id) !=
        0) {
        return -1;
    }

    return 0;
}

static void handle_start_io_thread_by_cc(uint32_t cc, int sync_fd, pthread_t thread_id)
{
    if (cc == ISULAD_SUCCESS) {
        if (thread_id > 0) {
            if (pthread_detach(thread_id) != 0) {
                SYSERROR("Failed to detach 0x%lx", thread_id);
            }
        }
        if (sync_fd >= 0) {
            close(sync_fd);
        }
    } else {
        if (sync_fd >= 0) {
            if (eventfd_write(sync_fd, 1) < 0) {
                SYSERROR("Failed to write eventfd.");
            }
        }
        if (thread_id > 0) {
            if (pthread_join(thread_id, NULL) != 0) {
                ERROR("Failed to join thread: 0x%lx", thread_id);
            }
        }
        if (sync_fd >= 0) {
            close(sync_fd);
        }
    }
}

static int container_start_cb(const container_start_request *request, container_start_response **response, int stdinfd,
                              struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler)
{
    uint32_t cc = ISULAD_SUCCESS;
    char *id = NULL;
    char *fifos[3] = { NULL, NULL, NULL };
    char *fifopath = NULL;
    container_t *cont = NULL;
    int sync_fd = -1;
    pthread_t thread_id = 0;
#ifdef ENABLE_CRI_API_V1
    cri_container_message_t message;
#endif

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

    container_state_set_starting(cont->state);

    if (container_is_running(cont->state)) {
        INFO("Container is already running");
        goto pack_response;
    }

    if (container_start_prepare(cont, request, stdinfd, stdout_handler, stderr_handler, &fifopath, fifos, &sync_fd,
                                &thread_id) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (start_container(cont, (const char **)fifos, true) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Running}", id);
    (void)isulad_monitor_send_container_event(id, START, -1, 0, NULL, NULL);

#ifdef ENABLE_CRI_API_V1
    if (is_container_in_sandbox(cont->common_config->sandbox_info)) {
        message.container_id = id;
        message.sandbox_id = cont->common_config->sandbox_info->id;
        message.type = CRI_CONTAINER_MESSAGE_TYPE_STARTED;
        mailbox_publish(MAILBOX_TOPIC_CRI_CONTAINER, &message);
    }
#endif

pack_response:
    handle_start_io_thread_by_cc(cc, sync_fd, thread_id);
    delete_daemon_fifos(fifopath, (const char **)fifos);
    free(fifos[0]);
    free(fifos[1]);
    free(fifos[2]);
    free(fifopath);
    pack_start_response(*response, cc, id);
    if (cont != NULL) {
        container_state_reset_starting(cont->state);
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

    if (container_is_removal_in_progress(cont->state) || container_is_dead(cont->state)) {
        ERROR("Container is marked for removal and cannot be started.");
        isulad_set_error_message("Container is marked for removal and cannot be started.");
        goto out;
    }

    (void)util_get_now_time_buffer(timebuffer, sizeof(timebuffer));

    params.rootpath = rootpath;

    ret = runtime_restart(id, runtime, &params);
    if (ret == -2) {
        goto out;
    }

    if (ret == 0) {
        container_restart_update_start_and_finish_time(cont->state, timebuffer);
    }

    if (container_state_to_disk(cont)) {
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

#ifdef ENABLE_NATIVE_NETWORK
    // skip remove network when restarting container
    set_container_skip_remove_network(cont);
#endif

    ret = stop_container(cont, timeout, false, true);

#ifdef ENABLE_NATIVE_NETWORK
    reset_container_skip_remove_network(cont);
#endif

    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
        goto out;
    }

    /* begin start container */
    container_state_set_starting(cont->state);
    if (container_state_to_disk_locking(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        cc = ISULAD_ERR_EXEC;
        isulad_set_error_message("Failed to save container \"%s\" to disk", id);
        goto out;
    }

    if (container_is_running(cont->state)) {
        INFO("Container is already running");
        goto out;
    }

    if (start_container(cont, console_fifos, true) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

out:
    container_state_reset_starting(cont->state);
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

    if (container_is_in_gc_progress(id)) {
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

    if (container_is_in_gc_progress(id)) {
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

    (void)isulad_monitor_send_container_event(id, STOP, -1, 0, NULL, NULL);
    EVENT("Event: {Object: %s, Type: Stopped}", id);

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

    if (!util_valid_signal((int)signal)) {
        isulad_set_error_message("Not supported signal %u", signal);
        ERROR("Not supported signal %u", signal);
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

    if (container_is_in_gc_progress(id)) {
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
#ifdef ENABLE_CRI_API_V1
    cri_container_message_t message;
#endif

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

    cont->rm_anonymous_volumes = request->volumes;
    if (delete_container(cont, force)) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Deleted}", id);

#ifdef ENABLE_CRI_API_V1
    if (is_container_in_sandbox(cont->common_config->sandbox_info)) {
        message.container_id = cont->common_config->id;
        message.sandbox_id = cont->common_config->sandbox_info->id;
        message.type = CRI_CONTAINER_MESSAGE_TYPE_DELETED;
        mailbox_publish(MAILBOX_TOPIC_CRI_CONTAINER, &message);
    }
#endif

pack_response:
    pack_delete_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static void pack_update_network_settings_response(container_update_network_settings_response *response, uint32_t cc,
                                                  const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    response->errmsg = util_strdup_s(g_isulad_errmsg);
    DAEMON_CLEAR_ERRMSG();
    response->id = util_strdup_s(id);
}

static int update_container_network_setting_lock(container_t *cont, const char *setting_json)
{
    int ret = 0;
    parser_error err = NULL;

    container_lock(cont);
    free_container_network_settings(cont->network_settings);
    cont->network_settings = container_network_settings_parse_data(setting_json, NULL, &err);
    if (cont->network_settings == NULL) {
        ERROR("Parse network settings failed: %s", err);
        ret = -1;
        goto out;
    }

    if (container_network_settings_to_disk(cont) != 0) {
        ERROR("Failed to save container '%s' network settings", cont->common_config->id);
        ret = -1;
    }

out:
    container_unlock(cont);
    free(err);
    return ret;
}

static int container_update_network_settings_cb(const container_update_network_settings_request *request,
                                                container_update_network_settings_response **response)
{
    uint32_t cc = ISULAD_SUCCESS;
    const char *name = NULL;
    const char *id = NULL;
    container_t *cont = NULL;

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    if (!util_valid_str(request->setting_json)) {
        DEBUG("Network setting is empty, no need to do anythin");
        return 0;
    }

    DAEMON_CLEAR_ERRMSG();
    *response = util_common_calloc_s(sizeof(container_update_network_settings_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;
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

    EVENT("Event: {Object: %s, Type: Updating netorksettings}", id);

    if (update_container_network_setting_lock(cont, request->setting_json) != 0) {
        ERROR("Updated network settings to disk error");
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Updated netorksettings}", id);

pack_response:
    pack_update_network_settings_response(*response, cc, id);
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
    cb->update_network_settings = container_update_network_settings_cb;

    container_information_callback_init(cb);
    container_stream_callback_init(cb);
    container_extend_callback_init(cb);
}
