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
 * Description: provide container supervisor functions
 ******************************************************************************/
#define _GNU_SOURCE
#include "supervisor.h"
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "mainloop.h"
#include "err_msg.h"
#include "events_sender_api.h"
#include "containers_gc.h"
#include "service_container_api.h"
#include "container_api.h"
#include "event_type.h"
#include "utils_file.h"
#include "mailbox.h"
#ifdef ENABLE_CRI_API_V1
#include "sandbox_ops.h"
#endif
#include "cgroup.h"
#include "specs_api.h"

pthread_mutex_t g_supervisor_lock = PTHREAD_MUTEX_INITIALIZER;
struct epoll_descr g_supervisor_descr;

struct supervisor_handler_data {
    int fd;
    int exit_code;
    char *name;
    char *sandbox_name;
    char *runtime;
    bool is_sandbox_container;
    pid_ppid_info_t pid_info;
};

/* supervisor handler lock */
static void supervisor_handler_lock()
{
    if (pthread_mutex_lock(&g_supervisor_lock) != 0) {
        ERROR("Failed to lock supervisor lock");
    }
}

/* supervisor handler unlock */
static void supervisor_handler_unlock()
{
    if (pthread_mutex_unlock(&g_supervisor_lock) != 0) {
        ERROR("Failed to lock supervisor lock");
    }
}

#define EXIT_FIFO "exit_fifo"
/* exit fifo name */
char *exit_fifo_name(const char *cont_state_path)
{
    int ret = 0;
    char fifo_path[PATH_MAX] = { 0 };

    if (cont_state_path == NULL) {
        return NULL;
    }

    ret = snprintf(fifo_path, sizeof(fifo_path), "%s/%s", cont_state_path, EXIT_FIFO);
    if (ret < 0 || (size_t)ret >= sizeof(fifo_path)) {
        ERROR("sprintf buffer failed");
        return NULL;
    }

    return util_strdup_s(fifo_path);
}

/* exit fifo create */
char *container_exit_fifo_create(const char *cont_state_path)
{
    int ret = 0;
    char fifo_path[PATH_MAX] = { 0 };

    if (cont_state_path == NULL) {
        return NULL;
    }

    ret = snprintf(fifo_path, sizeof(fifo_path), "%s/%s", cont_state_path, EXIT_FIFO);
    if (ret < 0 || (size_t)ret >= sizeof(fifo_path)) {
        ERROR("sprintf buffer failed");
        return NULL;
    }

    ret = mknod(fifo_path, S_IFIFO | S_IRUSR | S_IWUSR, (dev_t)0);
    if (ret < 0 && errno != EEXIST) {
        SYSERROR("Failed to mknod exit monitor fifo %s.", fifo_path);
        return NULL;
    }

    return util_strdup_s(fifo_path);
}

/* exit fifo open */
int container_exit_fifo_open(const char *cont_exit_fifo)
{
    int ret = 0;

    if (cont_exit_fifo == NULL) {
        return -1;
    }

    if (!util_file_exists(cont_exit_fifo)) {
        ERROR("Exit FIFO %s does not does not exist", cont_exit_fifo);
        ret = -1;
        goto out;
    }

    ret = util_open(cont_exit_fifo, O_RDONLY | O_NONBLOCK, 0);
    if (ret < 0) {
        SYSERROR("Failed to open exit monitor FIFO %s.", cont_exit_fifo);
        ret = -1;
        goto out;
    }
out:
    return ret;
}

/* supervisor handler data free */
static void supervisor_handler_data_free(struct supervisor_handler_data *data)
{
    if (data == NULL) {
        return;
    }

    free(data->name);
    data->name = NULL;

    free(data->sandbox_name);
    data->sandbox_name = NULL;

    free(data->runtime);
    data->runtime = NULL;

    if (data->fd >= 0) {
        close(data->fd);
    }
    free(data);
}

/* clean resources thread */
static void *clean_resources_thread(void *arg)
{
    int ret = 0;
    struct supervisor_handler_data *data = arg;
    char *name = data->name;
    char *runtime = data->runtime;
    unsigned long long start_time = data->pid_info.start_time;
    pid_t pid = data->pid_info.pid;
    int retry_count = 0;
    int max_retry = 10;
#ifdef ENABLE_CRI_API_V1
    cri_container_message_t msg;
#endif

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        CRIT("Set thread detach fail");
        return NULL;
    }

    prctl(PR_SET_NAME, "Clean resource");

retry:
    if (false == util_process_alive(pid, start_time)) {
        ret = clean_container_resource(name, runtime, pid);
        // clean_container_resource failed, do not log error message,
        // just add to gc to retry clean resource.
        if (ret != 0 && gc_add_container(name, runtime, &data->pid_info) != 0) {
            ERROR("Failed to clean resources of container %s", name);
        }
    } else {
        ret = kill(pid, SIGKILL);
        if (ret < 0 && errno != ESRCH) {
            ERROR("Can not kill process (pid=%d) with SIGKILL for container %s", pid, name);
        }

        if (retry_count < max_retry) {
            util_usleep_nointerupt(100 * 1000); /* 100 millisecond */
            retry_count++;
            goto retry;
        }

        // get info of init process in container for debug problem of container
        proc_t *c_proc = util_get_process_proc_info(pid);
        if (c_proc != NULL) {
            ERROR("Container %s into GC with process state: {cmd: %s, state: %c, pid: %d}", name, c_proc->cmd, c_proc->state,
                  (int)pid);
            free(c_proc);
        }

        ret = gc_add_container(name, runtime, &data->pid_info);
        if (ret != 0) {
            ERROR("Failed to send container %s to garbage handler", name);
        }
    }

    (void)isulad_monitor_send_container_event(name, STOPPED, (int)pid, data->exit_code, NULL, NULL);

#ifdef ENABLE_CRI_API_V1
    if (data->sandbox_name) {
        msg.container_id = name;
        msg.sandbox_id = data->sandbox_name;
        msg.type = CRI_CONTAINER_MESSAGE_TYPE_STOPPED;
        mailbox_publish(MAILBOX_TOPIC_CRI_CONTAINER, &msg);
    }

    if (data->is_sandbox_container) {
        if (sandbox_on_sandbox_exit(name, data->exit_code) < 0) {
            ERROR("Failed to handle sandbox %s exit", name);
        }
    }
#endif

    supervisor_handler_data_free(data);

    DAEMON_CLEAR_ERRMSG();
    return NULL;
}

/* new clean resources thread */
static int new_clean_resources_thread(struct supervisor_handler_data *data)
{
    int ret = 0;
    pthread_t clean_thread;

    if (pthread_create(&clean_thread, NULL, clean_resources_thread, data)) {
        ERROR("Create clean resource thread failed");
        supervisor_handler_data_free(data);
        ret = -1;
    }

    return ret;
}

/* supervisor exit cb */
static int supervisor_exit_cb(int fd, uint32_t events, void *cbdata, struct epoll_descr *descr)
{
    ssize_t r = 0;
    int exit_code = 0;
    struct supervisor_handler_data *data = cbdata;
    char *name = data->name;

    r = util_read_nointr(fd, &exit_code, sizeof(int));
    if (r <= 0) {
        exit_code = 137;
    }

    data->exit_code = exit_code;

    INFO("The container %s 's monitor on fd %d has exited", name, fd);
    supervisor_handler_lock();
    epoll_loop_del_handler(&g_supervisor_descr, fd);
    supervisor_handler_unlock();

    (void)new_clean_resources_thread(data);

    return EPOLL_LOOP_HANDLE_CONTINUE;
}

static int oom_handle_cb(int fd, uint32_t events, void *cbdata, struct epoll_descr *descr)
{
    cgroup_oom_handler_info_t *oom_handler_info = (cgroup_oom_handler_info_t *)cbdata;
    bool close_oom_handler = CGROUP_OOM_HANDLE_CLOSE;
    // supervisor only handle one oom event, so we remove the handler directly
    if (oom_handler_info != NULL && oom_handler_info->oom_event_handler != NULL) {
        close_oom_handler = oom_handler_info->oom_event_handler(fd, oom_handler_info);
    }

    if (close_oom_handler == CGROUP_OOM_HANDLE_CLOSE) {
        supervisor_handler_lock();
        epoll_loop_del_handler(&g_supervisor_descr, fd);
        supervisor_handler_unlock();

        common_free_cgroup_oom_handler_info(oom_handler_info);
    }

    return EPOLL_LOOP_HANDLE_CONTINUE;
}

/* supervisor add exit monitor */
int container_supervisor_add_exit_monitor(int fd, const char *exit_fifo, const pid_ppid_info_t *pid_info, const container_t *cont)
{
    int ret = 0;
    struct supervisor_handler_data *data = NULL;
    cgroup_oom_handler_info_t *oom_handler_info = NULL;
    __isula_auto_free char *cgroup_path = NULL;

    if (fd < 0) {
        ERROR("Invalid exit fifo fd");
        return -1;
    }

    if (pid_info == NULL || cont == NULL || cont->common_config == NULL) {
        ERROR("Invalid input arguments");
        close(fd);
        return -1;
    }

    cgroup_path = merge_container_cgroups_path(cont->common_config->id, cont->hostconfig);
    if (cgroup_path == NULL) {
        ERROR("Failed to get cgroup path");
        close(fd);
        return -1;
    }

    data = util_common_calloc_s(sizeof(struct supervisor_handler_data));
    if (data == NULL) {
        ERROR("Memory out");
        close(fd);
        return -1;
    }

    data->fd = fd;
    data->name = util_strdup_s(cont->common_config->id);
    data->runtime = util_strdup_s(cont->runtime);
#ifdef ENABLE_CRI_API_V1
    data->is_sandbox_container = is_sandbox_container(cont->common_config->sandbox_info);
    if (is_container_in_sandbox(cont->common_config->sandbox_info)) {
        data->sandbox_name = util_strdup_s(cont->common_config->sandbox_info->id);
    }
#endif
    data->pid_info.pid = pid_info->pid;
    data->pid_info.start_time = pid_info->start_time;
    data->pid_info.ppid = pid_info->ppid;
    data->pid_info.pstart_time = pid_info->pstart_time;
    oom_handler_info = common_get_cgroup_oom_handler(fd, cont->common_config->id, cgroup_path, exit_fifo);

    supervisor_handler_lock();
    if (oom_handler_info != NULL) {
        ret = epoll_loop_add_handler(&g_supervisor_descr, oom_handler_info->oom_event_fd, oom_handle_cb, oom_handler_info);
        if (ret != 0) {
            ERROR("Failed to add handler for oom event");
            goto err;
        }
    }

    ret = epoll_loop_add_handler(&g_supervisor_descr, fd, supervisor_exit_cb, data);
    if (ret != 0) {
        ERROR("Failed to add handler for exit fifo");
        goto err;
    }

    goto out;

err:
    supervisor_handler_data_free(data);
    common_free_cgroup_oom_handler_info(oom_handler_info);
out:
    supervisor_handler_unlock();
    return ret;
}

/* supervisor */
static void *supervisor(void *arg)
{
    int ret = 0;

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        CRIT("Set thread detach fail");
        goto pexit;
    }

    prctl(PR_SET_NAME, "Supervisor");

restart:
    ret = epoll_loop(&g_supervisor_descr, -1);
    if (ret == 0) {
        goto restart;
    }
    SYSERROR("Mainloop returned an error");

    epoll_loop_close(&g_supervisor_descr);

pexit:
    DAEMON_CLEAR_ERRMSG();
    return NULL;
}

/* new supervisor */
int new_supervisor(void)
{
    int ret = 0;
    pthread_t supervisor_thread;

    INFO("Starting supervisor...");

    ret = epoll_loop_open(&g_supervisor_descr);
    if (ret != 0) {
        ERROR("Failed to create epoll_loop");
        ret = -1;
        goto out;
    }

    if (pthread_create(&supervisor_thread, NULL, supervisor, NULL) != 0) {
        ERROR("Create supervisor thread failed");
        ret = -1;
    }

out:
    return ret;
}
