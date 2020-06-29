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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "supervisor.h"
#include "mainloop.h"
#include "libisulad.h"
#include "event_sender.h"
#include "containers_gc.h"
#include "service_container.h"

pthread_mutex_t g_supervisor_lock = PTHREAD_MUTEX_INITIALIZER;
struct epoll_descr g_supervisor_descr;

struct supervisor_handler_data {
    int fd;
    int exit_code;
    char *name;
    char *runtime;
    container_pid_t pid_info;
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
char *exit_fifo_create(const char *cont_state_path)
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
        ERROR("Failed to mknod exit monitor fifo %s: %s.", fifo_path, strerror(errno));
        return NULL;
    }

    return util_strdup_s(fifo_path);
}

/* exit fifo open */
int exit_fifo_open(const char *cont_exit_fifo)
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
        ERROR("Failed to open exit monitor FIFO %s: %s.", cont_exit_fifo, strerror(errno));
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

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        CRIT("Set thread detach fail");
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
            usleep_nointerupt(100 * 1000); /* 100 millisecond */
            retry_count++;
            goto retry;
        }

        ret = gc_add_container(name, runtime, &data->pid_info);
        if (ret != 0) {
            ERROR("Failed to send container %s to garbage handler", name);
        }
    }

    (void)isulad_monitor_send_container_event(name, STOPPED, (int)pid, data->exit_code, NULL, NULL);

    supervisor_handler_data_free(data);

    DAEMON_CLEAR_ERRMSG();
    return NULL;
}

/* new clean resources thread */
int new_clean_resources_thread(struct supervisor_handler_data *data)
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

    return 0;
}

/* supervisor add exit monitor */
int supervisor_add_exit_monitor(int fd, const container_pid_t *pid_info, const char *name, const char *runtime)
{
    int ret = 0;
    struct supervisor_handler_data *data = NULL;

    if (fd < 0) {
        ERROR("Invalid exit fifo fd");
        return -1;
    }

    if (pid_info == NULL || name == NULL || runtime == NULL) {
        ERROR("Invalid input arguments");
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
    data->name = util_strdup_s(name);
    data->runtime = util_strdup_s(runtime);
    data->pid_info.pid = pid_info->pid;
    data->pid_info.start_time = pid_info->start_time;
    data->pid_info.ppid = pid_info->ppid;
    data->pid_info.pstart_time = pid_info->pstart_time;

    supervisor_handler_lock();
    ret = epoll_loop_add_handler(&g_supervisor_descr, fd, supervisor_exit_cb, data);
    if (ret != 0) {
        ERROR("Failed to add handler for exit fifo");
        goto err;
    }

    goto out;

err:
    supervisor_handler_data_free(data);
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
    ERROR("Mainloop returned an error: %s", strerror(errno));

    epoll_loop_close(&g_supervisor_descr);

pexit:
    DAEMON_CLEAR_ERRMSG();
    return NULL;
}

/* new supervisor */
int new_supervisor()
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
