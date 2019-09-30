/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container collector functions
 ******************************************************************************/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <poll.h>
#include <sys/prctl.h>
#include <regex.h>
#include <errno.h>

#include "error.h"
#include "log.h"
#include <lcr/lcrcontainer.h>
#include "collector.h"
#include "lcrd_config.h"
#include "securec.h"
#include "liblcrd.h"
#include "containers_store.h"

static struct context_lists g_context_lists;

struct events_lists {
    unsigned int size;
    pthread_mutex_t event_mutex;
    struct linked_list event_list;
};
static struct events_lists g_events_buffer;

#define EVENTSLIMIT 64

struct context_elem {
    stream_func_wrapper stream;
    char *name;
    sem_t context_sem;
    const types_timestamp_t *since;
    const types_timestamp_t *until;
};

/* get idreg */
static bool get_idreg(regex_t *preg, const char *id)
{
    char *regexp = NULL;
    size_t len = 0;
    int nret = 0;
    bool ret = false;

    if (id == NULL) {
        ERROR("Invalid event id");
        return false;
    }

    len = strlen(id) + 3;
    regexp = util_common_calloc_s(len);
    if (regexp == NULL) {
        ERROR("failed to allocate memory");
        return false;
    }

    nret = sprintf_s(regexp, len, "^%s$", id);
    if (nret < 0) {
        ERROR("Failed to print string");
        goto error;
    }

    if (regcomp(preg, regexp, REG_NOSUB | REG_EXTENDED)) {
        ERROR("failed to compile the regex '%s'", id);
        goto error;
    }

    ret = true;

error:
    free(regexp);
    return ret;
}

static container_events_type_t lcrsta2Evetype(int value)
{
    container_events_type_t et = EVENTS_TYPE_EXIT;

    switch (value) {
        case STOPPED:
            et = EVENTS_TYPE_STOPPED1;
            break;
        case STARTING:
            et = EVENTS_TYPE_STARTING;
            break;
        case RUNNING:
            et = EVENTS_TYPE_RUNNING1;
            break;
        case STOPPING:
            et = EVENTS_TYPE_STOPPING;
            break;
        case ABORTING:
            et = EVENTS_TYPE_ABORTING;
            break;
        case FREEZING:
            et = EVENTS_TYPE_FREEZING;
            break;
        case FROZEN:
            et = EVENTS_TYPE_FROZEN;
            break;
        case THAWED:
            et = EVENTS_TYPE_THAWED;
            break;
        default:
            et = EVENTS_TYPE_EXIT;
            break;
    }
    return et;
}

/* format_msg */
static bool format_msg(struct lcrd_events_format *r, struct monitord_msg *msg)
{
    bool ret = false;
    int err = 0;
    struct timespec ts;

    err = clock_gettime(CLOCK_REALTIME, &ts);
    if (err != 0) {
        ERROR("failed to get time");
        return false;
    }
    r->timestamp.has_seconds = true;
    r->timestamp.seconds = (int64_t)ts.tv_sec;
    r->timestamp.has_nanos = true;
    r->timestamp.nanos = (int32_t)ts.tv_nsec;

    msg->name[sizeof(msg->name) - 1] = '\0';

    r->has_pid = false;
    switch (msg->type) {
        case monitord_msg_state:
            r->id = msg->name;
            if (msg->pid != -1) {
                r->has_pid = true;
                r->pid = (uint32_t)msg->pid;
            }
            r->has_type = true;
            r->type = lcrsta2Evetype(msg->value);
            if (r->type == EVENTS_TYPE_STOPPED1) {
                r->has_exit_status = true;
                if (msg->exit_code >= 0) {
                    r->exit_status = (uint32_t)msg->exit_code;
                } else {
                    r->exit_status = 125;
                }
            }
            ret = true;
            break;
        case monitord_msg_priority:
        case monitord_msg_exit_code:
        default:
            /* ignore garbage */
            ret = false;
            DEBUG("Ignore received %d event", msg->type);
            break;
    }
    return ret;
}

static const char * const g_lcrd_event_strtype[] = {
    "EXIT",   "STOPPED", "STARTING", "RUNNING", "STOPPING", "ABORTING",   "FREEZING",
    "FROZEN", "THAWED",  "OOM",      "CREATE",  "START",    "EXEC_ADDED", "PAUSED1",
};

/* lcrd event sta2str */
static const char *lcrd_event_sta2str(container_events_type_t sta)
{
    if (sta > EVENTS_TYPE_PAUSED1) {
        return NULL;
    }
    return g_lcrd_event_strtype[sta];
}

/* lcrd monitor fifo send */
static void lcrd_monitor_fifo_send(const struct monitord_msg *msg, const char *statedir)
{
    int fd = -1;
    ssize_t ret = 0;
    char *fifo_path = NULL;

    fifo_path = lcrd_monitor_fifo_name(statedir);
    if (fifo_path == NULL) {
        return;
    }

    /* Open the fifo nonblock in case the monitor is dead, we don't want the
     * open to wait for a reader since it may never come.
     */
    fd = util_open(fifo_path, O_WRONLY | O_NONBLOCK, 0);
    if (fd < 0) {
        /* It is normal for this open() to fail with ENXIO when there is
         * no monitor running, so we don't log it.
         */
        if (errno == ENXIO || errno == ENOENT) {
            goto out;
        }

        ERROR("Failed to open fifo to send message: %s.", strerror(errno));
        goto out;
    }

    ret = write(fd, msg, sizeof(struct monitord_msg));
    if (ret < 0 || (size_t)ret != sizeof(struct monitord_msg)) {
        ERROR("Failed to write to monitor fifo \"%s\": %s.", fifo_path, strerror(errno));
        goto out;
    }

out:
    free(fifo_path);
    if (fd >= 0) {
        close(fd);
    }
}

/* lcrd monitor send event */
int lcrd_monitor_send_event(const char *name, runtime_state_t state, int pid, int exit_code)
{
    int ret = 0;
    char *statedir = NULL;
    errno_t nret;
    struct monitord_msg msg = {
        .type = monitord_msg_state,
        .value = state,
        .pid = -1,
        .exit_code = -1
    };

    if (name == NULL) {
        CRIT("Invalid input arguments");
        ret = -1;
        goto out;
    }

    statedir = conf_get_lcrd_statedir();
    if (statedir == NULL) {
        CRIT("Can not get lcrd root path");
        ret = -1;
        goto out;
    }

    nret = strncpy_s(msg.name, sizeof(msg.name), name, sizeof(msg.name) - 1);
    if (nret != EOK) {
        ERROR("Fail at lcrd_monitor_send_event string copy!");
        ret = -1;
        goto out;
    }
    msg.name[sizeof(msg.name) - 1] = 0;
    if (pid > 0) {
        msg.pid = pid;
    }
    if (exit_code >= 0) {
        msg.exit_code = exit_code;
    }

    lcrd_monitor_fifo_send(&msg, statedir);

out:
    free(statedir);
    return ret;
}

/* write events log */
static int write_events_log(const struct lcrd_events_format *events)
{
#define PID_PREFIX ", Pid: "
#define EXIT_CODE_PREFIX ", ExitCode: "

    int ret = 0;
    int nret = 0;
    char *pid_str = NULL;
    char *exit_status_str = NULL;

    if (events == NULL) {
        goto out;
    }

    if (events->has_pid) {
        nret = asprintf(&pid_str, "%s%u", PID_PREFIX, events->pid);
        if (nret < 0) {
            ERROR("Sprintf pid failed");
            ret = -1;
            goto out;
        }
    }

    if (events->has_exit_status) {
        nret = asprintf(&exit_status_str, "%s%u", EXIT_CODE_PREFIX, events->exit_status);
        if (nret < 0) {
            ERROR("Sprintf exit status failed");
            ret = -1;
            goto out;
        }
    }

    EVENT("Event: {Object: %s, Type: %s%s%s}", events->id,
          (events->has_type ? lcrd_event_sta2str((container_events_type_t)events->type) : "-"),
          (events->has_pid ? pid_str : ""), (events->has_exit_status ? exit_status_str : ""));

out:
    free(pid_str);
    free(exit_status_str);
    return ret;
}

/* events copy*/
static void event_copy(const struct lcrd_events_format *src, struct lcrd_events_format *dest)
{
    if (src == NULL || dest == NULL) {
        return;
    }

    free(dest->id);
    dest->id = util_strdup_s(src->id);
    dest->has_type = src->has_type;
    dest->type = src->type;
    dest->has_pid = src->has_pid;
    dest->pid = src->pid;
    dest->has_exit_status = src->has_exit_status;
    dest->exit_status = src->exit_status;
    dest->timestamp.has_seconds = src->timestamp.has_seconds;
    dest->timestamp.seconds = src->timestamp.seconds;
    dest->timestamp.has_nanos = src->timestamp.has_nanos;
    dest->timestamp.nanos = src->timestamp.nanos;
}

/* events append */
static void events_append(const struct lcrd_events_format *event)
{
    struct lcrd_events_format *tmpevent = NULL;
    struct linked_list *newnode = NULL;
    struct linked_list *firstnode = NULL;

    if (pthread_mutex_lock(&g_events_buffer.event_mutex)) {
        WARN("Failed to lock");
        return;
    }

    if (g_events_buffer.size < EVENTSLIMIT) {
        newnode = util_common_calloc_s(sizeof(struct linked_list));
        if (newnode == NULL) {
            CRIT("Memory allocation error.");
            goto unlock;
        }

        tmpevent = util_common_calloc_s(sizeof(struct lcrd_events_format));
        if (tmpevent == NULL) {
            CRIT("Memory allocation error.");
            free(newnode);
            goto unlock;
        }

        event_copy(event, tmpevent);

        linked_list_add_elem(newnode, tmpevent);
        linked_list_add_tail(&g_events_buffer.event_list, newnode);
        g_events_buffer.size++;
    } else {
        firstnode = linked_list_first_node(&g_events_buffer.event_list);
        if (firstnode != NULL) {
            linked_list_del(firstnode);

            tmpevent = (struct lcrd_events_format *)firstnode->elem;
            event_copy(event, tmpevent);

            linked_list_add_tail(&g_events_buffer.event_list, firstnode);
        }
    }

unlock:
    if (pthread_mutex_unlock(&g_events_buffer.event_mutex)) {
        WARN("Failed to unlock");
        return;
    }
}

static int do_write_events(const stream_func_wrapper *stream, struct lcrd_events_format *event)
{
    int ret = 0;

    if (stream->write_func == NULL || stream->writer == NULL) {
        ERROR("Unimplemented write function");
        ret = -1;
        goto out;
    }
    if (!stream->write_func(stream->writer, event)) {
        ERROR("Failed to send exit event for 'events' client");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static int check_since_time(const types_timestamp_t *since, const struct lcrd_events_format *event)
{
    if (since != NULL && (since->has_seconds || since->has_nanos)) {
        if (types_timestamp_cmp(&event->timestamp, since) < 0) {
            return -1;
        }
    }
    return 0;
}

static int check_util_time(const types_timestamp_t *until, const struct lcrd_events_format *event)
{
    if (until != NULL && (until->has_seconds || until->has_nanos)) {
        if (types_timestamp_cmp(&event->timestamp, until) > 0) {
            return -1;
        }
    }
    return 0;
}

static int do_subscribe(const char *name, const types_timestamp_t *since, const types_timestamp_t *until,
                        const stream_func_wrapper *stream)
{
    bool regflag = false;
    int ret = 0;
    regex_t preg;
    regmatch_t regmatch = { 0 };
    struct linked_list *it = NULL;
    struct linked_list *next = NULL;
    struct lcrd_events_format *c_event = NULL;

    if (pthread_mutex_lock(&g_events_buffer.event_mutex)) {
        WARN("Failed to lock");
        return -1;
    }

    linked_list_for_each_safe(it, &g_events_buffer.event_list, next) {
        c_event = (struct lcrd_events_format *)it->elem;

        if (check_since_time(since, c_event) != 0) {
            continue;
        }

        if (check_util_time(until, c_event) != 0) {
            break;
        }

        if (regflag) {
            regfree(&preg);
        }
        regflag = get_idreg(&preg, c_event->id);

        if (name != NULL && regflag) {
            if (regexec(&preg, name, 1, &regmatch, 0)) {
                continue;
            }
        }

        ret = do_write_events(stream, c_event);
        if (ret != 0) {
            break;
        }
    }

    if (pthread_mutex_unlock(&g_events_buffer.event_mutex)) {
        WARN("Failed to unlock");
    }
    if (regflag) {
        regfree(&preg);
    }

    return ret;
}

/* events subscribe */
int events_subscribe(const char *name, const types_timestamp_t *since, const types_timestamp_t *until,
                     const stream_func_wrapper *stream)
{
    if (stream == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    if (since == NULL && until == NULL) {
        return 0;
    }

    if (since != NULL && (since->has_seconds || since->has_nanos) && until != NULL &&
        (until->has_seconds || until->has_nanos)) {
        if (types_timestamp_cmp(since, until) > 0) {
            ERROR("'since' time cannot be after 'until' time");
            return -1;
        }
    }

    return do_subscribe(name, since, until, stream);
}

/* events forward */
static void events_forward(struct lcrd_events_format *r)
{
    struct linked_list *it = NULL;
    struct linked_list *next = NULL;
    struct context_elem *context_info = NULL;
    char *name = NULL;
    regex_t preg;
    bool regflag = false;
    regmatch_t regmatch = { 0 };

    events_append(r);
    regflag = get_idreg(&preg, r->id);

    if (pthread_mutex_lock(&g_context_lists.context_mutex)) {
        WARN("Failed to lock");
        return;
    }

    linked_list_for_each_safe(it, &g_context_lists.context_list, next) {
        context_info = (struct context_elem *)it->elem;
        name = context_info->name;

        if (context_info->since != NULL) {
            if (types_timestamp_cmp(&r->timestamp, context_info->since) < 0) {
                continue;
            }
        }

        if (name != NULL && regflag) {
            if (regexec(&preg, name, 1, &regmatch, 0)) {
                continue;
            }
        }

        if (context_info->stream.write_func == NULL || context_info->stream.writer == NULL) {
            INFO("Unimplemented write function");
            goto delete_and_continue;
        }
        if (!context_info->stream.write_func(context_info->stream.writer, r)) {
            INFO("Failed to send exit event for 'events' client");
            goto delete_and_continue;
        }

        continue;

delete_and_continue:
        linked_list_del(it);
        sem_post(&context_info->context_sem);
        continue;
    }

    if (pthread_mutex_unlock(&g_context_lists.context_mutex)) {
        WARN("Failed to unlock");
    }

    if (regflag) {
        regfree(&preg);
    }
}

/* event should exit */
static void *event_should_exit(void *arg)
{
    int res = 0;
    int err = 0;

    res = pthread_detach(pthread_self());
    if (res != 0) {
        CRIT("Set thread detach fail");
        goto error;
    }

    prctl(PR_SET_NAME, "Clients_checker");

    struct linked_list *it = NULL;
    struct linked_list *next = NULL;
    struct context_elem *context_info = NULL;
    struct timespec ts_now = { 0 };
    types_timestamp_t t_now = { 0 };

    for (;;) {
        if (pthread_mutex_lock(&g_context_lists.context_mutex)) {
            WARN("Failed to lock");
            continue;
        }

        linked_list_for_each_safe(it, &g_context_lists.context_list, next) {
            context_info = (struct context_elem *)it->elem;

            if (context_info->stream.is_cancelled(context_info->stream.context)) {
                DEBUG("Client has exited, stop sending events");
                linked_list_del(it);
                sem_post(&context_info->context_sem);
                continue;
            }

            if (context_info->until == NULL ||
                (context_info->until->has_seconds == 0 && context_info->until->has_nanos == 0)) {
                continue;
            }

            err = clock_gettime(CLOCK_REALTIME, &ts_now);
            if (err != 0) {
                ERROR("Failed to get time");
                continue;
            }

            t_now.has_seconds = true;
            t_now.seconds = ts_now.tv_sec;
            t_now.has_nanos = true;
            t_now.nanos = (int32_t)ts_now.tv_nsec;

            if (types_timestamp_cmp(&t_now, context_info->until) > 0) {
                INFO("Finish response for RPC, client should exit");
                linked_list_del(it);
                sem_post(&context_info->context_sem);
                continue;
            }
        }

        if (pthread_mutex_unlock(&g_context_lists.context_mutex)) {
            WARN("Failed to unlock");
        }

        sleep(1);
    }
error:
    return NULL;
}

/* post event to events hander */
static int post_event_to_events_hander(const struct lcrd_events_format *events)
{
    int ret = 0;
    container_t *cont = NULL;

    if (events == NULL || events->id == NULL) {
        return -1;
    }

    /*only post STOPPED event to events_hander */
    if (events->type != EVENTS_TYPE_STOPPED1) {
        return 0;
    }

    cont = containers_store_get(events->id);
    if (cont == NULL) {
        ERROR("No such container:%s", events->id);
        return -1;
    }

    if (events_handler_post_events(cont->handler, events)) {
        ERROR("Failed to post events to events handler:%s", events->id);
        ret = -1;
        goto out;
    }

out:
    container_unref(cont);
    return ret;
}

/* events handler */
void events_handler(struct monitord_msg *msg)
{
    struct lcrd_events_format events = { 0 };

    if (msg == NULL) {
        ERROR("Invalid input arguments");
        return;
    }

    if (format_msg(&events, msg) != true) {
        return;
    }

    /* post events to events handler */
    if (post_event_to_events_hander(&events)) {
        ERROR("Failed to handle %s STOPPED events with pid %d", events.id, events.pid);
        return;
    }

    /* forward events to grpc clients */
    events_forward(&events);

    /* log event into lcrd.log */
    (void)write_events_log(&events);
}

/* dup event */
struct lcrd_events_format *dup_event(const struct lcrd_events_format *event)
{
    struct lcrd_events_format *out = NULL;

    if (event == NULL || event->id == NULL) {
        return NULL;
    }

    out = util_common_calloc_s(sizeof(struct lcrd_events_format));
    if (out == NULL) {
        return NULL;
    }

    event_copy(event, out);

    return out;
}

/* free event */
void free_event(struct lcrd_events_format *event)
{
    if (event == NULL) {
        return;
    }
    free(event->id);
    event->id = NULL;
    free(event);
    return;
}

/* add monitor client */
int add_monitor_client(char *name, const types_timestamp_t *since, const types_timestamp_t *until,
                       const stream_func_wrapper *stream)
{
    int ret = 0;
    struct linked_list *newnode = NULL;
    struct context_elem *context_info = NULL;

    if (stream == NULL) {
        CRIT("Should provide stream functions");
        return -1;
    }

    newnode = util_common_calloc_s(sizeof(struct linked_list));
    if (newnode == NULL) {
        CRIT("Memory allocation error.");
        return -1;
    }

    context_info = util_common_calloc_s(sizeof(struct context_elem));
    if (context_info == NULL) {
        CRIT("Memory allocation error.");
        ret = -1;
        goto free_out;
    }

    if (sem_init(&context_info->context_sem, 0, 0)) {
        ERROR("Semaphore initialization failed");
        ret = -1;
        goto free_out;
    }

    context_info->name = name;
    context_info->since = since;
    context_info->until = until;
    context_info->stream.is_cancelled = stream->is_cancelled;
    context_info->stream.context = stream->context;
    context_info->stream.write_func = stream->write_func;
    context_info->stream.writer = stream->writer;

    if (pthread_mutex_lock(&g_context_lists.context_mutex)) {
        ERROR("Failed to lock");
        ret = -1;
        goto sem_free;
    }

    linked_list_add_elem(newnode, context_info);
    linked_list_add_tail(&g_context_lists.context_list, newnode);

    if (pthread_mutex_unlock(&g_context_lists.context_mutex)) {
        WARN("Failed to unlock");
        ret = -1;
        goto sem_free;
    }

    sem_wait(&context_info->context_sem);

sem_free:
    sem_destroy(&context_info->context_sem);

free_out:
    free(context_info);
    free(newnode);
    return ret;
}

/* newcollector */
int newcollector()
{
    int ret = -1;
    pthread_t exit_thread;

    linked_list_init(&(g_context_lists.context_list));
    linked_list_init(&(g_events_buffer.event_list));
    g_events_buffer.size = 0;

    ret = pthread_mutex_init(&(g_context_lists.context_mutex), NULL);
    if (ret != 0) {
        CRIT("Mutex initialization failed");
        goto out;
    }

    ret = pthread_mutex_init(&(g_events_buffer.event_mutex), NULL);
    if (ret != 0) {
        CRIT("Mutex initialization failed");
        pthread_mutex_destroy(&(g_context_lists.context_mutex));
        goto out;
    }

    INFO("Starting collector...");
    ret = pthread_create(&exit_thread, NULL, event_should_exit, NULL);
    if (ret != 0) {
        CRIT("Thread creation failed");
        pthread_mutex_destroy(&(g_context_lists.context_mutex));
        pthread_mutex_destroy(&(g_events_buffer.event_mutex));
        goto out;
    }

    ret = 0;
out:
    return ret;
}
