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
#include "isula_libutils/log.h"
#include "collector.h"
#include "isulad_config.h"
#include "libisulad.h"
#include "containers_store.h"
#include "event_type.h"

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

    nret = snprintf(regexp, len, "^%s$", id);
    if ((size_t)nret >= len || nret < 0) {
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

static const char * const g_isulad_event_strtype[] = {
    "exit",     "die",     "starting", "running", "stopping", "aborting",     "freezing",       "frozen",
    "thawed",   "oom",     "create",   "start",   "restart",  "stop",         "exec_create",    "exec_start",
    "exec_die", "attach",  "kill",     "top",     "reanme",   "archive-path", "extract-to-dir", "update",
    "pause",    "unpause", "export",   "resize",  "paused1",
};

/* isulad event sta2str */
static const char *isulad_event_sta2str(container_events_type_t sta)
{
    if (sta > EVENTS_TYPE_PAUSED1) {
        return NULL;
    }

    return g_isulad_event_strtype[sta];
}

static const char * const g_isulad_image_event_strtype[] = { "load", "remove", "pull", "login", "logout" };

static const char *isulad_image_event_sta2str(image_events_type_t sta)
{
    if (sta > EVENTS_TYPE_IMAGE_LOGOUT) {
        return NULL;
    }

    return g_isulad_image_event_strtype[sta];
}

static void supplement_msg_for_events_handler(const struct monitord_msg *msg, struct isulad_events_format *format_msg)
{
    if (msg->pid != -1) {
        format_msg->has_pid = true;
        format_msg->pid = (uint32_t)msg->pid;
    }

    format_msg->has_type = true;
    format_msg->type = lcrsta2Evetype(msg->value);
    if (format_msg->type == EVENTS_TYPE_STOPPED1) {
        format_msg->has_exit_status = true;
        if (msg->exit_code >= 0) {
            format_msg->exit_status = (uint32_t)msg->exit_code;
        } else {
            format_msg->exit_status = 125;
        }
    }
}

static int supplement_operator_for_container_msg(const struct monitord_msg *msg,
                                                 struct isulad_events_format *format_msg)
{
#define CONTAINER_OPERATOR_MAX_LEN 300
    int nret = 0;
    char opt[CONTAINER_OPERATOR_MAX_LEN] = { 0x00 };

    if (strlen(msg->args) != 0) {
        nret = snprintf(opt, sizeof(opt), "container %s: %s", isulad_event_sta2str(msg->value), msg->args);
    } else {
        nret = snprintf(opt, sizeof(opt), "container %s", isulad_event_sta2str(msg->value));
    }
    if (nret < 0 || nret >= sizeof(opt)) {
        return -1;
    }

    free(format_msg->opt);
    format_msg->opt = util_strdup_s(opt);

    return 0;
}

static int supplement_pid_for_container_msg(const container_t *cont, const struct monitord_msg *msg,
                                            struct isulad_events_format *format_msg)
{
    int nret = 0;
    char info[EVENT_EXTRA_ANNOTATION_MAX] = { 0x00 };

    if (cont->state == NULL || cont->state->state == NULL || cont->state->state->pid <= 0) {
        return 0;
    }

    nret = snprintf(info, sizeof(info), "pid=%u", cont->state->state->pid);
    if (nret < 0 || nret >= sizeof(info)) {
        return -1;
    }

    if (util_array_append(&format_msg->annotations, info) != 0) {
        ERROR("Out of memory");
        return -1;
    }

    return 0;
}

static int supplement_exitcode_for_container_msg(const container_t *cont, const struct monitord_msg *msg,
                                                 struct isulad_events_format *format_msg)
{
    int nret = 0;
    int exit_code = 0;
    char info[EVENT_EXTRA_ANNOTATION_MAX] = { 0x00 };

    if (format_msg->exit_status != 0) {
        exit_code = format_msg->exit_status;
    } else if (cont->state != NULL && cont->state->state != NULL && cont->state->state->exit_code != 0) {
        exit_code = cont->state->state->exit_code;
    }

    if (exit_code == 0) {
        return 0;
    }

    nret = snprintf(info, sizeof(info), "exitCode=%u", exit_code);
    if (nret < 0 || nret >= sizeof(info)) {
        return -1;
    }

    if (util_array_append(&format_msg->annotations, info) != 0) {
        ERROR("Out of memory");
        return -1;
    }

    return 0;
}

static int supplement_image_for_container_msg(const container_t *cont, const struct monitord_msg *msg,
                                              struct isulad_events_format *format_msg)
{
    int nret = 0;
    char info[EVENT_EXTRA_ANNOTATION_MAX] = { 0x00 };

    if (cont->common_config == NULL || cont->common_config->image == NULL) {
        return 0;
    }

    nret = snprintf(info, sizeof(info), "image=%s", cont->common_config->image);
    if (nret < 0 || nret >= sizeof(info)) {
        return -1;
    }

    if (util_array_append(&format_msg->annotations, info) != 0) {
        ERROR("Out of memory");
        return -1;
    }

    return 0;
}

static int supplement_name_for_container_msg(const container_t *cont, const struct monitord_msg *msg,
                                             struct isulad_events_format *format_msg)
{
    int nret = 0;
    char info[EVENT_EXTRA_ANNOTATION_MAX] = { 0x00 };

    if (cont->common_config == NULL || cont->common_config->name == NULL) {
        return 0;
    }

    nret = snprintf(info, sizeof(info), "name=%s", cont->common_config->name);
    if (nret < 0 || nret >= sizeof(info)) {
        return -1;
    }

    if (util_array_append(&format_msg->annotations, info) != 0) {
        ERROR("Out of memory");
        return -1;
    }

    return 0;
}

static int supplement_labels_for_container_msg(const container_t *cont, const struct monitord_msg *msg,
                                               struct isulad_events_format *format_msg)
{
    size_t i;

    if (cont->common_config == NULL || cont->common_config->config->labels == NULL ||
        cont->common_config->config->labels->len == 0) {
        return 0;
    }

    for (i = 0; i < cont->common_config->config->labels->len; i++) {
        char info[EVENT_EXTRA_ANNOTATION_MAX] = { 0x00 };
        int nret = snprintf(info, sizeof(info), "%s=%s", cont->common_config->config->labels->keys[i],
                            cont->common_config->config->labels->values[i]);
        if (nret < 0 || nret >= sizeof(info)) {
            return -1;
        }

        if (util_array_append(&format_msg->annotations, info) != 0) {
            ERROR("Out of memory");
            return -1;
        }
    }

    return 0;
}

static int supplement_annotations_for_container_msg(const container_t *cont, const struct monitord_msg *msg,
                                                    struct isulad_events_format *format_msg)
{
    if (supplement_pid_for_container_msg(cont, msg, format_msg) != 0) {
        ERROR("Failed to supplement pid info");
        return -1;
    }

    if (supplement_exitcode_for_container_msg(cont, msg, format_msg) != 0) {
        ERROR("Failed to supplement exitCode info");
        return -1;
    }

    if (supplement_image_for_container_msg(cont, msg, format_msg) != 0) {
        ERROR("Failed to supplement image info");
        return -1;
    }

    if (supplement_name_for_container_msg(cont, msg, format_msg) != 0) {
        ERROR("Failed to supplement name info");
        return -1;
    }

    if (supplement_labels_for_container_msg(cont, msg, format_msg) != 0) {
        ERROR("Failed to supplement label info");
        return -1;
    }

    if (strlen(msg->extra_annations) != 0) {
        if (util_array_append(&format_msg->annotations, msg->extra_annations) != 0) {
            ERROR("Failed to supplement extra annations info");
            return -1;
        }
    }

    format_msg->annotations_len = util_array_len((const char **)format_msg->annotations);

    return 0;
}

static int supplement_msg_for_container(struct monitord_msg *msg, struct isulad_events_format *format_msg)
{
    int ret = 0;
    container_t *cont = containers_store_get(msg->name);
    if (cont == NULL) {
        ERROR("No such container:%s", msg->name);
        ret = -1;
        goto out;
    }

    // pid & exit_status parameter for events handler
    supplement_msg_for_events_handler(msg, format_msg);

    if (cont->common_config != NULL && cont->common_config->id != NULL) {
        format_msg->id = util_strdup_s(cont->common_config->id);
    }

    if (supplement_operator_for_container_msg(msg, format_msg) != 0) {
        ERROR("Failed to supplement operator info");
        ret = -1;
        goto out;
    }

    if (supplement_annotations_for_container_msg(cont, msg, format_msg) != 0) {
        ERROR("Failed to supplement annotations info");
        ret = -1;
        goto out;
    }

out:
    container_unref(cont);
    return ret;
}

static int supplement_msg_for_image(struct monitord_msg *msg, struct isulad_events_format *format_msg)
{
#define IMAGE_OPERATOR_MAX_LEN 50
    int ret = 0;
    int nret = 0;
    char opt[IMAGE_OPERATOR_MAX_LEN] = { 0x00 };

    format_msg->id = util_strdup_s(msg->name);

    nret = snprintf(opt, sizeof(opt), "image %s", isulad_image_event_sta2str(msg->value));
    if (nret < 0 || nret >= sizeof(opt)) {
        ERROR("Get operator operator info failed");
        ret = -1;
        goto out;
    }
    format_msg->opt = util_strdup_s(opt);

out:
    return ret;
}

/* format_msg */
static bool format_msg(struct isulad_events_format *r, struct monitord_msg *msg)
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
        case MONITORD_MSG_STATE:
            if (msg->event_type == CONTAINER_EVENT) {
                supplement_msg_for_container(msg, r);
            } else if (msg->event_type == IMAGE_EVENT) {
                supplement_msg_for_image(msg, r);
            }
            ret = true;
            break;
        case MONITORD_MSG_PRIORITY:
        case MONITORD_MSG_EXIT_CODE:
        default:
            /* ignore garbage */
            ret = false;
            DEBUG("Ignore received %d event", msg->type);
            break;
    }
    return ret;
}

static int calculate_annaotation_info_len(const struct isulad_events_format *events)
{
    size_t i;
    size_t len = 0;
    for (i = 0; i < events->annotations_len; i++) {
        len += strlen(events->annotations[i]);
    }
    len += events->annotations_len * 2; // length of ", " and "()"
    len += 1; // length of '\0'

    return len;
}

/* write events log */
static int write_events_log(const struct isulad_events_format *events)
{
    int ret = 0;
    size_t i;
    char *annotation = NULL;
    size_t len = 0;
    if (events == NULL) {
        goto out;
    }

    len = calculate_annaotation_info_len(events);
    if (len == 1) {
        EVENT("Event: {Object: %s, Type: %s}", events->id, events->opt);
    } else {
        annotation = (char *)util_common_calloc_s(len);
        if (annotation == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }

        (void)strcat(annotation, "(");
        for (i = 0; i < events->annotations_len; i++) {
            (void)strcat(annotation, events->annotations[i]);
            if (i != events->annotations_len - 1) {
                (void)strcat(annotation, ", ");
            }
        }
        (void)strcat(annotation, ")");

        EVENT("Event: {Object: %s, Type: %s %s}", events->id, events->opt, annotation);
    }

out:
    free(annotation);
    return ret;
}

/* events append */
static void events_append(const struct isulad_events_format *event)
{
    struct isulad_events_format *tmpevent = NULL;
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

        tmpevent = util_common_calloc_s(sizeof(struct isulad_events_format));
        if (tmpevent == NULL) {
            CRIT("Memory allocation error.");
            free(newnode);
            goto unlock;
        }

        if (event_copy(event, tmpevent) != 0) {
            CRIT("Failed to copy event.");
            isulad_events_format_free(tmpevent);
            free(newnode);
            goto unlock;
        }

        linked_list_add_elem(newnode, tmpevent);
        linked_list_add_tail(&g_events_buffer.event_list, newnode);
        g_events_buffer.size++;
    } else {
        firstnode = linked_list_first_node(&g_events_buffer.event_list);
        if (firstnode != NULL) {
            linked_list_del(firstnode);

            tmpevent = (struct isulad_events_format *)firstnode->elem;
            if (event_copy(event, tmpevent) != 0) {
                CRIT("Failed to copy event.");
                goto unlock;
            }

            linked_list_add_tail(&g_events_buffer.event_list, firstnode);
        }
    }

unlock:
    if (pthread_mutex_unlock(&g_events_buffer.event_mutex)) {
        WARN("Failed to unlock");
        return;
    }
}

static int do_write_events(const stream_func_wrapper *stream, struct isulad_events_format *event)
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

static int check_since_time(const types_timestamp_t *since, const struct isulad_events_format *event)
{
    if (since != NULL && (since->has_seconds || since->has_nanos)) {
        if (types_timestamp_cmp(&event->timestamp, since) < 0) {
            return -1;
        }
    }
    return 0;
}

static int check_util_time(const types_timestamp_t *until, const struct isulad_events_format *event)
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
    struct isulad_events_format *c_event = NULL;

    if (pthread_mutex_lock(&g_events_buffer.event_mutex)) {
        WARN("Failed to lock");
        return -1;
    }

    linked_list_for_each_safe(it, &g_events_buffer.event_list, next) {
        c_event = (struct isulad_events_format *)it->elem;

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
static void events_forward(struct isulad_events_format *r)
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
static int post_event_to_events_hander(const struct isulad_events_format *events)
{
    int ret = 0;

    if (events == NULL || events->id == NULL) {
        return -1;
    }

    /* only post STOPPED event to events_hander */
    if (events->type != EVENTS_TYPE_STOPPED1) {
        return 0;
    }

    if (events_handler_post_events(events)) {
        ERROR("Failed to post events to events handler:%s", events->id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/* events handler */
void events_handler(struct monitord_msg *msg)
{
    struct isulad_events_format *events = NULL;

    if (msg == NULL) {
        ERROR("Invalid input arguments");
        return;
    }

    events = (struct isulad_events_format *)util_common_calloc_s(sizeof(struct isulad_events_format));
    if (events == NULL) {
        ERROR("Out of memory");
        return;
    }

    if (format_msg(events, msg) != true) {
        ERROR("Failed to format massage");
        goto out;
    }

    /* post events to events handler */
    if (post_event_to_events_hander(events)) {
        ERROR("Failed to handle %s STOPPED events with pid %d", events->id, msg->pid);
        goto out;
    }

    /* forward events to grpc clients */
    events_forward(events);

    /* log event into isulad.log */
    (void)write_events_log(events);

out:
    isulad_events_format_free(events);
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
