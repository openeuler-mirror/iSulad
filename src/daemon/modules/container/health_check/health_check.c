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
 * Author: wujing
 * Create: 2018-11-1
 * Description: provide health check functions
 *********************************************************************************/
#define _GNU_SOURCE
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <isula_libutils/container_config.h>
#include <isula_libutils/container_config_v2.h>
#include <isula_libutils/container_exec_request.h>
#include <isula_libutils/container_exec_response.h>
#include <isula_libutils/defs.h>
#include <stdbool.h>
#include <stdint.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "health_check.h"
#include "service_container_api.h"
#include "log_gather_api.h"
#include "container_state.h"
#include "err_msg.h"
#include "io_wrapper.h"
#include "utils_array.h"
#include "utils_timestamp.h"

/* container state lock */
static void container_health_check_lock(health_check_manager_t *health)
{
    if (health == NULL) {
        return;
    }
    if (pthread_mutex_lock(&health->mutex)) {
        ERROR("Failed to lock health check manager");
    }
}

/* container state unlock */
static void container_health_check_unlock(health_check_manager_t *health)
{
    if (health == NULL) {
        return;
    }
    if (pthread_mutex_unlock(&health->mutex)) {
        ERROR("Failed to unlock health check manager");
    }
}

static char *get_health_status(container_state_t *s)
{
    char *status = NULL;

    if (s->state->health->status == NULL || strlen(s->state->health->status) == 0) {
        return util_strdup_s(UNHEALTHY);
    }

    container_state_lock(s);
    status = util_strdup_s(s->state->health->status);
    container_state_unlock(s);

    return status;
}

static void set_health_status(container_state_t *s, const char *new)
{
    if (s == NULL || new == NULL) {
        return;
    }
    container_state_lock(s);
    free(s->state->health->status);
    s->state->health->status = util_strdup_s(new);
    container_state_unlock(s);
}

static void set_monitor_idle_status(health_check_manager_t *health)
{
    container_health_check_lock(health);
    health->monitor_status = MONITOR_IDLE;
    container_health_check_unlock(health);
}

static void set_monitor_stop_status(health_check_manager_t *health)
{
    container_health_check_lock(health);
    health->monitor_status = MONITOR_STOP;
    container_health_check_unlock(health);
}

static void set_monitor_interval_timeout_status(health_check_manager_t *health)
{
    container_health_check_lock(health);
    health->monitor_status = MONITOR_INTERVAL;
    container_health_check_unlock(health);
}

static health_check_monitor_status_t get_health_check_monitor_state(health_check_manager_t *health)
{
    health_check_monitor_status_t ret;

    container_health_check_lock(health);
    ret = health->monitor_status;
    container_health_check_unlock(health);

    return ret;
}

static void close_health_check_monitor(const container_t *cont)
{
    if (cont == NULL || cont->health_check == NULL) {
        return;
    }
    set_monitor_stop_status(cont->health_check);
    set_health_status(cont->state, UNHEALTHY);
}

static void open_health_check_monitor(health_check_manager_t *health)
{
    set_monitor_interval_timeout_status(health);
}

// Called when the container is being stopped (whether because the health check is
// failing or for any other reason).
void container_stop_health_checks(const char *container_id)
{
    container_t *cont = NULL;

    if (container_id == NULL) {
        return;
    }

    cont = containers_store_get(container_id);
    if (cont == NULL) {
        ERROR("Failed to get container info");
        return;
    }
    if (cont->state != NULL && cont->state->state != NULL && cont->state->state->health != NULL) {
        close_health_check_monitor(cont);
    }
    container_unref(cont);
}

/* health check manager free */
void health_check_manager_free(health_check_manager_t *health_check)
{
    if (health_check == NULL) {
        return;
    }
    if (health_check->init_mutex) {
        pthread_mutex_destroy(&health_check->mutex);
    }
    free(health_check);
}

/* health check manager new */
static health_check_manager_t *health_check_manager_new()
{
    int ret;
    health_check_manager_t *health_check = NULL;

    health_check = util_common_calloc_s(sizeof(health_check_manager_t));
    if (health_check == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    ret = pthread_mutex_init(&health_check->mutex, NULL);
    if (ret != 0) {
        ERROR("Failed to init mutex of health check manager");
        goto cleanup;
    }
    health_check->init_mutex = true;

    health_check->monitor_status = MONITOR_IDLE;

    return health_check;
cleanup:
    health_check_manager_free(health_check);
    return NULL;
}

static ssize_t write_to_string(void *context, const void *data, size_t len)
{
    char *dst = (char *)context;

    if (len == 0) {
        return 0;
    }

    if (len >= REV_BUF_SIZE) {
        (void)strncpy(dst, data, REV_BUF_SIZE - 4);
        (void)strcpy(dst + REV_BUF_SIZE - 4, "...");
    } else {
        (void)strncpy(dst, data, len);
    }

    return (ssize_t)len;
}

static char **get_shell()
{
    char **shell = NULL;

    if (util_array_append(&shell, "/bin/sh") || util_array_append(&shell, "-c")) {
        ERROR("Failed to add shell, out of memory");
        util_free_array(shell);
        return NULL;
    }
    return shell;
}

static char **health_check_cmds(const container_config *config)
{
    size_t i = 0;
    size_t shell_len = 0;
    char **shell = NULL;
    char **cmd_slice = NULL;

    if (config == NULL) {
        return NULL;
    }
    shell = get_shell();
    if (shell == NULL) {
        ERROR("Failed to get shell");
        goto out;
    }

    shell_len = util_array_len((const char **)shell);
    if (shell_len > (SIZE_MAX / sizeof(char *)) - config->healthcheck->test_len) {
        ERROR("Invalid shell length");
        goto out;
    }
    cmd_slice = util_common_calloc_s((shell_len + config->healthcheck->test_len) * sizeof(char *));
    if (cmd_slice == NULL) {
        ERROR("out of memory");
        goto out;
    }
    for (i = 0; i < shell_len; i++) {
        cmd_slice[i] = util_strdup_s(shell[i]);
    }

    for (i = shell_len; i < (shell_len + config->healthcheck->test_len) - 1; i++) {
        cmd_slice[i] = util_strdup_s(config->healthcheck->test[(i - shell_len) + 1]);
    }

out:
    util_free_array(shell);
    return cmd_slice;
}

static int shift_and_store_log_result(defs_health *health, const defs_health_log_element *result)
{
    int ret = 0;
    size_t i = 0;

    for (i = 0; i < MAX_LOG_ENTRIES; i++) {
        free(health->log[i]->start);
        free(health->log[i]->end);
        free(health->log[i]->output);

        if (i != MAX_LOG_ENTRIES - 1) {
            health->log[i]->start = util_strdup_s(health->log[i + 1]->start);
            health->log[i]->end = util_strdup_s(health->log[i + 1]->end);
            health->log[i]->exit_code = health->log[i + 1]->exit_code;
            health->log[i]->output = health->log[i + 1]->output != NULL ? util_strdup_s(health->log[i + 1]->output) :
                                     NULL;
        } else {
            health->log[i]->start = util_strdup_s(result->start);
            health->log[i]->end = util_strdup_s(result->end);
            health->log[i]->exit_code = result->exit_code;
            health->log[i]->output = result->output != NULL ? util_strdup_s(result->output) : NULL;
        }
    }
    health->log_len = MAX_LOG_ENTRIES;

    return ret;
}

static int append_last_log_result(defs_health *health, const defs_health_log_element *result)
{
    int ret = 0;
    defs_health_log_element **tmp_log = NULL;
    defs_health_log_element *log = NULL;

    if (health->log_len > (SIZE_MAX / sizeof(defs_health_log_element *)) - 1) {
        ERROR("failed to realloc memory");
        return -1;
    }

    ret = mem_realloc((void **)(&tmp_log), (health->log_len + 1) * sizeof(defs_health_log_element *), health->log,
                      health->log_len * sizeof(defs_health_log_element *));
    if (ret != 0) {
        ERROR("failed to realloc memory");
        return -1;
    }
    health->log = tmp_log;
    log = util_common_calloc_s(sizeof(defs_health_log_element));
    if (log == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    log->start = util_strdup_s(result->start);
    log->end = util_strdup_s(result->end);
    log->exit_code = result->exit_code;
    log->output = result->output != NULL ? util_strdup_s(result->output) : NULL;
    health->log[health->log_len++] = log;

out:
    return ret;
}

static int handle_increment_streak(container_t *cont, int retries)
{
    int ret = 0;
    defs_health *health = NULL;

    health = cont->state->state->health;
    health->failing_streak++;
    if (health->failing_streak >= retries) {
        set_health_status(cont->state, UNHEALTHY);
        if (cont->common_config->config->healthcheck->exit_on_unhealthy) {
            // kill container when exit on unhealthy flag is set
            ret = stop_container(cont, 3, true, false);
            if (ret != 0) {
                isulad_try_set_error_message("Could not stop running container %s, cannot remove",
                                             cont->common_config->id);
                ERROR("Could not stop running container %s, cannot remove", cont->common_config->id);
                ret = -1;
            }
        }
    }
    return ret;
}

static int handle_unhealthy_case(container_t *cont, const defs_health_log_element *result, int retries)
{
    int ret = 0;
    bool should_increment_streak = true;
    char *health_status = NULL;

    health_status = get_health_status(cont->state);

    if (strcmp(health_status, HEALTH_STARTING) == 0) {
        int64_t start_period = (cont->common_config->config->healthcheck->start_period == 0) ?
                               DEFAULT_START_PERIOD :
                               cont->common_config->config->healthcheck->start_period;
        int64_t first, last;
        if (to_unix_nanos_from_str(cont->state->state->started_at, &first)) {
            ERROR("Parse container started time failed: %s", cont->state->state->started_at);
            ret = -1;
            goto out;
        }
        if (to_unix_nanos_from_str(result->start, &last)) {
            ERROR("Parse last health check start time failed: %s", result->start);
            ret = -1;
            goto out;
        }
        if (last - first < start_period) {
            should_increment_streak = false;
        }
    }
    if (should_increment_streak) {
        ret = handle_increment_streak(cont, retries);
    }
out:
    free(health_status);
    return ret;
}

static int append_health_log(container_state_t *s, const defs_health_log_element *result)
{
    int ret = 0;
    defs_health *health = NULL;

    container_state_lock(s);

    health = s->state->health;

    if (health->log_len >= MAX_LOG_ENTRIES) {
        if (shift_and_store_log_result(health, result)) {
            ERROR("failed to append last log result");
            ret = -1;
            goto out;
        }
    } else {
        if (append_last_log_result(health, result) != 0) {
            ERROR("failed to append last log result");
            ret = -1;
            goto out;
        }
    }

out:
    container_state_unlock(s);

    return ret;
}

// Update the container's Status.Health struct based on the latest probe's result.
static int handle_probe_result(const char *container_id, const defs_health_log_element *result)
{
    int ret = 0;
    int retries = 0;
    char *current = NULL;
    char *old_state = NULL;
    defs_health *health = NULL;
    container_t *cont = NULL;

    cont = containers_store_get(container_id);
    if (cont == NULL) {
        ERROR("Failed to get container info");
        return -1;
    }
    DEBUG("health check result: \n   start: %s\n    end: %s\n    output: %s\n    exit_code: %d\n", result->start,
          result->end, result->output, result->exit_code);
    // probe may have been cancelled while waiting on lock. Ignore result then
    if (get_health_check_monitor_state(cont->health_check) == MONITOR_STOP) {
        goto out;
    }
    retries = cont->common_config->config->healthcheck->retries;
    if (retries <= 0) {
        retries = DEFAULT_PROBE_RETRIES;
    }
    health = cont->state->state->health;
    old_state = get_health_status(cont->state);

    ret = append_health_log(cont->state, result);
    if (ret != 0) {
        goto out;
    }

    if (result->exit_code == EXIT_STATUS_HEALTHY) {
        health->failing_streak = 0;
        set_health_status(cont->state, HEALTHY);
    } else {
        if (handle_unhealthy_case(cont, result, retries)) {
            ERROR("failed to handle unhealthy case");
            ret = -1;
            goto out;
        }
        // else we're starting or healthy. Stay in that state.
    }
    // note: replicate Health status changes
    current = get_health_status(cont->state);
    if (strcmp(old_state, current) != 0) {
        // note: event
        EVENT("EVENT: {Object: %s, health_status: %s}", cont->common_config->id, current);
    }
    if (container_to_disk(cont)) {
        ERROR("Failed to save container \"%s\" to disk", cont->common_config->id);
        ret = -1;
    }
out:
    free(old_state);
    free(current);
    container_unref(cont);

    return ret;
}
static void health_check_exec_failed_handle(const container_exec_response *container_res,
                                            defs_health_log_element *result)
{
    if (container_res != NULL) {
        if (container_res->errmsg != NULL) {
            ERROR("%s, Exit code: %d", container_res->errmsg, (int)container_res->exit_code);
            result->output = util_strdup_s(container_res->errmsg);
        } else {
            ERROR("Execution of exec failed, Exit code: %d", (int)container_res->exit_code);
            result->output = util_strdup_s("Execution of exec failed");
        }
    } else {
        ERROR("Failed to call exec container callback");
        result->output = util_strdup_s("Failed to call exec container callback");
    }
    result->exit_code = -1;
}

static void health_check_exec_success_handle(const container_exec_response *container_res,
                                             defs_health_log_element *result, const char *output)
{
    result->output = util_strdup_s(output);
    if (container_res != NULL) {
        result->exit_code = (int)container_res->exit_code;
    } else {
        result->exit_code = -1;
    }
}

// exec the healthcheck command in the container.
// Returns the exit code and probe output (if any)
void *health_check_run(void *arg)
{
    int ret = 0;
    char *container_id = NULL;
    char **cmd_slice = NULL;
    char output[REV_BUF_SIZE] = { 0 };
    char timebuffer[TIME_STR_SIZE] = { 0 };
    struct io_write_wrapper Stdoutctx = { 0 };
    struct io_write_wrapper Stderrctx = { 0 };
    container_t *cont = NULL;
    container_exec_request *container_req = NULL;
    container_exec_response *container_res = NULL;
    defs_health_log_element *result = NULL;
    container_config *config = NULL;

    if (arg == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }

    container_id = util_strdup_s((char *)arg);

    cont = containers_store_get(container_id);
    if (cont == NULL) {
        ERROR("Failed to get container info");
        goto out;
    }

    config = cont->common_config->config;

    cmd_slice = health_check_cmds(config);
    if (cmd_slice == NULL) {
        ERROR("Failed to get health check cmds");
        goto out;
    }

    container_req = (container_exec_request *)util_common_calloc_s(sizeof(container_exec_request));
    if (container_req == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    container_res = (container_exec_response *)util_common_calloc_s(sizeof(container_exec_response));
    if (container_res == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    // Set tty to true, compatible with busybox
    container_req->tty = true;
    container_req->attach_stdin = false;
    container_req->attach_stdout = true;
    container_req->attach_stderr = true;
    container_req->timeout =
        ((config->healthcheck->timeout == 0) ? DEFAULT_PROBE_TIMEOUT : config->healthcheck->timeout) / Time_Second;
    container_req->container_id = util_strdup_s(cont->common_config->id);
    container_req->argv = cmd_slice;
    container_req->argv_len = util_array_len((const char **)cmd_slice);
    cmd_slice = NULL;
    EVENT("EVENT: {Object: %s, Type:  Health checking}", cont->common_config->id);

    (void)get_now_time_buffer(timebuffer, sizeof(timebuffer));
    result = util_common_calloc_s(sizeof(defs_health_log_element));
    if (result == NULL) {
        ERROR("Out of memory");
        goto out;
    }
    result->start = util_strdup_s(timebuffer);

    Stdoutctx.context = (void *)output;
    Stdoutctx.write_func = write_to_string;
    Stdoutctx.close_func = NULL;
    Stderrctx.context = (void *)output;
    Stderrctx.write_func = write_to_string;
    Stderrctx.close_func = NULL;
    ret = exec_container(cont, container_req, container_res, -1, &Stdoutctx, &Stderrctx);
    if (ret != 0) {
        health_check_exec_failed_handle(container_res, result);
    } else {
        health_check_exec_success_handle(container_res, result, output);
    }

    (void)get_now_time_buffer(timebuffer, sizeof(timebuffer));
    result->end = util_strdup_s(timebuffer);

    if (handle_probe_result(cont->common_config->id, result) != 0) {
        ERROR("Failed to handle probe result");
    }

out:
    util_free_array(cmd_slice);
    free(container_id);
    container_id = NULL;
    free_defs_health_log_element(result);
    free_container_exec_request(container_req);
    free_container_exec_response(container_res);
    container_unref(cont);
    return NULL;
}

// Get a suitable probe implementation for the container's healthcheck configuration.
// Nil will be returned if no healthcheck was configured or NONE was set.
static health_probe_t get_probe(const container_t *cont)
{
    defs_health_check *config = cont->common_config->config->healthcheck;

    if (config == NULL || config->test_len == 0) {
        return HEALTH_NONE;
    }

    if (strcmp(config->test[0], "CMD") == 0) {
        return CMD;
    } else if (strcmp(config->test[0], "CMD-SHELL") == 0) {
        return CMD_SHELL;
    } else if (strcmp(config->test[0], "NONE") == 0) {
        return HEALTH_NONE;
    } else {
        WARN("Unknown healthcheck type '%s' (expected 'CMD') in container %s", config->test[0],
             cont->common_config->id);
        return HEALTH_NONE;
    }
}

static int do_monitor_interval(const char *container_id, health_check_manager_t *health_check,
                               types_timestamp_t *start_timestamp)
{
    int ret = 0;
    pthread_t exec_tid = { 0 };

    if (pthread_create(&exec_tid, NULL, health_check_run, (void *)container_id)) {
        ERROR("Failed to create thread to exec health check");
        ret = -1;
        goto out;
    }
    if (pthread_join(exec_tid, NULL) < 0) {
        ERROR("Failed to run health check thread");
        ret = -1;
        goto out;
    }
    if (get_health_check_monitor_state(health_check) == MONITOR_STOP) {
        ret = 0;
        goto out;
    }
    set_monitor_idle_status(health_check);
    if (get_now_time_stamp(start_timestamp) == false) {
        ERROR("Failed to get time stamp");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static int do_monitor_default(int64_t probe_interval, health_check_manager_t *health_check,
                              const types_timestamp_t *start_timestamp, types_timestamp_t *last_timestamp)
{
    int64_t time_interval = 0;

    if (get_now_time_stamp(last_timestamp) == false) {
        ERROR("Failed to get time stamp");
        return -1;
    }

    if (get_time_interval(*start_timestamp, *last_timestamp, &time_interval)) {
        ERROR("Failed to get time interval");
        return -1;
    }

    if (time_interval >= probe_interval) {
        set_monitor_interval_timeout_status(health_check);
    }
    usleep_nointerupt(500);

    return 0;
}
// Run the container's monitoring thread until notified via "stop".
// There is never more than one monitor thread running per container at a time.
static void *health_check_monitor(void *arg)
{
    char *container_id = NULL;
    int64_t probe_interval = 0;
    container_t *cont = NULL;
    types_timestamp_t start_timestamp = { 0 };
    types_timestamp_t last_timestamp = { 0 };

    if ((char *)arg == NULL) {
        ERROR("Container id is empty");
        return NULL;
    }
    container_id = util_strdup_s((char *)arg);

    cont = containers_store_get(container_id);
    if (cont == NULL) {
        ERROR("Failed to get container info");
        goto out;
    }

    if (get_now_time_stamp(&start_timestamp) == false) {
        ERROR("Failed to monitor start time stamp");
        goto out;
    }
    probe_interval = (cont->common_config->config->healthcheck->interval == 0) ?
                     DEFAULT_PROBE_INTERVAL :
                     cont->common_config->config->healthcheck->interval;
    set_monitor_idle_status(cont->health_check);
    while (true) {
        switch (get_health_check_monitor_state(cont->health_check)) {
            case MONITOR_STOP:
                DEBUG("Stop healthcheck monitoring for container %s (received while idle)", cont->common_config->id);
                goto out;
            /* fall-through */
            case MONITOR_INTERVAL:
                if (do_monitor_interval(container_id, cont->health_check, &start_timestamp)) {
                    goto out;
                }
                break;
            case MONITOR_IDLE:
            /* fall-through */
            default:
                if (do_monitor_default(probe_interval, cont->health_check, &start_timestamp, &last_timestamp)) {
                    goto out;
                }
                break;
        }
    }
out:
    free(container_id);
    container_id = NULL;
    container_unref(cont);
    return NULL;
}

// Ensure the health-check monitor is running or not, depending on the current
// state of the container.
// Called from monitor.go, with c locked.
void container_update_health_monitor(const char *container_id)
{
    bool want_running = false;
    container_t *cont = NULL;
    defs_health *health = NULL;
    health_probe_t probe;

    if (container_id == NULL) {
        return;
    }
    cont = containers_store_get(container_id);
    if (cont == NULL) {
        ERROR("Failed to get container info");
        return;
    }

    health = cont->state->state->health;
    if (health == NULL) {
        goto out;
    }
    probe = get_probe(cont);
    want_running = cont->state->state->running && !cont->state->state->paused && probe != HEALTH_NONE;

    if (want_running) {
        open_health_check_monitor(cont->health_check);
        pthread_t monitor_tid = { 0 };
        if (pthread_create(&monitor_tid, NULL, health_check_monitor, (void *)container_id)) {
            ERROR("Failed to create thread to monitor health check...");
            goto out;
        }
        if (pthread_detach(monitor_tid)) {
            ERROR("Failed to detach the health check monitor thread");
            goto out;
        }
    } else {
        close_health_check_monitor(cont);
    }

out:
    container_unref(cont);
}

// Reset the health state for a newly-started, restarted or restored container.
// initHealthMonitor is called from monitor.go and we should never be running
// two instances at once.
// Note: Called with container locked.
void container_init_health_monitor(const char *id)
{
    container_t *cont = NULL;

    cont = containers_store_get(id);
    if (cont == NULL) {
        ERROR("Failed to get container info");
        return;
    }

    if (cont->common_config->config->healthcheck == NULL || cont->common_config->config->healthcheck->test == NULL) {
        goto out;
    }

    if (cont->health_check == NULL) {
        cont->health_check = health_check_manager_new();
        if (cont->health_check == NULL) {
            ERROR("Out of memory");
            goto out;
        }
    }

    // If no healthcheck is setup then don't init the monitor
    if (get_probe(cont) == HEALTH_NONE) {
        goto out;
    }
    // This is needed in case we're auto-restarting
    container_stop_health_checks(cont->common_config->id);
    if (cont->state == NULL || cont->state->state == NULL) {
        goto out;
    }

    if (cont->state->state->health != NULL) {
        set_health_status(cont->state, HEALTH_STARTING);
        cont->state->state->health->failing_streak = 0;
    } else {
        cont->state->state->health = util_common_calloc_s(sizeof(defs_health));
        if (cont->state->state->health == NULL) {
            ERROR("out of memory");
            goto out;
        }
        set_health_status(cont->state, HEALTH_STARTING);
    }

    if (container_to_disk(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        goto out;
    }

    container_update_health_monitor(id);

out:
    container_unref(cont);
    return;
}
