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
 * Description: provide container restart manager functions
 ******************************************************************************/
#include "restartmanager.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <time.h>
#include <pthread.h>

#include "error.h"
#include "isula_libutils/log.h"
#include "isulad_config.h"
#include "utils.h"
#include "service_container_api.h"
#include "container_unix.h"

#define backoffMultipulier 2U
// unit nanos
#define defaultTimeout (100LL * Time_Milli)
#define maxRestartTimeout Time_Minute

struct restart_args {
    char *id;
    uint64_t timeout;
    int exit_code;
};

/* free restart args */
static void free_restart_args(struct restart_args *args)
{
    if (args == NULL) {
        return;
    }
    if (args->id != NULL) {
        free(args->id);
        args->id = NULL;
    }
    free(args);
}

/* container restart */
static void *container_restart(void *args)
{
    int ret = 0;
    struct restart_args *arg = args;
    char *id = arg->id;
    container_t *cont = NULL;
    const char *console_fifos[3] = { NULL, NULL, NULL };
    restart_manager_t *rm = NULL;

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        CRIT("Set thread detach fail");
        goto out;
    }

    cont = containers_store_get(id);
    if (cont == NULL) {
        INFO("Container '%s' already removed", id);
        goto out;
    }

    if (container_in_gc_progress(id)) {
        ERROR("Cannot restart container %s in garbage collector progress.", id);
        goto set_stopped;
    }

    container_lock(cont);
    rm = get_restart_manager(cont);
    container_unlock(cont);
    if (rm == NULL) {
        ERROR("Failed to get restart manager for container '%s'", id);
        goto set_stopped;
    }

    ret = restart_manager_wait_cancel(rm, arg->timeout);
    if (ret == 0) {
        INFO("Canceled to restart container '%s' cased %d", id, ret);
        goto set_stopped;
    }

    if (start_container(cont, console_fifos, false) != 0 && is_restarting(cont->state)) {
        goto set_stopped;
    }
    goto out;

set_stopped:
    container_lock(cont);
    state_set_stopped(cont->state, arg->exit_code);
    container_wait_stop_cond_broadcast(cont);
    container_unlock(cont);
out:
    container_unref(cont);
    restart_manager_unref(rm);
    free_restart_args(arg);
    DAEMON_CLEAR_ERRMSG();
    return NULL;
}

/* container restart in thread */
int container_restart_in_thread(const char *id, uint64_t timeout, int exit_code)
{
    int ret = -1;
    pthread_t td;
    struct restart_args *arg = NULL;

    if (id == NULL) {
        ERROR("Invalid input arguments");
        goto error;
    }

    arg = util_common_calloc_s(sizeof(struct restart_args));
    if (arg == NULL) {
        ERROR("Out of memory");
        goto error;
    }
    arg->id = util_strdup_s(id);
    arg->timeout = timeout;
    arg->exit_code = exit_code;

    ret = pthread_create(&td, NULL, container_restart, arg);
    if (ret != 0) {
        CRIT("Thread create failed");
        goto error;
    }

    return 0;
error:
    free_restart_args(arg);
    return -1;
}

/* restart manager lock */
static void restart_manager_lock(restart_manager_t *rm)
{
    if (pthread_mutex_lock(&rm->mutex)) {
        ERROR("Failed to lock restart manager");
    }
}

/* restart manager unlock */
static void restart_manager_unlock(restart_manager_t *rm)
{
    if (pthread_mutex_unlock(&rm->mutex)) {
        ERROR("Failed to unlock restart manager");
    }
}

/* restart manager wait cancel cond broadcast */
static void restart_manager_wait_cancel_cond_broadcast(restart_manager_t *rm)
{
    if (pthread_cond_broadcast(&rm->wait_cancel_con)) {
        ERROR("Failed to broadcast wait cancel condition container");
    }
}

/* restart manager wait cancel cond wait */
static int restart_manager_wait_cancel_cond_wait(restart_manager_t *rm, uint64_t timeout)
{
    time_t sec = 0;
    long nsec = 0;
    struct timespec ts;

    sec = (time_t)(timeout / Time_Second);
    nsec = (long)(timeout - (uint64_t)sec * Time_Second);

    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        ERROR("Failed to get real time");
        return -1;
    }

    nsec += ts.tv_nsec;

    ts.tv_sec += sec + (time_t)nsec / Time_Second;
    ts.tv_nsec = nsec % Time_Second;

    return pthread_cond_timedwait(&rm->wait_cancel_con, &rm->mutex, &ts);
}

/* restart manager wait cancel */
int restart_manager_wait_cancel(restart_manager_t *rm, uint64_t timeout)
{
    int ret = 0;

    if (rm == NULL) {
        return -1;
    }

    restart_manager_lock(rm);

    if (rm->canceled) {
        goto unlock;
    }

    ret = restart_manager_wait_cancel_cond_wait(rm, timeout);
unlock:
    restart_manager_unlock(rm);
    return ret;
}

/* restart policy free */
void restart_policy_free(host_config_restart_policy *policy)
{
    if (policy == NULL) {
        return;
    }

    free(policy->name);
    policy->name = NULL;

    free(policy);
}

/* restart manager refinc */
void restart_manager_refinc(restart_manager_t *rm)
{
    if (rm == NULL) {
        return;
    }
    atomic_int_inc(&rm->refcnt);
}

/* restart manager unref */
void restart_manager_unref(restart_manager_t *rm)
{
    bool is_zero = false;

    if (rm == NULL) {
        return;
    }

    is_zero = atomic_int_dec_test(&rm->refcnt);
    if (!is_zero) {
        return;
    }

    restart_manager_free(rm);
}

/* restart manager free */
void restart_manager_free(restart_manager_t *rm)
{
    if (rm == NULL) {
        return;
    }

    restart_policy_free(rm->policy);
    rm->policy = NULL;

    if (rm->init_wait_cancel_con) {
        pthread_cond_destroy(&rm->wait_cancel_con);
    }
    if (rm->init_mutex) {
        pthread_mutex_destroy(&rm->mutex);
    }
    free(rm);
}

/* restart manager new */
restart_manager_t *restart_manager_new(const host_config_restart_policy *policy, int failure_count)
{
    int ret;
    restart_manager_t *rm = NULL;

    rm = util_common_calloc_s(sizeof(restart_manager_t));
    if (rm == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    ret = pthread_mutex_init(&rm->mutex, NULL);
    if (ret != 0) {
        ERROR("Failed to init mutex of restart manager");
        goto cleanup;
    }
    rm->init_mutex = true;

    ret = pthread_cond_init(&rm->wait_cancel_con, NULL);
    if (ret != 0) {
        ERROR("Failed to init wait cancel condition of restart manager");
        goto cleanup;
    }
    rm->init_wait_cancel_con = true;

    atomic_int_set(&rm->refcnt, 1);
    rm->policy = util_common_calloc_s(sizeof(host_config_restart_policy));
    if (rm->policy == NULL) {
        ERROR("Out of memory");
        goto cleanup;
    }

    if (policy != NULL) {
        rm->policy->name = util_strdup_s(policy->name);
        rm->policy->maximum_retry_count = policy->maximum_retry_count;
    }

    rm->failure_count = failure_count;

    return rm;
cleanup:
    restart_manager_free(rm);
    return NULL;
}

/* restart manager set policy */
int restart_manager_set_policy(restart_manager_t *rm, const host_config_restart_policy *policy)
{
    host_config_restart_policy *newpolicy = NULL;

    if (rm == NULL || policy == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    newpolicy = util_common_calloc_s(sizeof(host_config_restart_policy));
    if (newpolicy == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    newpolicy->name = util_strdup_s(policy->name);
    newpolicy->maximum_retry_count = policy->maximum_retry_count;

    restart_manager_lock(rm);
    restart_policy_free(rm->policy);
    rm->policy = newpolicy;
    restart_manager_unlock(rm);

    return 0;
}

static void restart_manager_set_items(restart_manager_t *rm, uint32_t exit_code, int64_t exec_duration)
{
    if (exit_code != 0) {
        rm->failure_count++;
    } else {
        rm->failure_count = 0;
    }

    // if the container ran for more than 10s, regardless of status and policy reset the
    // the timeout back to the default.
    if (exec_duration >= 10) {
        rm->timeout = 0;
    }

    if (rm->timeout == 0) {
        rm->timeout = defaultTimeout;
    } else if (rm->timeout < maxRestartTimeout) {
        rm->timeout *= backoffMultipulier;
    }
    if (rm->timeout > maxRestartTimeout) {
        rm->timeout = maxRestartTimeout;
    }

    return;
}

static bool should_be_restart(const restart_manager_t *rm, uint32_t exit_code, bool has_been_manually_stopped)
{
    bool restart = false;

    if (strcmp(rm->policy->name, "always") == 0) {
        restart = true;
    } else if (strcmp(rm->policy->name, "unless-stopped") == 0 && !has_been_manually_stopped) {
        restart = true;
    } else if (strcmp(rm->policy->name, "on-failure") == 0) {
        // the default value of 0 for MaximumRetryCount means that we will not enforce a maximum count
        if (rm->policy->maximum_retry_count == 0 || rm->failure_count <= rm->policy->maximum_retry_count) {
            restart = (exit_code != 0);
        }
    } else if (strcmp(rm->policy->name, "on-reboot") == 0) {
        restart = (exit_code == 129);
    }

    return restart;
}

/* restart manager should restart */
bool restart_manager_should_restart(const char *id, uint32_t exit_code, bool has_been_manually_stopped,
                                    int64_t exec_duration, uint64_t *timeout)
{
    bool restart = false;
    restart_manager_t *rm = NULL;
    container_t *cont = NULL;

    if (id == NULL) {
        return false;
    }

    cont = containers_store_get(id);
    if (cont == NULL) {
        ERROR("No such container:%s", id);
        restart = false;
        goto out;
    }

    rm = get_restart_manager(cont);
    if (rm == NULL) {
        ERROR("Failed to get restart manager");
        restart = false;
        goto unref;
    }

    if (rm->policy == NULL || rm->policy->name == NULL) {
        restart = false;
        goto unref;
    }

    restart_manager_lock(rm);

    if (rm->canceled) {
        INFO("Restart canceled");
        restart = false;
        goto unlock;
    }

    restart_manager_set_items(rm, exit_code, exec_duration);

    restart = should_be_restart(rm, exit_code, has_been_manually_stopped);
    if (restart) {
        *timeout = (uint64_t)rm->timeout;
    }

unlock:
    restart_manager_unlock(rm);
unref:
    restart_manager_unref(rm);
    container_unref(cont);
out:
    return restart;
}

/* restart manager cancel */
int restart_manager_cancel(restart_manager_t *rm)
{
    if (rm == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    // need atomic lock ?
    restart_manager_lock(rm);
    rm->canceled = true;
    restart_manager_wait_cancel_cond_broadcast(rm);
    restart_manager_unlock(rm);
    return 0;
}
