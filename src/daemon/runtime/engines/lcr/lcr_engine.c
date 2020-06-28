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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container lcr engine functions
 ******************************************************************************/
#include "lcr_engine.h"

#include <dlfcn.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <lcr/lcrcontainer.h>

#include "error.h"
#include "engine.h"
#include "isula_libutils/log.h"
#include "isulad_config.h"

typedef bool (*lcr_state_op_t)(const char *name, const char *lcrpath, struct lcr_container_state *lcs);
typedef void (*lcr_container_state_free_t)(struct lcr_container_state *lcs);
typedef bool (*lcr_update_op_t)(const char *name, const char *lcrpath, struct lcr_cgroup_resources *cr);
typedef bool (*lcr_start_op_t)(struct lcr_start_request *request);
typedef bool (*lcr_exec_op_t)(const struct lcr_exec_request *request, int *exit_code);

static lcr_state_op_t g_lcr_state_op = NULL;
static lcr_container_state_free_t g_lcr_container_state_free_op = NULL;
static lcr_update_op_t g_lcr_update_op = NULL;
static lcr_start_op_t g_lcr_start_op = NULL;
static lcr_exec_op_t g_lcr_exec_op = NULL;
/*
 * Trans the lcr_state_t to Status
 */
static Runtime_Container_Status lcrsta2sta(const char *state)
{
    Runtime_Container_Status status = RUNTIME_CONTAINER_STATUS_UNKNOWN;

    if (state == NULL) {
        WARN("Empty string of state");
        return status;
    }

    if (strcmp("STOPPED", state) == 0) {
        status = RUNTIME_CONTAINER_STATUS_STOPPED;
    } else if ((strcmp("STARTING", state) == 0) || (strcmp("STOPPING", state) == 0)) {
        status = RUNTIME_CONTAINER_STATUS_CREATED;
    } else if (strcmp("RUNNING", state) == 0) {
        status = RUNTIME_CONTAINER_STATUS_RUNNING;
    } else if ((strcmp("ABORTING", state) == 0) || (strcmp("FREEZING", state) == 0) || (strcmp("FROZEN", state) == 0) ||
               (strcmp("THAWED", state) == 0)) {
        status = RUNTIME_CONTAINER_STATUS_PAUSED;
    } else {
        DEBUG("invalid state '%s'", state);
        status = RUNTIME_CONTAINER_STATUS_UNKNOWN;
    }

    return status;
}

/* lcr update container */
static bool lcr_update_container(const char *name, const char *lcrpath, const struct engine_cgroup_resources *cr)
{
    struct lcr_cgroup_resources lcr_cr;

    if (g_lcr_update_op == NULL) {
        ERROR("Not supported update operation");
        return false;
    }

    if (cr == NULL) {
        ERROR("Empty configs for update");
        return false;
    }

    (void)memset(&lcr_cr, 0, sizeof(struct lcr_cgroup_resources));

    lcr_cr.blkio_weight = cr->blkio_weight;
    lcr_cr.cpu_shares = cr->cpu_shares;
    lcr_cr.cpu_period = cr->cpu_period;
    lcr_cr.cpu_quota = cr->cpu_quota;
    lcr_cr.cpuset_cpus = cr->cpuset_cpus;
    lcr_cr.cpuset_mems = cr->cpuset_mems;
    lcr_cr.memory_limit = cr->memory_limit;
    lcr_cr.memory_swap = cr->memory_swap;
    lcr_cr.memory_reservation = cr->memory_reservation;
    lcr_cr.kernel_memory_limit = cr->kernel_memory_limit;

    return g_lcr_update_op(name, lcrpath, &lcr_cr);
}

static bool lcr_start_container(const engine_start_request_t *request)
{
    struct lcr_start_request *lcr_request = (struct lcr_start_request *)request;

    return g_lcr_start_op(lcr_request);
}

static bool lcr_exec_container(const engine_exec_request_t *request, int *exit_code)
{
    struct lcr_exec_request *lcr_request = (struct lcr_exec_request *)request;

    return g_lcr_exec_op(lcr_request, exit_code);
}

/*
 * Get the state of container from 'lcr_container_state'
 */
static void copy_container_status(const struct lcr_container_state *lcs, struct runtime_container_status_info *status)
{
    (void)memset(status, 0, sizeof(struct runtime_container_status_info));

    status->has_pid = (-1 == lcs->init) ? false : true;
    status->pid = (uint32_t)lcs->init;

    status->status = lcrsta2sta(lcs->state);
}

/* get container status */
static int get_container_status(const char *name, const char *enginepath, struct runtime_container_status_info *status)
{
    struct lcr_container_state lcs = { 0 };

    if (g_lcr_state_op == NULL || g_lcr_container_state_free_op == NULL) {
        ERROR("Not supported op");
        return -1;
    }

    if (!g_lcr_state_op(name, enginepath, &lcs)) {
        DEBUG("Failed to state for container '%s'", name);
        g_lcr_container_state_free_op(&lcs);
        return -1;
    }
    copy_container_status(&lcs, status);
    g_lcr_container_state_free_op(&lcs);
    return 0;
}

static void copy_container_resources_stats(const struct lcr_container_state *lcs,
                                           struct runtime_container_resources_stats_info *rs_stats)
{
    (void)memset(rs_stats, 0, sizeof(struct runtime_container_resources_stats_info));
    rs_stats->pids_current = lcs->pids_current;

    rs_stats->cpu_use_nanos = lcs->cpu_use_nanos;

    rs_stats->blkio_read = lcs->io_service_bytes.read;
    rs_stats->blkio_write = lcs->io_service_bytes.write;

    rs_stats->mem_used = lcs->mem_used;
    rs_stats->mem_limit = lcs->mem_limit;
    rs_stats->kmem_used = lcs->kmem_used;
    rs_stats->kmem_limit = lcs->kmem_limit;
}

/* get container cgroup resources */
static int lcr_get_container_resources_stats(const char *name, const char *enginepath,
                                             struct runtime_container_resources_stats_info *rs_stats)
{
    struct lcr_container_state lcs = { 0 };

    if (g_lcr_state_op == NULL || g_lcr_container_state_free_op == NULL) {
        ERROR("Not supported op");
        return -1;
    }

    if (!g_lcr_state_op(name, enginepath, &lcs)) {
        DEBUG("Failed to state for container '%s'", name);
        g_lcr_container_state_free_op(&lcs);
        return -1;
    }
    copy_container_resources_stats(&lcs, rs_stats);
    g_lcr_container_state_free_op(&lcs);
    return 0;
}

static bool load_lcr_exec_ops(void *lcr_handler, struct engine_operation *eop)
{
    eop->engine_create_op = dlsym(lcr_handler, "lcr_create");
    if (dlerror() != NULL) {
        return false;
    }
    g_lcr_start_op = dlsym(lcr_handler, "lcr_start");
    if (dlerror() != NULL) {
        return false;
    }
    g_lcr_update_op = dlsym(lcr_handler, "lcr_update");
    if (dlerror() != NULL) {
        return false;
    }
    eop->engine_pause_op = dlsym(lcr_handler, "lcr_pause");
    if (dlerror() != NULL) {
        return false;
    }
    eop->engine_resume_op = dlsym(lcr_handler, "lcr_resume");
    if (dlerror() != NULL) {
        return false;
    }
    eop->engine_clean_op = dlsym(lcr_handler, "lcr_clean");
    if (dlerror() != NULL) {
        return false;
    }
    eop->engine_delete_op = dlsym(lcr_handler, "lcr_delete");
    if (dlerror() != NULL) {
        return false;
    }
    g_lcr_exec_op = dlsym(lcr_handler, "lcr_exec");
    if (dlerror() != NULL) {
        return false;
    }
    eop->engine_console_op = dlsym(lcr_handler, "lcr_console");
    if (dlerror() != NULL) {
        return false;
    }
    eop->engine_resize_op = dlsym(lcr_handler, "lcr_resize");
    if (dlerror() != NULL) {
        return false;
    }
    eop->engine_exec_resize_op = dlsym(lcr_handler, "lcr_exec_resize");
    if (dlerror() != NULL) {
        return false;
    }
    return true;
}

static bool load_lcr_info_ops(void *lcr_handler, struct engine_operation *eop)
{
    eop->engine_get_errmsg_op = dlsym(lcr_handler, "lcr_get_errmsg");
    if (dlerror() != NULL) {
        return false;
    }
    eop->engine_clear_errmsg_op = dlsym(lcr_handler, "lcr_free_errmsg");
    if (dlerror() != NULL) {
        return false;
    }
    eop->engine_get_container_pids_op = dlsym(lcr_handler, "lcr_get_container_pids");
    if (dlerror() != NULL) {
        return false;
    }
    g_lcr_state_op = dlsym(lcr_handler, "lcr_state");
    if (dlerror() != NULL) {
        return false;
    }
    g_lcr_container_state_free_op = dlsym(lcr_handler, "lcr_container_state_free");
    if (dlerror() != NULL) {
        return false;
    }
    return true;
}

/* lcr engine init */
struct engine_operation *lcr_engine_init()
{
    void *lcr_handler = NULL;
    struct engine_operation *eop = NULL;
    lcr_handler = dlopen("liblcr.so", RTLD_NOW);
    if (lcr_handler == NULL) {
        ERROR("Plugin error: %s", dlerror());
        return NULL;
    }

    eop = util_common_calloc_s(sizeof(struct engine_operation));
    if (eop == NULL) {
        ERROR("Failed to alloc memeory for engine_operation");
        goto badcleanup;
    }

    eop->engine_type = util_strdup_s("lcr");

    eop->engine_log_init_op = dlsym(lcr_handler, "lcr_log_init");
    if (dlerror() != NULL) {
        ERROR("Load lcr log_init operations failed");
        goto badcleanup;
    }

    if (!load_lcr_exec_ops(lcr_handler, eop)) {
        ERROR("Load lcr exec operations failed");
        goto badcleanup;
    }

    if (!load_lcr_info_ops(lcr_handler, eop)) {
        ERROR("Load lcr info operations failed");
        goto badcleanup;
    }
    eop->engine_get_container_status_op = get_container_status;
    eop->engine_get_container_resources_stats_op = lcr_get_container_resources_stats;
    eop->engine_update_op = lcr_update_container;
    eop->engine_start_op = lcr_start_container;
    eop->engine_exec_op = lcr_exec_container;

    goto cleanup;

badcleanup:
    dlclose(lcr_handler);
    if (eop != NULL) {
        engine_operation_free(eop);
        free(eop);
        eop = NULL;
    }
cleanup:
    return eop;
}
