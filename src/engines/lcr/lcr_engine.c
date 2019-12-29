/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
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
#include "log.h"
#include "lcrd_config.h"

typedef int(*lcr_list_all_containers_t)(const char *lcrpath, struct lcr_container_info **info_arr);
typedef void(*lcr_containers_info_free_t)(struct lcr_container_info **info_arr, size_t size);
typedef bool(*lcr_state_op_t)(const char *name, const char *lcrpath, struct lcr_container_state *lcs);
typedef void(*lcr_container_state_free_t)(struct lcr_container_state *lcs);
typedef bool(*lcr_update_op_t)(const char *name, const char *lcrpath, struct lcr_cgroup_resources *cr);
typedef bool(*lcr_get_console_config_op_t)(const char *name, const char *lcrpath, struct lcr_console_config *config);
typedef void(*lcr_free_console_config_op_t)(struct lcr_console_config *config);
typedef bool(*lcr_start_op_t)(struct lcr_start_request *request);
typedef bool(*lcr_exec_op_t)(const struct lcr_exec_request *request, int *exit_code);

static lcr_list_all_containers_t g_lcr_list_all_containers_op = NULL;
static lcr_containers_info_free_t g_lcr_containers_info_free_op = NULL;
static lcr_state_op_t g_lcr_state_op = NULL;
static lcr_container_state_free_t g_lcr_container_state_free_op = NULL;
static lcr_update_op_t g_lcr_update_op = NULL;
static lcr_get_console_config_op_t g_lcr_get_console_config_op = NULL;
static lcr_free_console_config_op_t g_lcr_free_console_config_op = NULL;
static lcr_start_op_t g_lcr_start_op = NULL;
static lcr_exec_op_t g_lcr_exec_op = NULL;
/*
 * Trans the lcr_state_t to Status
 */
static Engine_Container_Status lcrsta2sta(const char *state)
{
    Engine_Container_Status status = ENGINE_CONTAINER_STATUS_UNKNOWN;

    if (state == NULL) {
        WARN("Empty string of state");
        return status;
    }

    if (strcmp("STOPPED", state) == 0) {
        status = ENGINE_CONTAINER_STATUS_STOPPED;
    } else if ((strcmp("STARTING", state) == 0) || (strcmp("STOPPING", state) == 0)) {
        status = ENGINE_CONTAINER_STATUS_CREATED;
    } else if (strcmp("RUNNING", state) == 0) {
        status = ENGINE_CONTAINER_STATUS_RUNNING;
    } else if ((strcmp("ABORTING", state) == 0) || (strcmp("FREEZING", state) == 0) ||
               (strcmp("FROZEN", state) == 0) || (strcmp("THAWED", state) == 0)) {
        status = ENGINE_CONTAINER_STATUS_PAUSED;
    } else {
        DEBUG("invalid state '%s'", state);
        status = ENGINE_CONTAINER_STATUS_UNKNOWN;
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

/* free console config */
void free_console_config(struct engine_console_config *config)
{
    if (config == NULL) {
        return;
    }
    free(config->log_path);
    config->log_path = NULL;

    free(config->log_file_size);
    config->log_file_size = NULL;

    config->log_rotate = 0;
}

/* get console config */
bool get_console_config(const char *name, const char *lcrpath, struct engine_console_config *config)
{
    struct lcr_console_config lcr_config;
    bool ret = false;

    if (name == NULL || config == NULL) {
        ERROR("Invalid arguments");
        return ret;
    }

    (void)memset(&lcr_config, 0, sizeof(struct lcr_console_config));

    if (g_lcr_get_console_config_op != NULL) {
        ret = g_lcr_get_console_config_op(name, lcrpath, &lcr_config);
    }

    if (ret) {
        if (lcr_config.log_path) {
            config->log_path = util_strdup_s(lcr_config.log_path);
        } else {
            config->log_path = NULL;
        }
        config->log_rotate = lcr_config.log_rotate;
        if (lcr_config.log_file_size) {
            config->log_file_size = util_strdup_s(lcr_config.log_file_size);
        } else {
            config->log_file_size = NULL;
        }

        if (g_lcr_free_console_config_op != NULL) {
            g_lcr_free_console_config_op(&lcr_config);
        }
    }

    return ret;
}

/*
 * Get the containers info by liblcr
 */
static void get_containers_info(int num, const struct lcr_container_info *info_arr,
                                struct engine_container_summary_info *info)
{
    int i = 0;
    const struct lcr_container_info *in = NULL;
    char *name = NULL;

    for (i = 0, in = info_arr; i < num; i++, in++) {
        name = in->name;
        if (name == NULL) {
            continue;
        }

        info[i].id = util_strdup_s(name);
        info[i].has_pid = (-1 == in->init) ? false : true;
        info[i].pid = (uint32_t)in->init;
        info[i].status = lcrsta2sta(in->state);
    }
}

/*
 * Get the state of container from 'lcr_container_state'
 */
static void copy_container_status(const struct lcr_container_state *lcs, struct engine_container_info *status)
{
    const char *defvalue = "-";
    const char *name = NULL;

    (void)memset(status, 0, sizeof(struct engine_container_info));

    name = lcs->name ? lcs->name : defvalue;
    status->id = util_strdup_s(name);

    status->has_pid = (-1 == lcs->init) ? false : true;
    status->pid = (uint32_t)lcs->init;

    status->status = lcrsta2sta(lcs->state);

    status->pids_current = lcs->pids_current;

    status->cpu_use_nanos = lcs->cpu_use_nanos;

    status->blkio_read = lcs->io_service_bytes.read;
    status->blkio_write = lcs->io_service_bytes.write;

    status->mem_used = lcs->mem_used;
    status->mem_limit = lcs->mem_limit;
    status->kmem_used = lcs->kmem_used;
    status->kmem_limit = lcs->kmem_limit;
}

/*
 * Alloc Memory for containerArray and container
 */
static int service_list_alloc(int num, struct engine_container_summary_info **cons)
{
    if (num <= 0 || cons == NULL) {
        return -1;
    }

    if ((size_t)num > SIZE_MAX / sizeof(struct engine_container_summary_info)) {
        ERROR("Too many engine container summaries!");
        return -1;
    }
    *cons = util_common_calloc_s((size_t)num * sizeof(struct engine_container_summary_info));
    if ((*cons) == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    return 0;
}

/*
 * Free the container** containerArray
 */
static void free_all_containers_info(struct engine_container_summary_info *info, int num)
{
    int i = 0;

    if (num <= 0 || info == NULL) {
        return;
    }
    for (i = 0; i < num; i++) {
        free(info[i].id);
        info[i].id = NULL;
        free(info[i].command);
        info[i].command = NULL;
        free(info[i].image);
        info[i].image = NULL;
        free(info[i].finishat);
        info[i].finishat = NULL;
        free(info[i].startat);
        info[i].startat = NULL;
    }
    free(info);
}

/* get all containers info */
static int get_all_containers_info(const char *enginepath, struct engine_container_summary_info **cons)
{
    struct lcr_container_info *info_arr = NULL;
    int num = 0;

    if (cons == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    if (g_lcr_list_all_containers_op == NULL || g_lcr_containers_info_free_op == NULL) {
        ERROR("Not supported op");
        num = -1;
        goto free_out;
    }

    num = g_lcr_list_all_containers_op(enginepath, &info_arr);
    if (num <= 0) {
        num = 0; /* set to 0 if non were found */
        goto free_out;
    }

    if (service_list_alloc(num, cons)) {
        g_lcr_containers_info_free_op(&info_arr, (size_t)num);
        ERROR("service list alloc failed");
        num = -1;
        goto free_out;
    }

    get_containers_info(num, info_arr, *cons);
    g_lcr_containers_info_free_op(&info_arr, (size_t)num);

free_out:
    return num;
}

/* get container status */
static int get_container_status(const char *name, const char *enginepath, struct engine_container_info *status)
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

/* free container status */
static void free_container_status(struct engine_container_info *status)
{
    if (status == NULL) {
        return;
    }

    free(status->id);
    status->id = NULL;
}

#define CHECK_ERROR(P) do { \
        if (dlerror() != NULL) { \
            goto badcleanup; \
        } \
    } while (0)

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
    g_lcr_get_console_config_op = dlsym(lcr_handler, "lcr_get_console_config");
    if (dlerror() != NULL) {
        return false;
    }
    g_lcr_free_console_config_op = dlsym(lcr_handler, "lcr_free_console_config");
    if (dlerror() != NULL) {
        return false;
    }
    g_lcr_list_all_containers_op = dlsym(lcr_handler, "lcr_list_all_containers");
    if (dlerror() != NULL) {
        return false;
    }
    g_lcr_containers_info_free_op = dlsym(lcr_handler, "lcr_containers_info_free");
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
    lcr_handler = dlopen("liblcr.so", RTLD_NOW | RTLD_DEEPBIND);
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

    eop->engine_get_all_containers_info_op = get_all_containers_info;
    eop->engine_free_all_containers_info_op = free_all_containers_info;
    eop->engine_get_container_status_op = get_container_status;
    eop->engine_free_container_status_op = free_container_status;
    eop->engine_update_op = lcr_update_container;
    eop->engine_start_op = lcr_start_container;
    eop->engine_exec_op = lcr_exec_container;
    eop->engine_get_console_config_op = get_console_config;
    eop->engine_free_console_config_op = free_console_config;

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

