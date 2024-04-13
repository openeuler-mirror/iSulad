/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2019-11-22
 * Description: provide container list callback function definition
 ********************************************************************************/

#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <isula_libutils/log.h>
#include <isula_libutils/defs.h>
#include <isula_libutils/host_config.h>
#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/oci_runtime_spec.h>

#include "lcr_rt_ops.h"
#include "engine.h"
#include "error.h"
#include "isulad_config.h"
#include "err_msg.h"
#include "runtime_api.h"
#include "utils_file.h"

#define LCR_CONFIG_FILE "config"

bool rt_lcr_detect(const char *runtime)
{
    /* now we just support lcr engine */
    if (runtime != NULL && strcasecmp(runtime, "lcr") == 0) {
        return true;
    }

    return false;
}

int rt_lcr_create(const char *name, const char *runtime, const rt_create_params_t *params)
{
    int ret = 0;
    char *runtime_root = NULL;
    struct engine_operation *engine_ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }

    if (conf_get_systemd_cgroup()) {
        ERROR("Systemd cgroup not supported for lcr runtime");
        isulad_set_error_message("Systemd cgroup not supported for lcr runtime");
        ret = -1;
        goto out;
    }

    runtime_root = conf_get_routine_rootdir(runtime);
    if (runtime_root == NULL) {
        ERROR("Root path is NULL");
        ret = -1;
        goto out;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_create_op == NULL) {
        ERROR("Failed to get engine create operations");
        ret = -1;
        goto out;
    }

    if (!engine_ops->engine_create_op(name, runtime_root, params->oci_config_data)) {
        ERROR("Failed to create container");
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Create container error: %s",
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ret = -1;
        goto out;
    }

out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    free(runtime_root);
    return ret;
}

static int parse_container_pid(const char *S, pid_ppid_info_t *pid_info)
{
    int num;

    num = sscanf(S, "%d %Lu %d %Lu", &pid_info->pid, &pid_info->start_time, &pid_info->ppid, &pid_info->pstart_time);
    if (num != 4) { // args num to read is 4
        SYSERROR("Call sscanf failed.");
        return -1;
    }

    return 0;
}

static int lcr_rt_read_pidfile(const char *pidfile, pid_ppid_info_t *pid_info)
{
    if (pidfile == NULL || pid_info == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    char sbuf[1024] = { 0 }; /* bufs for stat */

    if ((util_file2str(pidfile, sbuf, sizeof(sbuf))) == -1) {
        return -1;
    }

    return parse_container_pid(sbuf, pid_info);
}

int rt_lcr_start(const char *name, const char *runtime, const rt_start_params_t *params, pid_ppid_info_t *pid_info)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;
    engine_start_request_t request = { 0 };

    if (name == NULL || runtime == NULL || params == NULL || pid_info == NULL) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_start_op == NULL) {
        ERROR("Failed to get engine start operations");
        ret = -1;
        goto out;
    }

    request.name = name;
    request.lcrpath = params->rootpath;
    request.logpath = params->logpath;
    request.loglevel = params->loglevel;
    request.daemonize = true;
    request.tty = params->tty;
    request.open_stdin = params->open_stdin;
    request.console_fifos = params->console_fifos;
    request.start_timeout = params->start_timeout;
    request.container_pidfile = params->container_pidfile;
    request.exit_fifo = params->exit_fifo;
    request.image_type_oci = params->image_type_oci;

    if (!engine_ops->engine_start_op(&request)) {
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Start container error: %s",
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ERROR("Start container error: %s", (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ret = -1;
        goto out;
    }
    ret = lcr_rt_read_pidfile(params->container_pidfile, pid_info);
    if (ret != 0) {
        ERROR("Failed to get started container's pid info, start container fail");
        ret = -1;
        goto out;
    }
out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

int rt_lcr_restart(const char *name, const char *runtime, const rt_restart_params_t *params)
{
    return RUNTIME_NOT_IMPLEMENT_RESET;
}

int rt_lcr_clean_resource(const char *name, const char *runtime, const rt_clean_params_t *params)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_clean_op == NULL) {
        ERROR("Failed to get engine clean operations");
        ret = -1;
        goto out;
    }

    if (!engine_ops->engine_clean_op(name, params->rootpath, params->logpath, params->loglevel, params->pid)) {
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_try_set_error_message("Clean resource container error;%s",
                                     (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ret = -1;
        goto out;
    }

out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

static int remove_container_rootpath(const char *id, const char *root_path)
{
    int ret = 0;
    char cont_root_path[PATH_MAX] = { 0 };

    ret = snprintf(cont_root_path, sizeof(cont_root_path), "%s/%s", root_path, id);
    if (ret < 0 || (size_t)ret >= sizeof(cont_root_path)) {
        ERROR("Failed to sprintf container_state");
        ret = -1;
        goto out;
    }
    ret = util_recursive_rmdir(cont_root_path, 0);
    if (ret != 0) {
        SYSERROR("Failed to delete container's root directory %s.", cont_root_path);
        isulad_set_error_message("Failed to delete container's root directory %s.", cont_root_path);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

int rt_lcr_rm(const char *name, const char *runtime, const rt_rm_params_t *params)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }
    if (params->rootpath == NULL) {
        ERROR("Missing root path");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_delete_op == NULL) {
        // if engine_ops is NULL, container root path may have been corrupted, try to remove by daemon
        // If user runs container with lcr but remove lcr runtime after, there might be resources remaining
        ERROR("Failed to get engine delete operations, container %s root path may have been corrupted, try to remove by daemon", name);
        if (remove_container_rootpath(name, params->rootpath) == 0) {
            ret = 0;
            goto out;
        }
        ret = -1;
        goto out;
    }

    if (!engine_ops->engine_delete_op(name, params->rootpath)) {
        const char *tmpmsg = NULL;
        ret = -1;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Runtime delete container error: %s",
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ERROR("Runtime delete container error: %s",
              (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        if (tmpmsg != NULL && strstr(tmpmsg, "No such container") != NULL) {
            // container root path may been corrupted, try to remove by daemon
            WARN("container %s root path may been corrupted, try to remove by daemon", name);
            if (remove_container_rootpath(name, params->rootpath) == 0) {
                ret = 0;
                goto out;
            }
        }
        goto out;
    }

out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

int rt_lcr_status(const char *name, const char *runtime, const rt_status_params_t *params,
                  struct runtime_container_status_info *status)
{
    int ret = 0;
    int nret = 0;
    struct engine_operation *engine_ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL || status == NULL) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_get_container_status_op == NULL) {
        ERROR("Failed to get engine status operations");
        ret = -1;
        goto out;
    }

    nret = engine_ops->engine_get_container_status_op(name, params->rootpath, status);
    if (nret != 0) {
        ret = -1;
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        if (tmpmsg != NULL && strstr(tmpmsg, "Failed to load config") != NULL) {
            status->error_code = INVALID_CONFIG_ERR_CODE;
        }
        isulad_set_error_message("Runtime state container error: %s",
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ERROR("Runtime state container error: %s",
              (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        goto out;
    }

out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

int rt_lcr_resources_stats(const char *name, const char *runtime, const rt_stats_params_t *params,
                           struct runtime_container_resources_stats_info *rs_stats)
{
    int ret = 0;
    int nret = 0;
    struct engine_operation *engine_ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL || rs_stats == NULL) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_get_container_resources_stats_op == NULL) {
        ERROR("Failed to get engine stats operations");
        ret = -1;
        goto out;
    }

    nret = engine_ops->engine_get_container_resources_stats_op(name, params->rootpath, rs_stats);
    if (nret != 0) {
        ret = -1;
        goto out;
    }

out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

// user string(UID:GID)
static int generate_user_string_by_uid_gid(const defs_process_user *puser, char **user)
{
    char uid_str[ISULAD_NUMSTRLEN32] = { 0 };
    char gid_str[ISULAD_NUMSTRLEN32] = { 0 };
    size_t len;
    int nret = 0;

    nret = snprintf(uid_str, ISULAD_NUMSTRLEN32, "%u", (unsigned int)puser->uid);
    if (nret < 0 || (size_t)nret >= ISULAD_NUMSTRLEN32) {
        ERROR("Invalid UID:%u", (unsigned int)puser->uid);
        return -1;
    }

    nret = snprintf(gid_str, ISULAD_NUMSTRLEN32, "%u", (unsigned int)puser->gid);
    if (nret < 0 || (size_t)nret >= ISULAD_NUMSTRLEN32) {
        ERROR("Invalid attach uid value :%u", (unsigned int)puser->gid);
        return -1;
    }

    len = strlen(uid_str) + 1 + strlen(gid_str) + 1;
    *user = (char *)util_smart_calloc_s(sizeof(char), len);
    if (*user == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    nret = snprintf(*user, len, "%u:%u", (unsigned int)puser->uid, (unsigned int)puser->gid);
    if (nret < 0 || (size_t)nret >= len) {
        ERROR("Invalid UID:GID (%u:%u)", (unsigned int)puser->uid, (unsigned int)puser->gid);
        free(*user);
        *user = NULL;
        return -1;
    }

    return 0;
}

static char **covert_gids_to_string(const gid_t *gids, const size_t gids_len)
{
    int nret = 0;
    size_t i = 0;
    size_t len = 0;
    char **result = NULL;

    result = util_smart_calloc_s(sizeof(char *), gids_len);
    if (result == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (i = 0; i < gids_len; i++) {
        char gid_str[ISULAD_NUMSTRLEN32] = { 0 };

        nret = snprintf(gid_str, ISULAD_NUMSTRLEN32, "%u", (unsigned int)gids[i]);
        if (nret < 0 || (size_t)nret >= ISULAD_NUMSTRLEN32) {
            ERROR("Invalid gid :%u", (unsigned int)gids[i]);
            util_free_array_by_len(result, len);
            return NULL;
        }

        result[i] = util_strdup_s(gid_str);
        len++;
    }

    return result;
}

// additional gids string(GID[,GID])
static int generate_add_gids_string(const defs_process_user *puser, char **add_gids)
{
    const size_t max_gids = 100;
    char **gids = NULL;

    if (puser->additional_gids == NULL || puser->additional_gids_len == 0) {
        INFO("None attach additional gids");
        return 0;
    }

    if (puser->additional_gids_len > max_gids) {
        ERROR("Too many additional gids");
        return -1;
    }

    gids = covert_gids_to_string(puser->additional_gids, puser->additional_gids_len);
    if (gids == NULL) {
        ERROR("Failed to covert gids to string");
        return -1;
    }

    *add_gids = util_string_join(",", (const char **)gids, puser->additional_gids_len);
    if (*add_gids == NULL) {
        ERROR("Failed to string join");
        util_free_array_by_len(gids, puser->additional_gids_len);
        return -1;
    }

    util_free_array_by_len(gids, puser->additional_gids_len);
    return 0;
}

int rt_lcr_exec(const char *id, const char *runtime, const rt_exec_params_t *params, int *exit_code)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;
    engine_exec_request_t request = { 0 };
    char *user = NULL;
    char *add_gids = NULL;

    if (id == NULL || runtime == NULL || params == NULL || exit_code == NULL) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_exec_op == NULL) {
        DEBUG("Failed to get engine exec operations");
        ret = -1;
        goto out;
    }

    request.name = id;
    request.lcrpath = params->rootpath;
    request.logpath = params->logpath;
    request.loglevel = params->loglevel;
    if (params->spec != NULL) {
        request.args = (const char **)params->spec->args;
        request.args_len = params->spec->args_len;
        request.env = (const char **)params->spec->env;
        request.env_len = params->spec->env_len;
    }
    request.console_fifos = params->console_fifos;
    request.timeout = params->timeout;
    request.suffix = params->suffix;
    if (params->spec != NULL && params->spec->user != NULL) {
        if (generate_user_string_by_uid_gid(params->spec->user, &user) != 0) {
            ret = -1;
            goto out;
        }
        request.user = user;

        if (generate_add_gids_string(params->spec->user, &add_gids) != 0) {
            ret = -1;
            goto out;
        }
        request.add_gids = add_gids;
    }

    request.open_stdin = params->attach_stdin;
    if (params->spec != NULL) {
        request.tty = params->spec->terminal;
    }
    if (params->workdir != NULL) {
        request.workdir = params->workdir;
    }

    if (!engine_ops->engine_exec_op(&request, exit_code)) {
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Exec container error;%s",
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        util_contain_errmsg(g_isulad_errmsg, exit_code);
        ret = -1;
        goto out;
    }

out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    free(user);
    free(add_gids);
    return ret;
}

int rt_lcr_pause(const char *name, const char *runtime, const rt_pause_params_t *params)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_pause_op == NULL) {
        DEBUG("Failed to get engine pause operations");
        ret = -1;
        goto out;
    }

    if (!engine_ops->engine_pause_op(name, params->rootpath)) {
        DEBUG("Pause container %s failed", name);
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Pause container error;%s",
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ret = -1;
        goto out;
    }
out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

int rt_lcr_resume(const char *name, const char *runtime, const rt_resume_params_t *params)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_resume_op == NULL) {
        DEBUG("Failed to get engine resume operations");
        ret = -1;
        goto out;
    }

    if (!engine_ops->engine_resume_op(name, params->rootpath)) {
        DEBUG("Resume container %s failed", name);
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Resume container error;%s",
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ret = -1;
        goto out;
    }
out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

int rt_lcr_attach(const char *name, const char *runtime, const rt_attach_params_t *params)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Null argument");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_console_op == NULL) {
        DEBUG("Failed to get engine attach operations");
        ret = -1;
        goto out;
    }

    if (!engine_ops->engine_console_op(name, params->rootpath, (char *)params->stdin, (char *)params->stdout,
                                       (char *)params->stderr)) {
        ERROR("attach failed");
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Attach container error;%s",
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ret = -1;
        goto out;
    }
out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

static void to_engine_resources(const host_config *hostconfig, struct engine_cgroup_resources *cr)
{
    uint64_t period = 0;
    int64_t quota = 0;

    if (hostconfig == NULL || cr == NULL) {
        return;
    }

    cr->blkio_weight = hostconfig->blkio_weight;
    cr->cpu_shares = (uint64_t)hostconfig->cpu_shares;
    cr->cpu_period = (uint64_t)hostconfig->cpu_period;
    cr->cpu_quota = hostconfig->cpu_quota;
    cr->cpuset_cpus = hostconfig->cpuset_cpus;
    cr->cpuset_mems = hostconfig->cpuset_mems;
    cr->memory_limit = (uint64_t)hostconfig->memory;
    cr->memory_swap = (uint64_t)hostconfig->memory_swap;
    cr->memory_reservation = (uint64_t)hostconfig->memory_reservation;
    cr->kernel_memory_limit = (uint64_t)hostconfig->kernel_memory;
    cr->cpurt_period = hostconfig->cpu_realtime_period;
    cr->cpurt_runtime = hostconfig->cpu_realtime_runtime;

    if (hostconfig->nano_cpus > 0) {
        period = (uint64_t)(100 * Time_Milli / Time_Micro);
        quota = hostconfig->nano_cpus * (int64_t)period / 1e9;
        cr->cpu_period = period;
        cr->cpu_quota = quota;
    }
}

int rt_lcr_update(const char *id, const char *runtime, const rt_update_params_t *params)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;
    struct engine_cgroup_resources cr = { 0 };

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_update_op == NULL) {
        DEBUG("Failed to get engine update operations");
        ret = -1;
        goto out;
    }

    to_engine_resources(params->hostconfig, &cr);

    if (!engine_ops->engine_update_op(id, params->rootpath, &cr)) {
        DEBUG("Update container %s failed", id);
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Cannot update container %s: %s", id,
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ret = -1;
        goto out;
    }
out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

int rt_lcr_listpids(const char *name, const char *runtime, const rt_listpids_params_t *params, rt_listpids_out_t *out)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL || out == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_get_container_pids_op == NULL) {
        ERROR("Failed to get engine top operations");
        ret = -1;
        goto out;
    }

    if (!engine_ops->engine_get_container_pids_op(name, params->rootpath, &(out->pids), &(out->pids_len))) {
        ERROR("Top container %s failed", name);
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Runtime top container error: %s",
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ret = -1;
        goto out;
    }
out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

int rt_lcr_resize(const char *id, const char *runtime, const rt_resize_params_t *params)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_resize_op == NULL) {
        DEBUG("Failed to get engine resume operations");
        ret = -1;
        goto out;
    }

    if (!engine_ops->engine_resize_op(id, params->rootpath, params->height, params->width)) {
        DEBUG("resize container %s failed", id);
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Resize container error;%s",
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);

        ret = -1;
        goto out;
    }
out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

int rt_lcr_exec_resize(const char *id, const char *runtime, const rt_exec_resize_params_t *params)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

    if (id == NULL || runtime == NULL || params == NULL) {
        ERROR("Nullptr arguments not allowed");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_resize_op == NULL) {
        DEBUG("Failed to get engine resume operations");
        ret = -1;
        goto out;
    }

    if (!engine_ops->engine_exec_resize_op(id, params->rootpath, params->suffix, params->height, params->width)) {
        DEBUG("exec resize container %s failed", id);
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Resize container error;%s",
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR) != 0) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ret = -1;
        goto out;
    }
out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

int rt_lcr_kill(const char *id, const char *runtime, const rt_kill_params_t *params)
{
    if (id == NULL || runtime == NULL || params == NULL || params->pid < 0) {
        ERROR("Invalid arguments not allowed");
        return -1;
    }

    if (util_process_alive(params->pid, params->start_time) == false) {
        if (params->signal == params->stop_signal || params->signal == SIGKILL) {
            WARN("Process %d is not alive", params->pid);
            return 0;
        } else {
            ERROR("Process (pid=%d) is not alive, can not kill with signal %u", params->pid, params->signal);
            return -1;
        }
    } else {
        int ret = kill(params->pid, (int)params->signal);
        if (ret < 0) {
            SYSERROR("Can not kill process (pid=%d) with signal %u.", params->pid, params->signal);
            return -1;
        }
    }

    return 0;
}

int rt_lcr_rebuild_config(const char *name, const char *runtime, const rt_rebuild_config_params_t *params)
{
    int ret = -1;
    int nret = 0;
    bool rebuild_success = false;
    char config_file[PATH_MAX] = { 0 };
    char bak_config_file[PATH_MAX] = { 0 };
    char oci_config_file[PATH_MAX] = { 0 };
    struct engine_operation *engine_ops = NULL;
    oci_runtime_spec *oci_spec = NULL;
    __isula_auto_free parser_error err = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalid arguments not allowed");
        return -1;
    }

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_create_op == NULL) {
        ERROR("Failed to get engine rebuild config operations");
        return -1;
    }

    nret = snprintf(config_file, PATH_MAX, "%s/%s/%s", params->rootpath, name, LCR_CONFIG_FILE);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        ERROR("Failed to snprintf config file for container %s", name);
        return -1;
    }

    nret = snprintf(bak_config_file, PATH_MAX, "%s/%s/%s", params->rootpath, name, ".tmp_config_bak");
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        ERROR("Failed to snprintf bak config file for container %s", name);
        return -1;
    }

    nret = snprintf(oci_config_file, sizeof(oci_config_file), "%s/%s/%s", params->rootpath, name, OCI_CONFIG_JSON);
    if (nret < 0 || (size_t)nret >= sizeof(oci_config_file)) {
        ERROR("Failed to snprintf for config json");
        return -1;
    }

    oci_spec = oci_runtime_spec_parse_file(oci_config_file, NULL, &err);
    if (oci_spec == NULL) {
        ERROR("Failed to parse oci config file:%s", err);
        return -1;
    }

    // delete the bak config file to prevent the remnants of the previous bak file
    if (util_fileself_exists(bak_config_file) && util_path_remove(bak_config_file) != 0) {
        ERROR("Failed to remove bak_config_file for container: %s", name);
        goto out;
    }

    if (util_fileself_exists(config_file) && rename(config_file, bak_config_file) != 0) {
        ERROR("Failed to backup old config for container: %s", name);
        goto out;
    }

    rebuild_success = engine_ops->engine_create_op(name, params->rootpath, (void *)oci_spec);
    if (!rebuild_success) {
        // delete the invalid config file to prevent rename failed
        if (util_fileself_exists(config_file) && util_path_remove(config_file) != 0) {
            WARN("Failed to remove bak_config_file for container %s", name);
        }
        if (util_fileself_exists(bak_config_file) && rename(bak_config_file, config_file) != 0) {
            WARN("Failed to rename backup old config to config for container %s", name);
        }
    }
    ret = rebuild_success ? 0 : -1;

out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    if (util_fileself_exists(bak_config_file) && util_path_remove(bak_config_file) != 0) {
        WARN("Failed to remove bak_config_file for %s", name);
    }
    free_oci_runtime_spec(oci_spec);
    return ret;
}
