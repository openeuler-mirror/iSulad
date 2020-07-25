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
#include <isula_libutils/defs.h>
#include <isula_libutils/host_config.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "lcr_rt_ops.h"
#include "isula_libutils/log.h"
#include "engine.h"
#include "error.h"
#include "isulad_config.h"
#include "err_msg.h"
#include "runtime_api.h"
#include "utils_file.h"

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
                                 (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
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
        ERROR("Call sscanf error: %s", errno ? strerror(errno) : "");
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

    if (!engine_ops->engine_start_op(&request)) {
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Start container error: %s",
                                 (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ERROR("Start container error: %s", (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
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
                                     (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
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
        const char *tmp_err = (errno != 0) ? strerror(errno) : "error";
        ERROR("Failed to delete container's root directory %s: %s", cont_root_path, tmp_err);
        isulad_set_error_message("Failed to delete container's root directory %s: %s", cont_root_path, tmp_err);
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

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_delete_op == NULL) {
        ERROR("Failed to get engine delete operations");
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
                                 (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ERROR("Runtime delete container error: %s",
              (tmpmsg != NULL && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
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

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_get_container_status_op == NULL) {
        ERROR("Failed to get engine status operations");
        ret = -1;
        goto out;
    }

    nret = engine_ops->engine_get_container_status_op(name, params->rootpath, status);
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

int rt_lcr_resources_stats(const char *name, const char *runtime, const rt_stats_params_t *params,
                           struct runtime_container_resources_stats_info *rs_stats)
{
    int ret = 0;
    int nret = 0;
    struct engine_operation *engine_ops = NULL;

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
    if (nret < 0 || nret >= ISULAD_NUMSTRLEN32) {
        ERROR("Invalid UID:%u", (unsigned int)puser->uid);
        return -1;
    }

    nret = snprintf(gid_str, ISULAD_NUMSTRLEN32, "%u", (unsigned int)puser->gid);
    if (nret < 0 || nret >= ISULAD_NUMSTRLEN32) {
        ERROR("Invalid attach uid value :%u", (unsigned int)puser->gid);
        return -1;
    }

    len = strlen(uid_str) + 1 + strlen(gid_str) + 1;
    *user = (char *)util_common_calloc_s(len * sizeof(char));
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

int rt_lcr_exec(const char *id, const char *runtime, const rt_exec_params_t *params, int *exit_code)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;
    engine_exec_request_t request = { 0 };
    char *user = NULL;

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
    }

    request.open_stdin = params->attach_stdin;
    if (params->spec != NULL) {
        request.tty = params->spec->terminal;
    }

    if (!engine_ops->engine_exec_op(&request, exit_code)) {
        const char *tmpmsg = NULL;
        if (engine_ops->engine_get_errmsg_op != NULL) {
            tmpmsg = engine_ops->engine_get_errmsg_op();
        }
        isulad_set_error_message("Exec container error;%s",
                                 (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        util_contain_errmsg(g_isulad_errmsg, exit_code);
        ret = -1;
        goto out;
    }

out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    free(user);
    return ret;
}

int rt_lcr_pause(const char *name, const char *runtime, const rt_pause_params_t *params)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

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
                                 (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
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
                                 (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
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
                                 (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
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
    if (hostconfig == NULL || cr == NULL) {
        return;
    }

    cr->blkio_weight = hostconfig->blkio_weight;
    cr->cpu_shares = (uint64_t)hostconfig->cpu_shares;
    cr->cpu_period = (uint64_t)hostconfig->cpu_period;
    cr->cpu_quota = (uint64_t)hostconfig->cpu_quota;
    cr->cpuset_cpus = hostconfig->cpuset_cpus;
    cr->cpuset_mems = hostconfig->cpuset_mems;
    cr->memory_limit = (uint64_t)hostconfig->memory;
    cr->memory_swap = (uint64_t)hostconfig->memory_swap;
    cr->memory_reservation = (uint64_t)hostconfig->memory_reservation;
    cr->kernel_memory_limit = (uint64_t)hostconfig->kernel_memory;
}

int rt_lcr_update(const char *id, const char *runtime, const rt_update_params_t *params)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;
    struct engine_cgroup_resources cr = { 0 };

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
                                 (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
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

    if (out == NULL) {
        ERROR("Invalid arguments");
        ret = -1;
        goto out;
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
                                 (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
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
                                 (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);

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
                                 (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);
        ret = -1;
        goto out;
    }
out:
    if (engine_ops != NULL && engine_ops->engine_clear_errmsg_op != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}
