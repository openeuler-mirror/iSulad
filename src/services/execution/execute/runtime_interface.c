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
 * Description: provide container list callback function definition
 ********************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <lcr/lcrcontainer.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <malloc.h>

#include "log.h"
#include "engine.h"
#include "callback.h"
#include "runtime_interface.h"
#include "error.h"
#include "lcrd_config.h"

int runtime_create(const char *name, const char *runtime, const char *rootfs, void *oci_config_data)
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

    if (!engine_ops->engine_create_op(name, runtime_root, rootfs, NULL,
                                      (void *)oci_config_data)) {
        ERROR("Failed to create container");
        const char *tmpmsg = NULL;
        tmpmsg = engine_ops->engine_get_errmsg_op();
        lcrd_set_error_message("Create container error: %s",
                               (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg
                               : DEF_ERR_RUNTIME_STR);
        engine_ops->engine_clear_errmsg_op();
        ret = -1;
        goto out;
    }

out:
    free(runtime_root);
    return ret;
}

int runtime_start(const char *name, const char *runtime, const char *rootpath, bool tty, bool interactive,
                  const char *engine_log_path, const char *loglevel, const char *console_fifos[],
                  const char *share_ns[], unsigned int start_timeout, const char *pidfile, const char *exit_fifo,
                  const oci_runtime_spec_process_user *puser)
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
    request.lcrpath = rootpath;
    request.logpath = engine_log_path;
    request.loglevel = loglevel;
    request.daemonize = true;
    request.tty = tty;
    request.open_stdin = interactive;
    request.pidfile = NULL;
    request.console_fifos = console_fifos;
    request.console_logpath = NULL;
    request.share_ns = (const char **)share_ns;
    request.start_timeout = start_timeout;
    request.container_pidfile = pidfile;
    request.exit_fifo = exit_fifo;
    if (puser != NULL) {
        request.uid = puser->uid;
        request.gid = puser->gid;
        request.additional_gids = puser->additional_gids;
        request.additional_gids_len = puser->additional_gids_len;
    }
    if (!engine_ops->engine_start_op(&request)) {
        const char *tmpmsg = NULL;
        tmpmsg = engine_ops->engine_get_errmsg_op();
        lcrd_set_error_message("Start container error: %s",
                               (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg
                               : DEF_ERR_RUNTIME_STR);
        ERROR("Start container error: %s", (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg
              : DEF_ERR_RUNTIME_STR);
        engine_ops->engine_clear_errmsg_op();
        ret = -1;
        goto out;
    }
out:
    return ret;
}

int runtime_restart(const char *name, const char *runtime, const char *rootpath)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_reset_op == NULL) {
        ERROR("Get reset operation failed");
        ret = -2;
        goto out;
    }

    if (!engine_ops->engine_reset_op(name, rootpath)) {
        ERROR("Reset operate failed");
        if (engine_ops->engine_get_errmsg_op != NULL) {
            const char *tmpmsg = NULL;
            tmpmsg = engine_ops->engine_get_errmsg_op();
            lcrd_set_error_message("Restart container error: %s",
                                   (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg
                                   : DEF_ERR_RUNTIME_STR);
            if (engine_ops->engine_clear_errmsg_op != NULL) {
                engine_ops->engine_clear_errmsg_op();
            }
        }
        ret = -1;
    }
out:
    return ret;
}

int runtime_clean_resource(const char *name, const char *runtime, const char *rootpath,
                           const char *engine_log_path, const char *loglevel, pid_t pid)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_clean_op == NULL) {
        ERROR("Failed to get engine clean operations");
        ret = -1;
        goto out;
    }

    if (!engine_ops->engine_clean_op(name, rootpath, engine_log_path, loglevel, pid)) {
        const char *tmpmsg = NULL;
        tmpmsg = engine_ops->engine_get_errmsg_op();
        lcrd_try_set_error_message("Clean resource container error;%s",
                                   (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg
                                   : DEF_ERR_RUNTIME_STR);
        ret = -1;
        goto out;
    }

out:
    if (engine_ops != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

int runtime_rm(const char *name, const char *runtime, const char *rootpath)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || engine_ops->engine_delete_op == NULL) {
        ERROR("Failed to get engine delete operations");
        ret = -1;
        goto out;
    }

    if (!engine_ops->engine_delete_op(name, rootpath)) {
        ERROR("Delete container %s failed", name);
        const char *tmpmsg = NULL;
        tmpmsg = engine_ops->engine_get_errmsg_op();
        lcrd_set_error_message("Runtime delete container error: %s",
                               (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ? tmpmsg : DEF_ERR_RUNTIME_STR);

        ret = -1;
        goto out;
    }

out:
    if (engine_ops != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

int runtime_get_console_config(const char *name, const char *runtime, const char *rootpath,
                               struct engine_console_config *config)
{
    int ret = 0;
    struct engine_operation *engine_ops = NULL;

    engine_ops = engines_get_handler(runtime);
    if (engine_ops == NULL || (engine_ops->engine_get_console_config_op) == NULL) {
        ERROR("Failed to get engine get_console_config operation");
        ret = -1;
        goto out;
    }

    if (!engine_ops->engine_get_console_config_op(name, rootpath, config)) {
        ERROR("Failed to get console config");
        const char *tmpmsg = NULL;
        tmpmsg = engine_ops->engine_get_errmsg_op();
        lcrd_set_error_message("Get console config error;%s", (tmpmsg && strcmp(tmpmsg, DEF_SUCCESS_STR)) ?
                               tmpmsg : DEF_ERR_RUNTIME_STR);
        ret = -1;
        goto out;
    }


out:
    if (engine_ops != NULL) {
        engine_ops->engine_clear_errmsg_op();
    }
    return ret;
}

