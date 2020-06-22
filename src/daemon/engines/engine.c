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
 * Description: provide container engine functions
 ******************************************************************************/
#include "engine.h"

#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>

#include "constants.h"
#include "linked_list.h"
#include "isulad_config.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "lcr_engine.h"
#include "libisulad.h"

struct isulad_engine_operation_lists {
    pthread_rwlock_t isulad_engines_op_rwlock;
    struct linked_list isulad_engines_op_list;
};

static struct isulad_engine_operation_lists g_isulad_engines_lists;

typedef int (*engine_init_func_t)(struct engine_operation *ops);

/* engine global init */
int engines_global_init()
{
    int ret = 0;

    (void)memset(&g_isulad_engines_lists, 0, sizeof(struct isulad_engine_operation_lists));
    /* init isulad_engines_op_rwlock */

    ret = pthread_rwlock_init(&g_isulad_engines_lists.isulad_engines_op_rwlock, NULL);
    if (ret != 0) {
        ERROR("Failed to init isulad conf rwlock");
        ret = -1;
        goto out;
    }

    linked_list_init(&g_isulad_engines_lists.isulad_engines_op_list);

out:
    return ret;
}

/* engine routine log init */
static int engine_routine_log_init(const struct engine_operation *eop)
{
    int ret = 0;
    char *engine_log_path = NULL;
    struct service_arguments *args = NULL;

    if (eop == NULL || eop->engine_log_init_op == NULL) {
        ERROR("Failed to get engine log init operations");
        ret = -1;
        goto out;
    }

    engine_log_path = conf_get_engine_log_file();
    if (isulad_server_conf_rdlock()) {
        ret = -1;
        goto out;
    }

    args = conf_get_server_conf();
    if (args == NULL) {
        ERROR("Failed to get isulad server config");
        ret = -1;
        goto unlock_out;
    }

    if (engine_log_path == NULL) {
        ERROR("Log fifo path is NULL");
        ret = -1;
        goto unlock_out;
    }
    // log throught fifo, so we need disable stderr by quiet (set to 1)
    ret = eop->engine_log_init_op(args->progname, engine_log_path, args->json_confs->log_level, eop->engine_type, 1,
                                  NULL);
    if (ret != 0) {
        ret = -1;
        goto unlock_out;
    }

unlock_out:
    if (isulad_server_conf_unlock()) {
        ret = -1;
        goto out;
    }
out:
    free(engine_log_path);
    return ret;
}

/* engine operation free */
void engine_operation_free(struct engine_operation *eop)
{
    if (eop->engine_type != NULL) {
        free(eop->engine_type);
        eop->engine_type = NULL;
    }
}

/* create engine root path */
static int create_engine_root_path(const char *path)
{
    int ret = -1;

    if (path == NULL) {
        return ret;
    }

    if (util_dir_exists(path)) {
        ret = 0;
        goto out;
    }
    ret = util_mkdir_p(path, CONFIG_DIRECTORY_MODE);
    if (ret != 0) {
        ERROR("Unable to create engine root path: %s", path);
    }

out:
    return ret;
}

static struct engine_operation *query_engine_locked(const char *name)
{
    struct engine_operation *engine_op = NULL;
    struct linked_list *it = NULL;
    struct linked_list *next = NULL;

    linked_list_for_each_safe(it, &g_isulad_engines_lists.isulad_engines_op_list, next) {
        engine_op = (struct engine_operation *)it->elem;
        if (engine_op == NULL) {
            DEBUG("Invalid engine list elem");
            linked_list_del(it);
            continue;
        }

        if (strcasecmp(name, engine_op->engine_type) == 0) {
            break;
        }
        engine_op = NULL;
    }

    return engine_op;
}

static struct engine_operation *new_engine_locked(const char *name)
{
    struct engine_operation *engine_op = NULL;
    char *rootpath = NULL;

    /* now we just support lcr engine */
    if (strcasecmp(name, "lcr") == 0) {
        engine_op = lcr_engine_init();
    }

    if (engine_op == NULL) {
        ERROR("Failed to initialize engine or runtime: %s", name);
        isulad_set_error_message("Failed to initialize engine or runtime: %s", name);
        return NULL;
    }

    /* First init engine log */
    if (engine_routine_log_init(engine_op) != 0) {
        ERROR("Init engine: %s log failed", name);
        goto out;
    }

    rootpath = conf_get_routine_rootdir(name);
    if (rootpath == NULL) {
        ERROR("Root path is NULL");
        goto out;
    }

    if (create_engine_root_path(rootpath)) {
        ERROR("Create engine path failed");
        free(rootpath);
        goto out;
    }

    free(rootpath);
    return engine_op;

out:
    engine_operation_free(engine_op);
    free(engine_op);

    return NULL;
}

/* engines discovery */
int engines_discovery(const char *name)
{
    int ret = 0;
    struct engine_operation *engine_op = NULL;
    struct linked_list *newnode = NULL;

    if (name == NULL) {
        return -1;
    }

    if (pthread_rwlock_wrlock(&g_isulad_engines_lists.isulad_engines_op_rwlock)) {
        ERROR("Failed to acquire isulad engines list write lock");
        return -1;
    }

    engine_op = query_engine_locked(name);
    if (engine_op != NULL) {
        goto unlock_out;
    }

    engine_op = new_engine_locked(name);
    if (engine_op == NULL) {
        ret = -1;
        goto unlock_out;
    }

    newnode = util_common_calloc_s(sizeof(struct linked_list));
    if (newnode == NULL) {
        CRIT("Memory allocation error.");
        ret = -1;

        engine_operation_free(engine_op);
        free(engine_op);
        goto unlock_out;
    }

    linked_list_add_elem(newnode, engine_op);
    linked_list_add_tail(&g_isulad_engines_lists.isulad_engines_op_list, newnode);

unlock_out:
    if (pthread_rwlock_unlock(&g_isulad_engines_lists.isulad_engines_op_rwlock)) {
        ERROR("Failed to release isulad engines list write lock");
        ret = -1;
    }

    return ret;
}

/* engines check handler exist */
static struct engine_operation *engines_check_handler_exist(const char *name)
{
    struct engine_operation *engine_op = NULL;
    struct linked_list *it = NULL;
    struct linked_list *next = NULL;

    if (name == NULL) {
        goto out;
    }

    if (pthread_rwlock_rdlock(&g_isulad_engines_lists.isulad_engines_op_rwlock)) {
        ERROR("Failed to acquire isulad engines list read lock");
        engine_op = NULL;
        goto out;
    }

    linked_list_for_each_safe(it, &g_isulad_engines_lists.isulad_engines_op_list, next) {
        engine_op = (struct engine_operation *)it->elem;
        if (engine_op == NULL) {
            DEBUG("Invalid engine list elem");
            linked_list_del(it);
            continue;
        }
        if (strcasecmp(name, engine_op->engine_type) == 0) {
            /* find the matched handle */
            break;
        }
        engine_op = NULL;
    }

    if (pthread_rwlock_unlock(&g_isulad_engines_lists.isulad_engines_op_rwlock)) {
        CRIT("Failed to release isulad engines list read lock");
        engine_op = NULL;
        goto out;
    }

out:
    return engine_op;
}

/*
 * get the engine operation by engine name,
 * if not exist in the list, try to discovery it, and then get it again
 */
struct engine_operation *engines_get_handler(const char *name)
{
    struct engine_operation *engine_op = NULL;

    if (name == NULL) {
        ERROR("Runtime is NULL");
        engine_op = NULL;
        goto out;
    }

    engine_op = engines_check_handler_exist(name);
    if (engine_op != NULL) {
        goto out;
    }

    if (engines_discovery(name)) {
        engine_op = NULL;
        goto out;
    }

    engine_op = engines_check_handler_exist(name);
    if (engine_op != NULL) {
        goto out;
    }

out:
    return engine_op;
}
