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
 * Create: 2019-11-14
 * Description: provide runtime functions
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <sys/utsname.h>
#include <ctype.h>

#include "runtime.h"
#include "engine.h"
#include "isulad_config.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "lcr_rt_ops.h"
#include "isula_rt_ops.h"

static const struct rt_ops g_lcr_rt_ops = {
    .detect = rt_lcr_detect,
    .rt_create = rt_lcr_create,
    .rt_start = rt_lcr_start,
    .rt_restart = rt_lcr_restart,
    .rt_clean_resource = rt_lcr_clean_resource,
    .rt_rm = rt_lcr_rm,
    .rt_status = rt_lcr_status,
    .rt_exec = rt_lcr_exec,
    .rt_pause = rt_lcr_pause,
    .rt_resume = rt_lcr_resume,
    .rt_attach = rt_lcr_attach,
    .rt_update = rt_lcr_update,
    .rt_listpids = rt_lcr_listpids,
    .rt_resources_stats = rt_lcr_resources_stats,
    .rt_resize = rt_lcr_resize,
    .rt_exec_resize = rt_lcr_exec_resize,
};

static const struct rt_ops g_isula_rt_ops = {
    .detect = rt_isula_detect,
    .rt_create = rt_isula_create,
    .rt_start = rt_isula_start,
    .rt_restart = rt_isula_restart,
    .rt_clean_resource = rt_isula_clean_resource,
    .rt_rm = rt_isula_rm,
    .rt_status = rt_isula_status,
    .rt_exec = rt_isula_exec,
    .rt_pause = rt_isula_pause,
    .rt_resume = rt_isula_resume,
    .rt_attach = rt_isula_attach,
    .rt_update = rt_isula_update,
    .rt_listpids = rt_isula_listpids,
    .rt_resources_stats = rt_isula_resources_stats,
    .rt_resize = rt_isula_resize,
    .rt_exec_resize = rt_isula_exec_resize,
};

static const struct rt_ops *g_rt_ops[] = {
    &g_lcr_rt_ops,
    &g_isula_rt_ops,
};

static const size_t g_rt_nums = sizeof(g_rt_ops) / sizeof(struct rt_ops *);

static const struct rt_ops *rt_ops_query(const char *runtime)
{
    size_t i;

    for (i = 0; i < g_rt_nums; i++) {
        bool r = g_rt_ops[i]->detect(runtime);
        if (r) {
            break;
        }
    }

    if (i == g_rt_nums) {
        return NULL;
    }
    return g_rt_ops[i];
}

int runtime_create(const char *name, const char *runtime, const rt_create_params_t *params)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL) {
        ERROR("Invalide arguments for runtime create");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops for %s", runtime);
        ret = -1;
        goto out;
    }

    ret = ops->rt_create(name, runtime, params);

out:
    return ret;
}

int runtime_start(const char *name, const char *runtime, const rt_start_params_t *params, container_pid_t *pid_info)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL || pid_info == NULL) {
        ERROR("Invalide arguments for runtime start");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_start(name, runtime, params, pid_info);

out:
    return ret;
}

int runtime_restart(const char *name, const char *runtime, const rt_restart_params_t *params)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL) {
        ERROR("Invalide arguments for runtime restart");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_restart(name, runtime, params);

out:
    return ret;
}

int runtime_clean_resource(const char *name, const char *runtime, const rt_clean_params_t *params)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL) {
        ERROR("Invalide arguments for runtime clean");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_clean_resource(name, runtime, params);

out:
    return ret;
}

int runtime_rm(const char *name, const char *runtime, const rt_rm_params_t *params)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL) {
        ERROR("Invalide arguments for runtime rm");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_rm(name, runtime, params);

out:
    return ret;
}

int runtime_status(const char *name, const char *runtime, const rt_status_params_t *params,
                   struct runtime_container_status_info *status)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL || status == NULL) {
        ERROR("Invalide arguments for runtime status");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_status(name, runtime, params, status);

out:
    return ret;
}

int runtime_resources_stats(const char *name, const char *runtime, const rt_stats_params_t *params,
                            struct runtime_container_resources_stats_info *rs_stats)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL || rs_stats == NULL) {
        ERROR("Invalide arguments for runtime stats");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_resources_stats(name, runtime, params, rs_stats);

out:
    return ret;
}

int runtime_exec(const char *name, const char *runtime, const rt_exec_params_t *params, int *exit_code)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL || exit_code == NULL) {
        ERROR("Invalide arguments for runtime exec");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_exec(name, runtime, params, exit_code);

out:
    return ret;
}

int runtime_pause(const char *name, const char *runtime, const rt_pause_params_t *params)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalide arguments for runtime pause");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_pause(name, runtime, params);

out:
    return ret;
}

int runtime_resume(const char *name, const char *runtime, const rt_resume_params_t *params)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalide arguments for runtime resume");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_resume(name, runtime, params);

out:
    return ret;
}

int runtime_attach(const char *name, const char *runtime, const rt_attach_params_t *params)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalide arguments for runtime attach");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_attach(name, runtime, params);

out:
    return ret;
}

int runtime_update(const char *name, const char *runtime, const rt_update_params_t *params)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalide arguments for runtime update");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_update(name, runtime, params);

out:
    return ret;
}

void free_rt_listpids_out_t(rt_listpids_out_t *out)
{
    if (out == NULL) {
        return;
    }

    free(out->pids);
    out->pids = NULL;
    free(out);
}

int runtime_listpids(const char *name, const char *runtime, const rt_listpids_params_t *params, rt_listpids_out_t *out)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL || out == NULL) {
        ERROR("Invalide arguments for runtime listpids");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_listpids(name, runtime, params, out);

out:
    return ret;
}

int runtime_resize(const char *name, const char *runtime, const rt_resize_params_t *params)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalide arguments for runtime resize");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_resize(name, runtime, params);

out:
    return ret;
}

int runtime_exec_resize(const char *name, const char *runtime, const rt_exec_resize_params_t *params)
{
    int ret = 0;
    const struct rt_ops *ops = NULL;

    if (name == NULL || runtime == NULL || params == NULL) {
        ERROR("Invalide arguments for runtime exec resize");
        ret = -1;
        goto out;
    }

    ops = rt_ops_query(runtime);
    if (ops == NULL) {
        ERROR("Failed to get runtime ops");
        ret = -1;
        goto out;
    }

    ret = ops->rt_exec_resize(name, runtime, params);

out:
    return ret;
}

int runtime_init()
{
    int ret = 0;
    char *engine = NULL;

    engine = conf_get_isulad_engine();
    if (engine == NULL) {
        ret = -1;
        goto out;
    }

    if (engines_global_init()) {
        ERROR("Init engines global failed");
        ret = -1;
        goto out;
    }

    /* Init default engine, now is lcr */
    if (engines_discovery(engine)) {
        ERROR("Failed to discovery default engine:%s", engine);
        ret = -1;
    }

out:
    free(engine);
    return ret;
}
