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
 * Author: xuxuepeng
 * Create: 2023-01-18
 * Description: provide sandbox controller functions
 ******************************************************************************/

#include "controller_api.h"
#include "isula_libutils/log.h"
#include "proxy_ctrl_ops.h"
#include "shim_ctrl_ops.h"

#define CONTROLLER_GET_OPS(sandboxer) \
    const struct sb_ctrl_ops *ops = NULL; \
    ops = get_ctrl_ops(sandboxer); \
    if (ops == NULL) { \
        ERROR("Failed to get sandboxer, %s", sandboxer); \
        ret = -1; \
        break; \
    }

#define CONTROLLER_EXECUTE_OPER_ARG0(ctrl_op, sandboxer, sandbox_id) \
do { \
    CONTROLLER_GET_OPS(sandboxer) \
    if (ops->ctrl_op(sandboxer, sandbox_id) != 0) { \
        ERROR("Failed to execute sandboxer "#ctrl_op", %s", sandboxer); \
        ret = -1; \
    } \
    DEBUG("Finish sandboxer execution: "#ctrl_op); \
} while(0)

#define CONTROLLER_EXECUTE_OPER_ARG1(ctrl_op, sandboxer, sandbox_id, arg1) \
do { \
    CONTROLLER_GET_OPS(sandboxer) \
    if (ops->ctrl_op(sandboxer, sandbox_id, arg1) != 0) { \
        ERROR("Failed to execute sandboxer "#ctrl_op", %s", sandboxer); \
        ret = -1; \
    } \
    DEBUG("Finish sandboxer execution: "#ctrl_op); \
} while(0)

#define CONTROLLER_EXECUTE_OPER_ARG2(ctrl_op, sandboxer, sandbox_id, arg1, arg2) \
do { \
    CONTROLLER_GET_OPS(sandboxer) \
    if (ops->ctrl_op(sandboxer, sandbox_id, arg1, arg2) != 0) { \
        ERROR("Failed to execute sandboxer "#ctrl_op", %s", sandboxer); \
        ret = -1; \
    } \
    DEBUG("Finish sandboxer execution: "#ctrl_op); \
} while(0)

static const struct sb_ctrl_ops g_shim_sb_ctrl_ops = {
    .init = ctrl_shim_init,
    .detect = ctrl_shim_detect,
    .create = ctrl_shim_create,
    .start = ctrl_shim_start,
    .platform = ctrl_shim_platform,
    .prepare = ctrl_shim_prepare,
    .purge = ctrl_shim_purge,
    .update_resources = ctrl_shim_update_resources,
    .stop = ctrl_shim_stop,
    .wait = ctrl_shim_wait,
    .status = ctrl_shim_status,
    .shutdown = ctrl_shim_shutdown
};

static const struct sb_ctrl_ops g_proxy_sb_ctrl_ops = {
    .init = ctrl_proxy_init,
    .detect = ctrl_proxy_detect,
    .create = ctrl_proxy_create,
    .start = ctrl_proxy_start,
    .platform = ctrl_proxy_platform,
    .prepare = ctrl_proxy_prepare,
    .purge = ctrl_proxy_purge,
    .update_resources = ctrl_proxy_update_resources,
    .stop = ctrl_proxy_stop,
    .wait = ctrl_proxy_wait,
    .status = ctrl_proxy_status,
    .shutdown = ctrl_proxy_shutdown
};

static const struct sb_ctrl_ops* g_sb_ctrl_ops_list[] = {
    &g_shim_sb_ctrl_ops,
    &g_proxy_sb_ctrl_ops
};

static const size_t g_ctrl_ops_nums = sizeof(g_sb_ctrl_ops_list) / sizeof(const struct sb_ctrl_ops *);

static const struct sb_ctrl_ops *get_ctrl_ops(const char *sandboxer) {
    for (size_t i = 0; i < g_ctrl_ops_nums; i++) {
        if (g_sb_ctrl_ops_list[i]->detect(sandboxer)) {
            return g_sb_ctrl_ops_list[i];
        }
    }
    return NULL;
}

int sandbox_ctrl_init()
{
    int ret = 0;
    INFO("Initialize sandbox controller");
    if (!g_shim_sb_ctrl_ops.init()) {
        ERROR("Failed to initialize sandbox shim controller");
        ret = -1;
    }
    if (!g_proxy_sb_ctrl_ops.init()) {
        ERROR("Failed to initialize sandbox proxy controller");
        ret = -1;
    }
    return ret;
}

int sandbox_ctrl_create(const char *sandboxer, const char *sandbox_id,
                        const ctrl_create_params_t *params)
{
    int ret = 0;
    CONTROLLER_EXECUTE_OPER_ARG1(create, sandboxer, sandbox_id, params);
    return ret;
}

int sandbox_ctrl_start(const char *sandboxer, const char *sandbox_id)
{
    int ret = 0;
    CONTROLLER_EXECUTE_OPER_ARG0(start, sandboxer, sandbox_id);
    return ret;
}

int sandbox_ctrl_platform(const char *sandboxer, const char *sandbox_id,
                          ctrl_platform_response_t *response)
{
    int ret = 0;
    CONTROLLER_EXECUTE_OPER_ARG1(platform, sandboxer, sandbox_id, response);
    return ret;
}

int sandbox_ctrl_prepare(const char *sandboxer, const char *sandbox_id,
                         const ctrl_prepare_params_t *params,
                         ctrl_prepare_response_t *response)
{
    int ret = 0;
    CONTROLLER_EXECUTE_OPER_ARG2(prepare, sandboxer, sandbox_id, params, response);
    return ret;
}

int sandbox_ctrl_purge(const char *sandboxer, const char *sandbox_id,
                       const ctrl_purge_params_t *params)
{
    int ret = 0;
    CONTROLLER_EXECUTE_OPER_ARG1(purge, sandboxer, sandbox_id, params);
    return ret;
}

int sandbox_ctrl_update_resources(const char *sandboxer, const char *sandbox_id,
                                  const ctrl_update_resources_params_t *params)
{
    int ret = 0;
    CONTROLLER_EXECUTE_OPER_ARG1(update_resources, sandboxer, sandbox_id, params);
    return ret;
}

int sandbox_ctrl_stop(const char *sandboxer, const char *sandbox_id, uint32_t timeout)
{
    int ret = 0;
    CONTROLLER_EXECUTE_OPER_ARG1(stop, sandboxer, sandbox_id, timeout);
    return ret;
}

int sandbox_ctrl_wait(const char *sandboxer, const char *sandbox_id,
                      uint32_t *exit_status, uint64_t *exited_at)
{
    int ret = 0;
    CONTROLLER_EXECUTE_OPER_ARG2(wait, sandboxer, sandbox_id, exit_status, exited_at);
    return ret;
}

int sandbox_ctrl_status(const char *sandboxer, const char *sandbox_id,
                        bool verbose, ctrl_status_response_t *response)
{
    int ret = 0;
    CONTROLLER_EXECUTE_OPER_ARG2(status, sandboxer, sandbox_id, verbose, response);
    return ret;
}

int sandbox_ctrl_shutdown(const char *sandboxer, const char *sandbox_id)
{
    int ret = 0;
    CONTROLLER_EXECUTE_OPER_ARG0(shutdown, sandboxer, sandbox_id);
    return ret;
}
