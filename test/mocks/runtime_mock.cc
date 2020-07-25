/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: jikui
 * Create: 2020-02-25
 * Description: provide runtime mock
 ******************************************************************************/

#include "runtime_mock.h"

namespace {
MockRuntime *g_runtime_mock = NULL;
}

void MockRuntime_SetMock(MockRuntime *mock)
{
    g_runtime_mock = mock;
}

int runtime_pause(const char *name, const char *runtime, const rt_pause_params_t *params)
{
    if (g_runtime_mock != nullptr) {
        return g_runtime_mock->RuntimePause(name, runtime, params);
    }
    return 0;
}

int runtime_resources_stats(const char *name, const char *runtime, const rt_stats_params_t *params,
                            struct runtime_container_resources_stats_info *rs_stats)
{
    if (g_runtime_mock != nullptr) {
        return g_runtime_mock->RuntimeResourcesStats(name, runtime, params, rs_stats);
    }
    return 0;
}

int runtime_resume(const char *name, const char *runtime, const rt_resume_params_t *params)
{
    if (g_runtime_mock != nullptr) {
        return g_runtime_mock->RuntimeResume(name, runtime, params);
    }
    return 0;
}

int runtime_update(const char *name, const char *runtime, const rt_update_params_t *params)
{
    if (g_runtime_mock != nullptr) {
        return g_runtime_mock->RuntimeUpdate(name, runtime, params);
    }
    return 0;
}

int runtime_resize(const char *name, const char *runtime, const rt_resize_params_t *params)
{
    if (g_runtime_mock != nullptr) {
        return g_runtime_mock->RuntimeResize(name, runtime, params);
    }
    return 0;
}

int runtime_exec_resize(const char *name, const char *runtime, const rt_exec_resize_params_t *params)
{
    if (g_runtime_mock != nullptr) {
        return g_runtime_mock->RuntimeExecResize(name, runtime, params);
    }
    return 0;
}
