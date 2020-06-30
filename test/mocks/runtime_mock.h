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

#ifndef RUNTIME_MOCK_H_
#define RUNTIME_MOCK_H_

#include <gmock/gmock.h>
#include "runtime_api.h"

class MockRuntime {
public:
    MOCK_METHOD3(RuntimePause, int(const char *name, const char *runtime, const rt_pause_params_t *params));
    MOCK_METHOD3(RuntimeResume, int(const char *name, const char *runtime, const rt_resume_params_t *params));
    MOCK_METHOD3(RuntimeUpdate, int(const char *name, const char *runtime, const rt_update_params_t *params));
    MOCK_METHOD3(RuntimeResize, int(const char *name, const char *runtime, const rt_resize_params_t *params));
    MOCK_METHOD3(RuntimeExecResize, int(const char *name, const char *runtime, const rt_exec_resize_params_t *params));
    MOCK_METHOD4(RuntimeResourcesStats, int(const char *name, const char *runtime, const rt_stats_params_t *params,
                                            struct runtime_container_resources_stats_info *rs_stats));
};

void MockRuntime_SetMock(MockRuntime *mock);

#endif
