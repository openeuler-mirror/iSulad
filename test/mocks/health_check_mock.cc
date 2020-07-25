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
 * Description: provide health_check mock
 ******************************************************************************/

#include "health_check_mock.h"

namespace {
MockHealthCheck *g_health_check_mock = NULL;
}

void MockHealthCheck_SetMock(MockHealthCheck *mock)
{
    g_health_check_mock = mock;
}

void container_update_health_monitor(const char *container_id)
{
    if (g_health_check_mock != nullptr) {
        return g_health_check_mock->UpdateHealthMonitor(container_id);
    }
    return;
}
