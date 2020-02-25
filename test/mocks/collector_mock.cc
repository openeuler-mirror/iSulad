/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: jikui
 * Create: 2020-02-25
 * Description: provide collector mock
 ******************************************************************************/

#include "collector_mock.h"

namespace {
MockCollector *g_collector_mock = NULL;
}

void MockCollector_SetMock(MockCollector *mock)
{
    g_collector_mock = mock;
}

int events_subscribe(const char *name, const types_timestamp_t *since, const types_timestamp_t *until,
                     const stream_func_wrapper *stream)
{
    if (g_collector_mock != nullptr) {
        return g_collector_mock->EventsSubscribe(name, since, until, stream);
    }
    return 0;
}

int add_monitor_client(char *name, const types_timestamp_t *since, const types_timestamp_t *until,
                       const stream_func_wrapper *stream)
{
    if (g_collector_mock != nullptr) {
        return g_collector_mock->AddMonitorClient(name, since, until, stream);
    }
    return 0;
}
