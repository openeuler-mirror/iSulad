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
 * Description: provide collector mock
 ******************************************************************************/

#include "collector_mock.h"

namespace {
MockCollector *g_collector_mock = nullptr;
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

int isulad_monitor_send_container_event(const char *name, runtime_state_t state, int pid, int exit_code,
                                        const char *args, const char *extra_annations)
{
    if (g_collector_mock != nullptr) {
        return g_collector_mock->IsuladMonitorSendContainerEvent(name, state, pid, exit_code, args, extra_annations);
    }
    return 0;
}
