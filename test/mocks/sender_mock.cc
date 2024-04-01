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
 * Author: jikai
 * Create: 2024-03-29
 * Description: provide collector mock
 ******************************************************************************/

#include "sender_mock.h"

namespace {
MockEventSender *g_sender_mock = nullptr;
}

void MockEventSender_SetMock(MockEventSender *mock)
{
    g_sender_mock = mock;
}

int isulad_monitor_send_container_event(const char *name, runtime_state_t state, int pid, int exit_code,
                                        const char *args, const char *extra_annations)
{
    if (g_sender_mock != nullptr) {
        return g_sender_mock->IsuladMonitorEventSendContainerEvent(name, state, pid, exit_code, args, extra_annations);
    }
    return 0;
}
