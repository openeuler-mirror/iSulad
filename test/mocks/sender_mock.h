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
 * Create: 2024-03-30
 * Description: provide sender mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_SENDER_MOCK_H
#define _ISULAD_TEST_MOCKS_SENDER_MOCK_H

#include <gmock/gmock.h>
#include "events_sender_api.h"

class MockEventSender {
public:
    MOCK_METHOD6(IsuladMonitorEventSendContainerEvent, int(const char *name, runtime_state_t state, int pid, int exit_code,
                                                       const char *args, const char *extra_annations));
};

void MockEventSender_SetMock(MockEventSender *mock);

#endif

