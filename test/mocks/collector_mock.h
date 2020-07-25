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

#ifndef _ISULAD_TEST_MOCKS_COLLECTOR_MOCK_H
#define _ISULAD_TEST_MOCKS_COLLECTOR_MOCK_H

#include <gmock/gmock.h>
#include "events_collector_api.h"

class MockCollector {
public:
    MOCK_METHOD4(EventsSubscribe, int(const char *name, const types_timestamp_t *since, const types_timestamp_t *until,
                                      const stream_func_wrapper *stream));
    MOCK_METHOD4(AddMonitorClient, int(const char *name, const types_timestamp_t *since, const types_timestamp_t *until,
                                       const stream_func_wrapper *stream));
    MOCK_METHOD6(IsuladMonitorSendContainerEvent, int(const char *name, runtime_state_t state, int pid, int exit_code,
                                                      const char *args, const char *extra_annations));
};

void MockCollector_SetMock(MockCollector *mock);

#endif
