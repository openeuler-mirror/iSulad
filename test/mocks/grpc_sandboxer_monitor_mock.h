/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-07-31
 * Description: provide grpc sandboxer client monitor mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_GRPC_SANDBOXER_MONITOR_MOCK_H
#define _ISULAD_TEST_MOCKS_GRPC_SANDBOXER_MONITOR_MOCK_H

#include <gmock/gmock.h>
#include "grpc_sandboxer_monitor.h"

using namespace sandbox;

class SandboxerClientMonitorMock {
public:
    MOCK_METHOD1(Monitor, bool(SandboxerAsyncWaitCall *call));
    MOCK_METHOD0(Start, void());
    MOCK_METHOD0(Stop, void());
};

void MockSandboxerMonitor_SetMock(std::shared_ptr<SandboxerClientMonitorMock> mock);

#endif // _ISULAD_TEST_MOCKS_GRPC_SANDBOXER_MONITOR_MOCK_H
