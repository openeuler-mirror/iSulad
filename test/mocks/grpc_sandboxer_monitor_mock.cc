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

#include "grpc_sandboxer_monitor_mock.h"

static std::shared_ptr<SandboxerClientMonitorMock> g_sandboxer_client_monitor_mock = NULL;


SandboxerClientMonitor::SandboxerClientMonitor(std::shared_ptr<grpc::Channel> channel, const std::string &sandboxer):
    m_channel(channel), m_sandboxer(sandboxer) ,m_teardown(false) {}

void SandboxerClientMonitor::Start()
{
    if (g_sandboxer_client_monitor_mock == NULL) {
        return;
    }
    return g_sandboxer_client_monitor_mock->Start();
}

void SandboxerClientMonitor::Stop()
{
    if (g_sandboxer_client_monitor_mock == NULL) {
        return;
    }
    return g_sandboxer_client_monitor_mock->Stop();
}

bool SandboxerClientMonitor::Monitor(SandboxerAsyncWaitCall *call)
{
    if (g_sandboxer_client_monitor_mock == NULL) {
        return true;
    }
    return g_sandboxer_client_monitor_mock->Monitor(call);
}

void MockSandboxerMonitor_SetMock(std::shared_ptr<SandboxerClientMonitorMock> mock)
{
    g_sandboxer_client_monitor_mock = mock;
}
