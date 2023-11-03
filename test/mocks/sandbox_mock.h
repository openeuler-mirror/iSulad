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
 * Author: zhongtao
 * Create: 2023-07-18
 * Description: provide sandbox mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_SANDBOX_MOCK_H
#define _ISULAD_TEST_MOCKS_SANDBOX_MOCK_H

#include <gmock/gmock.h>
#include "sandbox.h"

namespace sandbox {

class MockSandbox {
public:
    MockSandbox() = default;
    virtual ~MockSandbox() = default;

    MOCK_METHOD0(IsReady, bool());
    MOCK_METHOD0(GetId, const std::string & ());
    MOCK_METHOD0(GetName, const std::string & ());
    MOCK_METHOD0(GetSandboxer, const std::string & ());
    MOCK_METHOD0(GetRuntimeHandle, const std::string & ());
    MOCK_METHOD0(GetSandboxConfig, const runtime::v1::PodSandboxConfig &());
    MOCK_METHOD0(GetMutableSandboxConfig, std::shared_ptr<runtime::v1::PodSandboxConfig>());
    MOCK_METHOD0(GetRootDir, const std::string & ());
    MOCK_METHOD0(GetStateDir, std::string & ());
    MOCK_METHOD0(GetResolvPath, std::string());
    MOCK_METHOD0(GetShmPath, std::string());
    MOCK_METHOD0(GetStatsInfo, StatsInfo());
    MOCK_METHOD0(GetNetworkReady, bool());

    MOCK_METHOD1(SetController, void(std::shared_ptr<Controller> controller));
    MOCK_METHOD2(AddAnnotations, void(const std::string &key, const std::string &value));
    MOCK_METHOD1(RemoveAnnotations, void(const std::string &key));
    MOCK_METHOD2(AddLabels, void(const std::string &key, const std::string &value));
    MOCK_METHOD1(RemoveLabels, void(const std::string &key));
    MOCK_METHOD2(UpdateNetworkSettings, void(const std::string &settingsJson, Errors &error));
    MOCK_METHOD1(UpdateStatsInfo, StatsInfo(const StatsInfo &info));
    MOCK_METHOD1(SetNetworkReady, void(bool ready));

    MOCK_METHOD1(Save, bool(Errors &error));
    MOCK_METHOD1(Load, bool(Errors &error));
    MOCK_METHOD1(OnSandboxExit, void(const ControllerExitInfo &exitInfo));
    MOCK_METHOD1(UpdateStatus, bool(Errors &error));
    MOCK_METHOD1(Create, bool(Errors &error));
    MOCK_METHOD1(Start, bool(Errors &error));
    MOCK_METHOD2(Stop, bool(uint32_t timeoutSecs, Errors &error));
    MOCK_METHOD1(Remove, bool(Errors &error));
    MOCK_METHOD1(Status, void(runtime::v1::PodSandboxStatus &status));
};

void MockSandbox_SetMock(MockSandbox *mock);

}

#endif
