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
 * Author: liuxu
 * Create: 2024-11-22
 * Description: provide rust sandbox api mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_RUST_SANDBOX_API_MOCK_H
#define _ISULAD_TEST_MOCKS_RUST_SANDBOX_API_MOCK_H

#include <gmock/gmock.h>
#include <isula_sandbox_api.h>

class RustSandboxApiMock {
public:
    RustSandboxApiMock() = default;
    MOCK_METHOD2(sandbox_api_build_controller, ControllerHandle_t(const char *sandboxer, const char *address));
    MOCK_METHOD3(sandbox_api_create, int(ControllerHandle_t chandle, const sandbox_create_request *request, sandbox_create_response *response));
    MOCK_METHOD3(sandbox_api_start, int(ControllerHandle_t chandle, const sandbox_start_request *request, sandbox_start_response *response));
    MOCK_METHOD2(sandbox_api_stop, int(ControllerHandle_t chandle, const sandbox_stop_request *request));
    MOCK_METHOD3(sandbox_api_wait, int(ControllerHandle_t chandle, const sandbox_wait_request *request, sandbox_api_wait_callback callback));
    MOCK_METHOD3(sandbox_api_status, int(ControllerHandle_t chandle, const sandbox_status_request *request, sandbox_status_response *response));
    MOCK_METHOD2(sandbox_api_shutdown, int(ControllerHandle_t chandle, const sandbox_shutdown_request *request));
    MOCK_METHOD3(sandbox_api_metrics, int(ControllerHandle_t chandle, const sandbox_metrics_request *request, sandbox_metrics_response *response));
    MOCK_METHOD3(sandbox_api_platform, int(ControllerHandle_t chandle, const sandbox_platform_request *request, sandbox_platform_response *response));
    MOCK_METHOD2(sandbox_api_update, int(ControllerHandle_t chandle, const sandbox_update_request *request));
};

void RustSandboxApiMock_SetMock(std::shared_ptr<RustSandboxApiMock> mock);

#endif // _ISULAD_TEST_MOCKS_RUST_SANDBOX_API_MOCK_H
