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

#include "rust_sandbox_api_mock.h"

static std::shared_ptr<RustSandboxApiMock> g_rust_sandbox_api_mock = NULL;

void RustSandboxApiMock_SetMock(std::shared_ptr<RustSandboxApiMock> mock)
{
    g_rust_sandbox_api_mock = mock;
}

ControllerHandle_t sandbox_api_build_controller(const char *sandboxer, const char *address)
{
    if (g_rust_sandbox_api_mock != nullptr) {
        return g_rust_sandbox_api_mock->sandbox_api_build_controller(sandboxer, address);
    }
    return nullptr;
}

int sandbox_api_create(ControllerHandle_t chandle, const sandbox_create_request *request, sandbox_create_response *response)
{
    if (g_rust_sandbox_api_mock != nullptr) {
        return g_rust_sandbox_api_mock->sandbox_api_create(chandle, request, response);
    }
    return 0;
}

int sandbox_api_start(ControllerHandle_t chandle, const sandbox_start_request *request, sandbox_start_response *response)
{
    if (g_rust_sandbox_api_mock != nullptr) {
        return g_rust_sandbox_api_mock->sandbox_api_start(chandle, request, response);
    }
    return 0;
}

int sandbox_api_platform(ControllerHandle_t chandle, const sandbox_platform_request *request, sandbox_platform_response *response)
{
    if (g_rust_sandbox_api_mock != nullptr) {
        return g_rust_sandbox_api_mock->sandbox_api_platform(chandle, request, response);
    }
    return 0;
}

int sandbox_api_stop(ControllerHandle_t chandle, const sandbox_stop_request *request)
{
    if (g_rust_sandbox_api_mock != nullptr) {
        return g_rust_sandbox_api_mock->sandbox_api_stop(chandle, request);
    }
    return 0;
}

int sandbox_api_wait(ControllerHandle_t chandle, const sandbox_wait_request *request, sandbox_api_wait_callback callback)
{
    if (g_rust_sandbox_api_mock != nullptr) {
        return g_rust_sandbox_api_mock->sandbox_api_wait(chandle, request, callback);
    }
    return 0;
}

int sandbox_api_status(ControllerHandle_t chandle, const sandbox_status_request *request, sandbox_status_response *response)
{
    if (g_rust_sandbox_api_mock != nullptr) {
        return g_rust_sandbox_api_mock->sandbox_api_status(chandle, request, response);
    }
    return 0;
}

int sandbox_api_shutdown(ControllerHandle_t chandle, const sandbox_shutdown_request *request)
{
    if (g_rust_sandbox_api_mock != nullptr) {
        return g_rust_sandbox_api_mock->sandbox_api_shutdown(chandle, request);
    }
    return 0;
}

int sandbox_api_metrics(ControllerHandle_t chandle, const sandbox_metrics_request *request, sandbox_metrics_response *response)
{
    if (g_rust_sandbox_api_mock != nullptr) {
        return g_rust_sandbox_api_mock->sandbox_api_metrics(chandle, request, response);
    }
    return 0;
}

int sandbox_api_update(ControllerHandle_t chandle, const sandbox_update_request *request)
{
    if (g_rust_sandbox_api_mock != nullptr) {
        return g_rust_sandbox_api_mock->sandbox_api_update(chandle, request);
    }
    return 0;
}
