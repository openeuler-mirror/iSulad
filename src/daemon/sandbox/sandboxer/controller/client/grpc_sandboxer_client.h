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
 * Create: 2023-07-10
 * Description: Sandboxer grpc client
 ******************************************************************************/

#ifndef DAEON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_H
#define DAEON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_H

#include <string>
#include <memory>
#include <future>

#include <isula_sandbox_api.h>

#include "controller.h"
#include "utils_array.h"

namespace sandbox {

class SandboxerClient {
public:
    SandboxerClient(const std::string &sandboxer, const std::string &address);

    ~SandboxerClient() = default;

    auto Create(const std::string &sandboxId, const ControllerCreateParams &params, Errors &error) -> bool;

    auto Start(const std::string &sandboxId, ControllerSandboxInfo &sandboxInfo, Errors &error) -> bool;

    auto Platform(const std::string &sandboxId, ControllerPlatformInfo &platformInfo, Errors &error) -> bool;

    auto Update(sandbox_sandbox *apiSandbox, string_array *fields, Errors &error) -> bool;

    auto Stop(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error) -> bool;

    auto Wait(std::shared_ptr<SandboxStatusCallback> cb, const std::string &sandboxId, Errors &error) -> bool;

    auto Status(const std::string &sandboxId, bool verbose, ControllerSandboxStatus &sandboxStatus, Errors &error) -> bool;

    auto Shutdown(const std::string &sandboxId, Errors &error) -> bool;

private:
    auto InitMountInfo(sandbox_mount &m, const ControllerMountInfo &mountInfo) -> int;
    auto InitCreateRequest(sandbox_create_request &request,
                           const std::string &sandboxId,
                           const ControllerCreateParams &params) -> bool;
    void StartResponseToSandboxInfo(sandbox_start_response &response,
                                    ControllerSandboxInfo &sandboxInfo);
    void InitUpdateRequest(sandbox_update_request &request,
                           sandbox_sandbox *apiSandbox, string_array *fields);

    void PlatformResponseToPlatformInfo(sandbox_platform_response &response,
                                        ControllerPlatformInfo &platformInfo);
    void StatusResponseToSandboxStatus(sandbox_status_response &response,
                                       ControllerSandboxStatus &sandboxStatus);
protected:
    std::string m_sandboxer;
    std::string m_address;
    ControllerHandle_t m_controller_handle;
};

} // namespace
#endif // DAEON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_H