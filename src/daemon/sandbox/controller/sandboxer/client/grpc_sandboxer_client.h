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

#include "sandbox/types/mount.pb.h"
#include "sandbox.pb.h"
#include "sandbox.grpc.pb.h"
#include "controller.h"

using containerd::types::Mount;
using google::protobuf::Timestamp;

namespace sandbox {

class SandboxerClient {
public:
    SandboxerClient(const std::string &sandboxer, const std::string &address);

    ~SandboxerClient() = default;

    auto Create(const std::string &sandboxId, const ControllerCreateParams &params, Errors &error) -> bool;

    auto Start(const std::string &sandboxId, ControllerSandboxInfo &sandboxInfo, Errors &error) -> bool;

    auto Platform(const std::string &sandboxId, ControllerPlatformInfo &platformInfo, Errors &error) -> bool;

    auto Prepare(const std::string &sandboxId, const ControllerPrepareParams &params, std::string &bundle, Errors &error) -> bool;

    auto Purge(const std::string &sandboxId, const std::string &containerId,
               const std::string &execId, Errors &error) -> bool;

    auto UpdateResources(const std::string &sandboxId, const ControllerUpdateResourcesParams &params, Errors &error) -> bool;

    auto Stop(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error) -> bool;

    auto Wait(const std::string &sandboxId, Errors &error) -> bool;

    auto Status(const std::string &sandboxId, bool verbose, ControllerSandboxStatus &sandboxStatus, Errors &error) -> bool;

    auto Shutdown(const std::string &sandboxId, Errors &error) -> bool;

private:
    void InitMountInfo(Mount &mount, const ControllerMountInfo &mountInfo);
    auto InitCreateRequest(containerd::services::sandbox::v1::ControllerCreateRequest &request,
                           const std::string &sandboxId,
                           const ControllerCreateParams &params) -> bool;
    auto TimestampToNanos(const Timestamp &timestamp) -> uint64_t;
    void StartResponseToSandboxInfo(const containerd::services::sandbox::v1::ControllerStartResponse &response,
                                    ControllerSandboxInfo &sandboxInfo);
    auto InitPrepareRequest(containerd::services::sandbox::v1::PrepareRequest &request,
                            const std::string &sandboxId, const ControllerPrepareParams &params) -> bool;
    auto InitUpdateResourcesRequest(containerd::services::sandbox::v1::UpdateResourcesRequest &request,
                                    const std::string &sandboxId,
                                    const ControllerUpdateResourcesParams &params) -> bool;
    void PlatformResponseToPlatformInfo(const containerd::services::sandbox::v1::ControllerPlatformResponse &response,
                                        ControllerPlatformInfo &platformInfo);
    void StatusResponseToSandboxStatus(const containerd::services::sandbox::v1::ControllerStatusResponse &response,
                                       ControllerSandboxStatus &sandboxStatus);
    std::string m_sandboxer;
    std::string m_address;

protected:
    std::unique_ptr<containerd::services::sandbox::v1::Controller::StubInterface> stub_;
};

} // namespace
#endif // DAEON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_H