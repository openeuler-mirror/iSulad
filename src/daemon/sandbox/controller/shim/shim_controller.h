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
 * Create: 2023-06-15
 * Description: Provide shim controller class definition.
 *              Shim controller sends requests to executor internally for sandbox management.
 *              It uses the traditional way to create pause container as sandbox.
 *********************************************************************************/

#ifndef DAEMON_SANDBOX_CONTROLLER_SHIM_CONTROLLER_H
#define DAEMON_SANDBOX_CONTROLLER_SHIM_CONTROLLER_H

#include "controller.h"

#include <isula_libutils/container_config.h>
#include <isula_libutils/container_create_request.h>
#include <isula_libutils/container_inspect.h>
#include <isula_libutils/container_sandbox_info.h>
#include <isula_libutils/host_config.h>
#include <memory>

#include "callback.h"
#include "cstruct_wrapper.h"

namespace sandbox {

const std::string SHIM_CONTROLLER_NAME = "shim";

class ShimController : public Controller {
public:
    ShimController(const std::string &sandboxer);
    virtual ~ShimController();
    bool Init(Errors &error) override;
    void Destroy() override;
    bool Create(const std::string &sandboxId,
                const ControllerCreateParams &params,
                Errors &error) override;
    std::unique_ptr<ControllerSandboxInfo> Start(const std::string &sandboxId, Errors &error) override;
    std::unique_ptr<ControllerPlatformInfo> Platform(const std::string &sandboxId, Errors &error) override;
    std::string Prepare(const std::string &sandboxId,
                        const ControllerPrepareParams &params,
                        Errors &error) override;
    bool Purge(const std::string &sandboxId, const std::string &containerId,
               const std::string &execId, Errors &error) override;
    bool UpdateResources(const std::string &sandboxId,
                         const ControllerUpdateResourcesParams &params,
                         Errors &error) override;
    bool Stop(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error) override;
    bool Wait(std::shared_ptr<SandboxStatusCallback> cb, const std::string &sandboxId, Errors &error) override;
    std::unique_ptr<ControllerSandboxStatus> Status(const std::string &sandboxId, bool verbose, Errors &error) override;
    bool Shutdown(const std::string &sandboxId, Errors &error) override;
    bool UpdateNetworkSettings(const std::string &sandboxId, const std::string &networkSettings, Errors &error) override;

private:
    void ApplySandboxLinuxOptions(const runtime::v1::LinuxPodSandboxConfig &lc, host_config *hc,
                                  container_config *custom_config, Errors &error);

    void MakeSandboxIsuladConfig(const runtime::v1::PodSandboxConfig &config,
                                 host_config *hostconfig, container_config *custom_config,
                                 const std::string &networkMode, Errors &error);

    auto GenerateSandboxInfo(const std::string &sandboxId, const ControllerCreateParams &params,
                             Errors &err) -> container_sandbox_info *;

    auto PackCreateContainerRequest(const std::string &sandboxId,
                                    const ControllerCreateParams &params,
                                    host_config *hostconfig, container_config *custom_config,
                                    Errors &error) -> std::unique_ptr<CStructWrapper<container_create_request>>;

    auto GenerateSandboxCreateContainerRequest(const std::string &sandboxId,
                                               const ControllerCreateParams &params,
                                               Errors &error) -> std::unique_ptr<CStructWrapper<container_create_request>>;

    void InspectResponseToSandboxStatus(container_inspect *inspect,
                                        ControllerSandboxStatus &sandboxStatus,
                                        Errors &error);

    void GetContainerTimeStamps(const container_inspect *inspect, int64_t *createdAt, int64_t *startedAt,
                                int64_t *finishedAt, Errors &err);

private:
    std::string m_sandboxer;
    std::string m_podSandboxImage;
    service_executor_t *m_cb;
};

} // namespace

#endif // DAEMON_SANDBOX_CONTROLLER_SHIM_CONTROLLER_H
