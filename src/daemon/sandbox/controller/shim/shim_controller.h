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

namespace sandbox {

class ShimController : public Controller {
public:
    ShimController(const std::string &sandboxer);
    virtual ~ShimController();
    bool Init(Errors &error) override;
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
    bool Wait(std::shared_ptr<SandboxExitCallback> cb, const std::string &sandboxId, Errors &error) = 0;
    std::unique_ptr<ControllerSandboxStatus> Status(const std::string &sandboxId, bool verbose, Errors &error) override;
    bool Shutdown(const std::string &sandboxId, Errors &error) override;
    bool UpdateNetworkSettings(const std::string &sandboxId, const std::string &networkSettings, Errors &error) override;
private:
    std::string m_sandboxer;
    std::string m_podSandboxImage;
};

} // namespace

#endif // DAEMON_SANDBOX_CONTROLLER_SHIM_CONTROLLER_H