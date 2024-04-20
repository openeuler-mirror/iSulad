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
 * Description: provide controller manager definition
 *********************************************************************************/

#ifndef DAEMON_SANDBOX_CONTROLLER_CONTROLLER_MANAGER_H
#define DAEMON_SANDBOX_CONTROLLER_CONTROLLER_MANAGER_H

#include "controller.h"

#include "errors.h"

namespace sandbox {

class ControllerManager {
public:
    static auto GetInstance() -> ControllerManager*;

    auto Init(Errors &error) -> bool;
    auto Cleanup(Errors &error) -> bool;
    auto GetController(const std::string &name) -> std::shared_ptr<Controller>;
private:
    auto RegisterShimController(Errors &error) -> bool;
#ifdef ENABLE_SANDBOXER
    auto RegisterAllSandboxerControllers(Errors &error) -> bool;
    auto LoadSandboxerControllersConfig(std::map<std::string, std::string> &config) -> bool;
    auto RegisterSandboxerController(const std::string &sandboxer, const std::string &address, Errors &error) -> bool;
#endif

protected:
    std::map<std::string, std::shared_ptr<Controller>> m_controllers;
    static std::atomic<ControllerManager *> m_instance;
};

} // namespace

#endif // DAEMON_SANDBOX_CONTROLLER_CONTROLLER_MANAGER_H