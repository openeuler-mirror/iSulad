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
 * Create: 2023-07-06
 * Description: provide controller manager implementation
 *********************************************************************************/

#include "controller_manager.h"

#include <memory>
#include <isula_libutils/log.h>
#include <isula_libutils/defs.h>

#include "shim_controller.h"
#ifdef ENABLE_SANDBOXER
#include "sandboxer_controller.h"
#endif
#include "isulad_config.h"
#include "daemon_arguments.h"

namespace sandbox {

std::atomic<ControllerManager *> ControllerManager::m_instance;

auto ControllerManager::GetInstance() -> ControllerManager *
{
    static std::once_flag flag;

    std::call_once(flag, [] { m_instance = new ControllerManager(); });

    return m_instance;
}

bool ControllerManager::Init(Errors &error)
{
    // Initialize shim controller
    if (!RegisterShimController(error)) {
        return false;
    }

#ifdef ENABLE_SANDBOXER
    // Initialize sandboxer controller
    if (!RegisterAllSandboxerControllers(error)) {
        return false;
    }
#endif
    return true;
}

bool ControllerManager::Cleanup(Errors &error)
{
    for (auto &it : m_controllers) {
        it.second->Destroy();
    }
    return true;
}

auto ControllerManager::RegisterShimController(Errors &error) -> bool
{
    if (m_controllers.find(SHIM_CONTROLLER_NAME) != m_controllers.end()) {
        return true;
    }

    std::shared_ptr<Controller> shimController = std::make_shared<ShimController>(SHIM_CONTROLLER_NAME);

    if (!shimController->Init(error)) {
        return false;
    }
    m_controllers[SHIM_CONTROLLER_NAME] = shimController;
    INFO("Shim controller initialized successfully");
    return true;
}

#ifdef ENABLE_SANDBOXER
auto ControllerManager::RegisterAllSandboxerControllers(Errors &error) -> bool
{
    std::map<std::string, std::string> config;

    if (!LoadSandboxerControllersConfig(config)) {
        error.SetError("Failed to load sandboxer controllers config");
        return false;
    }

    for (auto &it : config) {
        if (!RegisterSandboxerController(it.first, it.second, error)) {
            return false;
        }
    }
    return true;
}

auto ControllerManager::LoadSandboxerControllersConfig(std::map<std::string, std::string> &config) -> bool
{
    struct service_arguments *args = NULL;
    defs_map_string_object_sandboxer *sandboxers = NULL;
    bool ret = false;

    if (isulad_server_conf_rdlock()) {
        return false;
    }
    args = conf_get_server_conf();
    if (args == NULL) {
        ERROR("Failed to get isulad server config for sandboxer registration");
        goto done;
    }
    if (args->json_confs != NULL) {
        sandboxers = args->json_confs->cri_sandboxers;
    }
    if (sandboxers == NULL) {
        ret = true;
        goto done;
    }
    for (size_t i = 0; i < sandboxers->len; i++) {
        std::string runtimeHandler = sandboxers->keys[i];
        defs_map_string_object_sandboxer_element *element = sandboxers->values[i];
        if (element == NULL) {
            ERROR("Empty sandboxer config for runtime handler: %s", runtimeHandler.c_str());
            goto done;
        }
        if (element->name == NULL || element->address == NULL) {
            ERROR("Empty name or address in sandboxer config for runtime handler: %s", runtimeHandler.c_str());
            goto done;
        }

        std::string sandboxer(element->name);
        std::string address(element->address);

        if (config.find(sandboxer) != config.end()) {
            ERROR("Duplicate sandboxer config for sandboxer: %s", sandboxer.c_str());
            goto done;
        }

        config[sandboxer] = address;
    }
    ret = true;
done:
    isulad_server_conf_unlock();
    return ret;
}


auto ControllerManager::RegisterSandboxerController(const std::string &sandboxer,
                                                    const std::string &address, Errors &error) -> bool
{
    if (m_controllers.find(sandboxer) != m_controllers.end()) {
        error.SetError("Sandboxer controller already registered, sandboxer: " + sandboxer);
        ERROR("Sandboxer controller already registered, sandboxer: %s", sandboxer.c_str());
        return false;
    }
    std::shared_ptr<Controller> sandboxerController = std::make_shared<SandboxerController>(sandboxer, address);
    if (!sandboxerController->Init(error)) {
        error.SetError("Failed to initialize sandboxer controller, sandboxer: " + sandboxer);
        ERROR("Failed to initialize sandboxer controller, sandboxer: %s", sandboxer.c_str());
        return false;
    }
    m_controllers[sandboxer] = sandboxerController;
    INFO("Sandboxer controller initialized successfully, sandboxer: %s", sandboxer.c_str());
    return true;
}
#endif

auto ControllerManager::GetController(const std::string &name) -> std::shared_ptr<Controller>
{
    auto it = m_controllers.find(name);
    if (it != m_controllers.end()) {
        return it->second;
    }
    return nullptr;
}

} // namespace
