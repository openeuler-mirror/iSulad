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

namespace sandbox {

std::unique_ptr<ControllerManager> ControllerManager::manager = nullptr;

std::shared_ptr<Controller> ControllerManager::FindController(const std::string &sandboxer)
{
    return manager->GetController(sandboxer);
}

bool ControllerManager::Init(const isulad_daemon_configs *config)
{
    return true;
}

auto ControllerManager::RegisterController(const std::string &type, const std::string &sandboxer,
                                           const std::string &address,
                                           Errors &error) -> bool
{
    return true;
}

auto ControllerManager::GetController(const std::string &sandboxer) -> std::shared_ptr<Controller>
{
    return nullptr;
}

} // namespace
