/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-12-15
 * Description: provide cri runtime manager service function implementation
 *********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_RUNTIME_MANAGER_IMPL_H
#define DAEMON_ENTRY_CRI_RUNTIME_MANAGER_IMPL_H
#include "cri_runtime_manager_service.h"
#include <memory>
#include <string>
#include <vector>

#include "api.pb.h"
#include "errors.h"
#include "network_plugin.h"
#include "callback.h"

namespace CRI {
class RuntimeManagerServiceImpl : public RuntimeManagerService {
public:
    RuntimeManagerServiceImpl(service_executor_t *cb, std::shared_ptr<Network::PluginManager> pluginManager) :
        m_cb(cb), m_pluginManager(pluginManager) {}
    RuntimeManagerServiceImpl(const RuntimeManagerServiceImpl &) = delete;
    auto operator=(const RuntimeManagerServiceImpl &) -> RuntimeManagerServiceImpl & = delete;
    virtual ~RuntimeManagerServiceImpl() = default;

    void UpdateRuntimeConfig(const runtime::v1alpha2::RuntimeConfig &config, Errors &error) override;

    auto Status(Errors &error) -> std::unique_ptr<runtime::v1alpha2::RuntimeStatus> override;

private:
    service_executor_t *m_cb;
    std::shared_ptr<Network::PluginManager> m_pluginManager;
};
} // namespace CRI

#endif // DAEMON_ENTRY_CRI_RUNTIME_MANAGER_IMPL_H