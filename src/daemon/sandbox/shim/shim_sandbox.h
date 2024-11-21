/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: liuxu
 * Create: 2024-11-20
 * Description: provide shim sandbox class definition
 *********************************************************************************/

#ifndef DAEMON_SANDBOX_SHIM_SANDBOX_H
#define DAEMON_SANDBOX_SHIM_SANDBOX_H

#include <string>
#include <mutex>
#include <google/protobuf/map.h>

#include "read_write_lock.h"
#include "sandbox_task.h"
#include "sandbox.h"

namespace sandbox {

class ShimSandbox : public Sandbox {
public:
    ShimSandbox(const std::string id, const std::string &rootdir, const std::string &statedir, const std::string name = "",
            const RuntimeInfo info = {"", "", ""}, std::string netMode = DEFAULT_NETMODE, std::string netNsPath = "",
            const runtime::v1::PodSandboxConfig sandboxConfig = runtime::v1::PodSandboxConfig::default_instance(),
            const std::string image = "");
    virtual ~ShimSandbox() = default;

    // for sandbox api update
    void LoadSandboxTasks() override;
    auto SaveSandboxTasks() -> bool override;
    auto AddSandboxTasks(sandbox_task *task) -> bool override;
    auto GetAnySandboxTasks() -> std::string override;
    void DeleteSandboxTasks(const char *containerId) override;
    auto AddSandboxTasksProcess(const char *containerId, sandbox_process *processes) -> bool override;
    void DeleteSandboxTasksProcess(const char *containerId, const char *execId) override;
};

} // namespace sandbox

#endif // DAEMON_SANDBOX_SHIM_SANDBOX_H