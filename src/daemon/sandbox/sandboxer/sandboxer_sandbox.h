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
 * Description: provide sandboxer sandbox class definition
 *********************************************************************************/

#ifndef DAEMON_SANDBOX_SANDBOXER_SANDBOX_H
#define DAEMON_SANDBOX_SANDBOXER_SANDBOX_H

#include <string>
#include <mutex>
#include <google/protobuf/map.h>

#include "read_write_lock.h"
#include "sandbox_task.h"
#include "sandbox.h"

namespace sandbox {

class SandboxerSandbox : public Sandbox {
public:
    SandboxerSandbox(const std::string id, const std::string &rootdir, const std::string &statedir, const std::string name = "",
            const RuntimeInfo info = {"", "", ""}, std::string netMode = DEFAULT_NETMODE, std::string netNsPath = "",
            const runtime::v1::PodSandboxConfig sandboxConfig = runtime::v1::PodSandboxConfig::default_instance(),
            const std::string image = "");
    virtual ~SandboxerSandbox() = default;

    // for sandbox api update
    auto GetTasksJsonPath() -> std::string;
    void LoadSandboxTasks() override;
    auto SaveSandboxTasks() -> bool override;
    auto AddSandboxTasks(sandbox_task *task) -> bool override;
    auto GetAnySandboxTasks() -> std::string override;
    void DeleteSandboxTasks(const char *containerId) override;
    auto AddSandboxTasksProcess(const char *containerId, sandbox_process *processes) -> bool override;
    void DeleteSandboxTasksProcess(const char *containerId, const char *execId) override;

private:
    auto AddTaskById(const char *task_id, sandbox_task *task) -> bool;
    auto ReadSandboxTasksJson() -> sandbox_tasks *;
    auto WriteSandboxTasksJson(std::string &tasks_json) -> bool;
    auto DeleteSandboxTasksJson() -> bool;
    void AddSandboxTasksByArray(sandbox_tasks *tasksArray);

private:
    // use m_tasksMutex to ensure the correctness of the tasks
    RWMutex m_tasksMutex;
    // for sandbox api update, containerId --> tasks
    std::map<std::string, std::shared_ptr<SandboxTask>> m_tasks;
};

} // namespace sandbox

#endif // DAEMON_SANDBOX_SANDBOXER_SANDBOX_H