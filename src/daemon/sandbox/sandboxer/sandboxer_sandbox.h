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
    
    void LoadSandboxTasks() override;

    auto PrepareContainer(const char *containerId, const char *baseFs,
                          const oci_runtime_spec *ociSpec,
                          const char *consoleFifos[]) -> int override;
    auto PrepareExec(const char *containerId, const char *execId,
                     defs_process *processSpec, const char *consoleFifos[]) -> int override;
    auto PurgeContainer(const char *containerId) -> int override;
    auto PurgeExec(const char *containerId, const char *execId) -> int override;

private:
    auto DoPurgeContainer(const char *containerId) -> int;
    auto DoPurgeExec(const char *containerId, const char *execId) -> int;

    auto GetTasksJsonPath() -> std::string;
    auto SaveSandboxTasks() -> bool;
    auto AddSandboxTasks(sandbox_task *task) -> bool;
    auto GetAnySandboxTasks() -> std::string;
    void DeleteSandboxTasks(const char *containerId);
    auto AddSandboxTasksProcess(const char *containerId, sandbox_process *processes) -> bool;
    void DeleteSandboxTasksProcess(const char *containerId, const char *execId);

    auto AddTaskById(const char *task_id, sandbox_task *task) -> bool;
    auto ReadSandboxTasksJson() -> sandbox_tasks *;
    auto WriteSandboxTasksJson(std::string &tasks_json) -> bool;
    auto DeleteSandboxTasksJson() -> bool;
    void AddSandboxTasksByArray(sandbox_tasks *tasksArray);

    auto GenerateCtrlRootfs(sandbox_task *task, const char *baseFs) -> int;
    auto InitSandboxRuntime() -> sandbox_sandbox_runtime *;
    auto InitSandboxLabels() -> json_map_string_string *;
    auto InitSandboxExtensions() -> defs_map_string_object_any *;
    auto InitApiSandbox(sandbox_sandbox *apiSandbox) -> int;
    auto DoSandboxUpdate(sandbox_sandbox *apiSandbox) -> int;

private:
    // use m_tasksMutex to ensure the correctness of the tasks and task json file when the external interface accesses them.
    std::mutex m_tasksMutex;
    // for sandbox api update, containerId --> tasks
    std::map<std::string, std::shared_ptr<SandboxTask>> m_tasks;
};

} // namespace sandbox

#endif // DAEMON_SANDBOX_SANDBOXER_SANDBOX_H