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
#include "sandboxer_sandbox.h"

#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <mutex>
#include <memory>
#include <sys/mount.h>

#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>

#include "utils_file.h"
#include "utils.h"
#include "cxxutils.h"

namespace sandbox {

SandboxerSandbox::SandboxerSandbox(const std::string id, const std::string &rootdir, const std::string &statedir, const std::string name,
                 const RuntimeInfo info, std::string netMode, std::string netNsPath, const runtime::v1::PodSandboxConfig sandboxConfig,
                 const std::string image):Sandbox(id, rootdir, statedir, name, info, netMode,
					 								  netNsPath, sandboxConfig, image)
{
}

auto SandboxerSandbox::GetTasksJsonPath() -> std::string
{
    return GetStateDir() + std::string("/") + SANDBOX_TASKS_JSON;
}

auto SandboxerSandbox::AddTaskById(const char *task_id, sandbox_task *task) -> bool
{
    
    std::string taskId = std::string(task_id);
    auto iter = m_tasks.find(taskId);

    if (iter != m_tasks.end()) {
        ERROR("Failed to add existing sandbox task %s for sandbox: %s",
            task_id, GetId().c_str());
        return false;
    }
    m_tasks[taskId] = std::make_shared<SandboxTask>(task);
    return true;
}

auto SandboxerSandbox::ReadSandboxTasksJson() -> sandbox_tasks *
{
    const std::string path = GetTasksJsonPath();
    __isula_auto_free parser_error err = nullptr;
    sandbox_tasks *tasksArray = nullptr;

    ReadGuard<RWMutex> lock(m_tasksMutex);
    tasksArray = sandbox_tasks_parse_file(path.c_str(), nullptr, &err);
    if (tasksArray == nullptr) {
        WARN("Failed to read %s tasks json: %s", path.c_str(), err);
    }
    return tasksArray;
}

auto SandboxerSandbox::WriteSandboxTasksJson(std::string &tasks_json) -> bool
{
    int nret = 0;
    const std::string path = GetTasksJsonPath();

    WriteGuard<RWMutex> lock(m_tasksMutex);
    nret = util_atomic_write_file(path.c_str(), tasks_json.c_str(), tasks_json.size(), CONFIG_FILE_MODE, false);
    if (nret != 0) {
        SYSERROR("Failed to write file %s", path.c_str());
    }
    return nret == 0;
}

auto SandboxerSandbox::DeleteSandboxTasksJson() -> bool
{
    int get_err = 0;
    const std::string path = GetTasksJsonPath();

    WriteGuard<RWMutex> lock(m_tasksMutex);
    if (util_fileself_exists(path.c_str()) &&
        !util_force_remove_file(path.c_str(), &get_err)) {
        errno = get_err;
        SYSERROR("Failed to remove file %s", path.c_str());
        return false;
    }

    return true;
}

void SandboxerSandbox::AddSandboxTasksByArray(sandbox_tasks *tasksArray)
{
    size_t i;

    WriteGuard<RWMutex> lock(m_tasksMutex);
    for (i = 0; i < tasksArray->tasks_len; i++) {
        if (!AddTaskById(tasksArray->tasks[i]->task_id, tasksArray->tasks[i])) {
            return;
        }
        tasksArray->tasks[i] = nullptr;
    }
    tasksArray->tasks_len = 0;
}

void SandboxerSandbox::LoadSandboxTasks()
{
    sandbox_tasks *tasksArray = nullptr;

    tasksArray = ReadSandboxTasksJson();
    if (tasksArray == nullptr) {
        return;
    }

    AddSandboxTasksByArray(tasksArray);

    free_sandbox_tasks(tasksArray);
}

auto SandboxerSandbox::SaveSandboxTasks() -> bool
{
    std::string tasks_json;

    if (m_tasks.empty()) {
        return DeleteSandboxTasksJson();
    }

    tasks_json = GetAnySandboxTasks();
    if (tasks_json.empty()) {
        ERROR("Failed to get sandbox tasks json for sandbox: '%s'", GetId().c_str());
        return false;
    }

    return WriteSandboxTasksJson(tasks_json);
}

auto SandboxerSandbox::AddSandboxTasks(sandbox_task *task) -> bool
{
    if (task == nullptr) {
        return true;
    }
    if (task->task_id == nullptr) {
        return false;
    }

    WriteGuard<RWMutex> lock(m_tasksMutex);

    return AddTaskById(task->task_id, task);
}

auto SandboxerSandbox::GetAnySandboxTasks() -> std::string
{
    __isula_auto_free parser_error err = nullptr;
    sandbox_tasks tasksArray = { 0 };
    size_t i = 0;
    __isula_auto_free char *tasks_json = nullptr;

    tasksArray.tasks = (sandbox_task **)util_smart_calloc_s(sizeof(sandbox_task *), m_tasks.size());
    if (tasksArray.tasks == nullptr) {
        SYSERROR("Out of memory.");
        return std::string("");
    }

    ReadGuard<RWMutex> lock(m_tasksMutex);
    for (auto const& [_, val] : m_tasks) {
        /* 
         * We ignore that the processes are modified 
         * when we generate tasks json string. 
         * Because no matter whether a process is deleted or added, 
         * the Update of sandbox api will be called eventually.
         * 
         * And we ignore that the task is freed after we do GetTask().
         * Because the only way to free task is DeleteSandboxTasks()
         * which needs write lock of m_tasksMutex.
        */ 
        tasksArray.tasks[i] = val->GetTask();
        i++;
    }
    tasksArray.tasks_len = m_tasks.size();

    tasks_json = sandbox_tasks_generate_json(&tasksArray, nullptr, &(err));
    if (tasks_json == nullptr || strlen(tasks_json) == 0) {
        ERROR("Failed to get sandbox tasks json for sandbox: '%s'", GetId().c_str());
        free(tasksArray.tasks);
        return std::string("");
    }

    free(tasksArray.tasks);
    return std::string(tasks_json);
}

void SandboxerSandbox::DeleteSandboxTasks(const char *containerId)
{
    if (containerId == nullptr) {
        return;
    }

    std::string taskId = std::string(containerId);

    WriteGuard<RWMutex> lock(m_tasksMutex);
    auto iter = m_tasks.find(taskId);
    if (iter == m_tasks.end()) {
        return;
    }
    m_tasks.erase(iter);
}

auto SandboxerSandbox::AddSandboxTasksProcess(const char *containerId, sandbox_process *processes) -> bool
{
    if (containerId == nullptr || processes == nullptr) {
        ERROR("Empty args.");
        return false;
    }

    std::string taskId = std::string(containerId);

    ReadGuard<RWMutex> lock(m_tasksMutex);
    auto iter = m_tasks.find(taskId);
    if (iter == m_tasks.end()) {
        SYSERROR("Failed to find container %s", containerId);
        return false;
    }
    
    return iter->second->AddSandboxTasksProcess(processes);
}

void SandboxerSandbox::DeleteSandboxTasksProcess(const char *containerId, const char *execId)
{
    if (containerId == nullptr || execId == nullptr) {
        return;
    }

    std::string taskId = std::string(containerId);

    ReadGuard<RWMutex> lock(m_tasksMutex);
    auto iter = m_tasks.find(taskId);
    if (iter == m_tasks.end()) {
        return;
    }
    iter->second->DeleteSandboxTasksProcess(execId);
}

}