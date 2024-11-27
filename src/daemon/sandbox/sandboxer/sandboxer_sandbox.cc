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
#include <isula_libutils/sandbox_sandbox.h>
#include <isula_libutils/defs_process.h>

#include "utils_file.h"
#include "utils.h"
#include "cxxutils.h"
#include "utils_timestamp.h"
#include "utils_array.h"

namespace sandbox {

const std::string SANDBOX_EXTENSIONS_TASKS = "extensions.tasks";
const std::string SANDBOX_TASKS_KEY = "tasks";
const std::string SANDBOX_TASKS_TYPEURL = "github.com/containerd/containerd/Tasks";

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

static oci_runtime_spec *clone_oci_runtime_spec(const oci_runtime_spec *oci_spec)
{
    __isula_auto_free char *json_str = nullptr;
    __isula_auto_free parser_error err = nullptr;
    oci_runtime_spec *ret = nullptr;

    json_str = oci_runtime_spec_generate_json(oci_spec, nullptr, &err);
    if (json_str == nullptr) {
        ERROR("Failed to generate spec json: %s", err);
        return nullptr;
    }
    ret = oci_runtime_spec_parse_data(json_str, nullptr, &err);
    if (ret == nullptr) {
        ERROR("Failed to generate spec: %s", err);
    }
    return ret;
}

static defs_process *clone_defs_process(defs_process *process_spec)
{
    __isula_auto_free char *json_str = nullptr;
    __isula_auto_free parser_error err = nullptr;
    defs_process *ret = nullptr;

    json_str = defs_process_generate_json(process_spec, nullptr, &err);
    if (json_str == nullptr) {
        ERROR("Failed to generate process spec json: %s", err);
        return nullptr;
    }
    ret = defs_process_parse_data(json_str, nullptr, &err);
    if (ret == nullptr) {
        ERROR("Failed to generate process spec: %s", err);
    }
    return ret;
}

auto SandboxerSandbox::GenerateCtrlRootfs(sandbox_task *task, const char *baseFs) -> int
{
    size_t len = 1;
    if (nullptr == baseFs) {
        ERROR("Container %s has no base fs", task->task_id);
        return -1;
    }

    // TODO: rootfs's options left to be configured
    task->rootfs = (sandbox_mount **)util_smart_calloc_s(sizeof(sandbox_mount *), len);
    if (task->rootfs == nullptr) {
        ERROR("Out of memory.");
        return -1;
    }
    task->rootfs[0] = (sandbox_mount *)util_common_calloc_s(sizeof(sandbox_mount));
    if (task->rootfs[0] == nullptr) {
        ERROR("Out of memory.");
        return -1;
    }
    task->rootfs_len = len;
    task->rootfs[0]->type = util_strdup_s(MOUNT_TYPE_BIND);
    task->rootfs[0]->source = util_strdup_s(baseFs);

    return 0;
}

auto SandboxerSandbox::InitSandboxRuntime() -> sandbox_sandbox_runtime *
{
    sandbox_sandbox_runtime *runtime = nullptr;

    auto runtime_wrapper = makeUniquePtrCStructWrapper<sandbox_sandbox_runtime>(free_sandbox_sandbox_runtime);
    if (runtime_wrapper == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }
    runtime = runtime_wrapper->get();
    runtime->name = util_strdup_s(GetRuntime().c_str());
    // Just ignore options for now

    return runtime_wrapper->move();
}

auto SandboxerSandbox::InitSandboxLabels() -> json_map_string_string *
{
    json_map_string_string *labels = nullptr;

    auto labels_wrapper = makeUniquePtrCStructWrapper<json_map_string_string>(free_json_map_string_string);
    if (labels_wrapper == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }
    labels = labels_wrapper->get();
    if (append_json_map_string_string(labels, "name", GetName().c_str()) != 0) {
        ERROR("Out of memory");
        return nullptr;
    }
    
    return labels_wrapper->move();
}

auto SandboxerSandbox::InitSandboxExtensions() -> defs_map_string_object_any *
{
    defs_map_string_object_any *extensions = nullptr;
    size_t len = 1;
    std::string task_json;

    auto extensions_wrapper = makeUniquePtrCStructWrapper<defs_map_string_object_any>(free_defs_map_string_object_any);
    if (extensions_wrapper == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }
    extensions = extensions_wrapper->get();

    extensions->keys = (char **)util_smart_calloc_s(sizeof(char *), len);
    if (extensions->keys == nullptr) {
        ERROR("Out of memory.");
        return nullptr;
    }
    extensions->values = (defs_map_string_object_any_element **)
        util_smart_calloc_s(sizeof(defs_map_string_object_any_element *), len);
    if (extensions->values == nullptr) {
        ERROR("Out of memory.");
        free(extensions->keys);
        extensions->keys = nullptr;
        return nullptr;
    }
    extensions->len = len;

    extensions->values[0] = (defs_map_string_object_any_element *)
        util_common_calloc_s(sizeof(defs_map_string_object_any_element));
    if (extensions->values[0] == nullptr) {
        ERROR("Out of memory.");
        return nullptr;
    }
    extensions->values[0]->element = (defs_any *)util_common_calloc_s(sizeof(defs_any));
    if (extensions->values[0]->element == nullptr) {
        ERROR("Out of memory.");
        return nullptr;
    }

    extensions->keys[0] = util_strdup_s(SANDBOX_TASKS_KEY.c_str());
    task_json = GetAnySandboxTasks();
    if (task_json.empty()) {
        ERROR("Failed to get any sandbox tasks");
        return nullptr;
    }
    DEBUG("Get any sandbox tasks %s", task_json.c_str());
    extensions->values[0]->element->type_url = util_strdup_s(SANDBOX_TASKS_TYPEURL.c_str());
    extensions->values[0]->element->value = reinterpret_cast<uint8_t *>(util_strdup_s(task_json.c_str()));
    extensions->values[0]->element->value_len = strlen(task_json.c_str());
    
    return extensions_wrapper->move();
}

auto SandboxerSandbox::InitApiSandbox(sandbox_sandbox *apiSandbox) -> int
{
    apiSandbox->sandbox_id = util_strdup_s(GetId().c_str());
    apiSandbox->runtime = InitSandboxRuntime();
    if (apiSandbox->runtime == nullptr) {
        ERROR("Failed to init sandbox runtime");
        return -1;
    }
    // Just ignore spec
    apiSandbox->labels = InitSandboxLabels();
    if (apiSandbox->labels == nullptr) {
        ERROR("Failed to init sandbox runtime");
        return -1;
    }
    apiSandbox->created_at = GetCreatedAt();
    apiSandbox->updated_at = util_get_now_time_nanos();
    apiSandbox->extensions = InitSandboxExtensions();
    if (apiSandbox->extensions == nullptr) {
        ERROR("Failed to init sandbox runtime");
        return -1;
    }
    apiSandbox->sandboxer = util_strdup_s(GetSandboxer().c_str());

    return 0;
}

auto SandboxerSandbox::DoSandboxUpdate(sandbox_sandbox *apiSandbox) -> int
{
    Errors err;
    size_t fields_len = 1;
    __isula_auto_string_array_t string_array *fields = nullptr;

    fields = util_string_array_new(fields_len);
    if (fields == nullptr) {
        ERROR("Out of memory.");
        return -1;
    }
    if (util_append_string_array(fields, SANDBOX_EXTENSIONS_TASKS.c_str())) {
        ERROR("Out of memory.");
        return -1;
    }

    auto controller = sandbox::ControllerManager::GetInstance()->GetController(GetSandboxer());
    if (nullptr == controller) {
        ERROR("Invalid sandboxer name: %s", GetSandboxer().c_str());
        return -1;
    }

    if (!controller->Update(apiSandbox, fields, err)) {
        ERROR("Failed to update in container controller update: %s", err.GetCMessage());
        return -1;
    }

    return 0;
}

auto SandboxerSandbox::PrepareContainer(const char *containerId, const char *baseFs,
                                        const oci_runtime_spec *ociSpec,
                                        const char *consoleFifos[]) -> int
{
    sandbox_task *task = nullptr;
    sandbox_sandbox *apiSandbox = nullptr;

    INFO("Prepare container for sandbox");

    if (nullptr == consoleFifos) {
        ERROR("Invlaid parameter: consoleFifos");
        return -1;
    }

    auto apiSandbox_wrapper = makeUniquePtrCStructWrapper<sandbox_sandbox>(free_sandbox_sandbox);
    if (apiSandbox_wrapper == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    apiSandbox = apiSandbox_wrapper->get();
    auto task_wrapper = makeUniquePtrCStructWrapper<sandbox_task>(free_sandbox_task);
    if (task_wrapper == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    task = task_wrapper->get();

    task->task_id = util_strdup_s(containerId);
    task->spec = clone_oci_runtime_spec(ociSpec);
    if (task->spec == nullptr) {
        ERROR("Out of memory.");
        return -1;
    }
    if (GenerateCtrlRootfs(task, baseFs) != 0) {
        ERROR("Invalid rootfs");
        return -1;
    }
    task->stdin = util_strdup_s((nullptr == consoleFifos[0]) ? "" : consoleFifos[0]);
    task->stdout = util_strdup_s((nullptr == consoleFifos[1]) ? "" : consoleFifos[1]);
    task->stderr = util_strdup_s((nullptr == consoleFifos[2]) ? "" : consoleFifos[2]);

    if (!AddSandboxTasks(task)) {
        ERROR("Failed to add sandbox %s task.", containerId);
        return -1;
    }
    task = task_wrapper->move();
    if (InitApiSandbox(apiSandbox) != 0) {
        ERROR("Failed to init %s api sandbox.", containerId);
        goto del_out;
    }
    if (DoSandboxUpdate(apiSandbox) != 0) {
        ERROR("Failed to update %s api sandbox.", containerId);
        goto del_out;
    }
    if (!SaveSandboxTasks()) {
        ERROR("Failed to Save %s sandbox tasks.", containerId);
        (void)PurgeContainer(containerId);
        return -1;
    }
    return 0;

del_out:
    DeleteSandboxTasks(containerId);
    return -1;
}   

auto SandboxerSandbox::PrepareExec(const char *containerId, const char *execId,
                                   defs_process *processSpec, const char *consoleFifos[]) -> int
{
    sandbox_process *process = nullptr;
    sandbox_sandbox *apiSandbox = nullptr;

    INFO("Prepare exec for container in sandbox");

    if (nullptr == consoleFifos) {
        ERROR("Invlaid parameter: consoleFifos");
        return -1;
    }

    auto apiSandbox_wrapper = makeUniquePtrCStructWrapper<sandbox_sandbox>(free_sandbox_sandbox);
    if (apiSandbox_wrapper == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    apiSandbox = apiSandbox_wrapper->get();
    auto process_wrapper = makeUniquePtrCStructWrapper<sandbox_process>(free_sandbox_process);
    if (process_wrapper == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    process = process_wrapper->get();

    process->exec_id = util_strdup_s(execId);
    process->spec = clone_defs_process(processSpec);
    if (process->spec == nullptr) {
        ERROR("Out of memory.");
        return -1;
    }
    process->stdin = util_strdup_s((nullptr == consoleFifos[0]) ? "" : consoleFifos[0]);
    process->stdout = util_strdup_s((nullptr == consoleFifos[1]) ? "" : consoleFifos[1]);
    process->stderr = util_strdup_s((nullptr == consoleFifos[2]) ? "" : consoleFifos[2]);

    if (!AddSandboxTasksProcess(containerId, process)) {
        ERROR("Failed to add sandbox %s process.", containerId);
        return -1;
    }
    process = process_wrapper->move();
    if (InitApiSandbox(apiSandbox) != 0) {
        ERROR("Failed to init %s api sandbox.", containerId);
        goto del_out;
    }
    if (DoSandboxUpdate(apiSandbox) != 0) {
        ERROR("Failed to init %s api sandbox.", containerId);
        goto del_out;
    }
    if (!SaveSandboxTasks()) {
        ERROR("Failed to Save %s sandbox tasks.", containerId);
        (void)PurgeExec(containerId, execId);
        return -1;
    }
    return 0;

del_out:
    DeleteSandboxTasksProcess(containerId, execId);
    return -1;
}   

auto SandboxerSandbox::PurgeContainer(const char *containerId) -> int
{
    sandbox_sandbox *apiSandbox = nullptr;

    INFO("Purge container for sandbox");

    auto apiSandbox_wrapper = makeUniquePtrCStructWrapper<sandbox_sandbox>(free_sandbox_sandbox);
    if (apiSandbox_wrapper == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    apiSandbox = apiSandbox_wrapper->get();

    DeleteSandboxTasks(containerId);

    if (InitApiSandbox(apiSandbox) != 0) {
        ERROR("Failed to init %s api sandbox.", containerId);
        return -1;
    }
    if (DoSandboxUpdate(apiSandbox) != 0) {
        ERROR("Failed to update %s api sandbox.", containerId);
        return -1;
    }
    if (!SaveSandboxTasks()) {
        ERROR("Failed to Save %s sandbox tasks.", containerId);
        return -1;
    }
    return 0;
}

auto SandboxerSandbox::PurgeExec(const char *containerId, const char *execId) -> int
{
    sandbox_sandbox *apiSandbox = nullptr;

    INFO("Purge exec for container in sandbox");

    auto apiSandbox_wrapper = makeUniquePtrCStructWrapper<sandbox_sandbox>(free_sandbox_sandbox);
    if (apiSandbox_wrapper == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    apiSandbox = apiSandbox_wrapper->get();

    DeleteSandboxTasksProcess(containerId, execId);

    if (InitApiSandbox(apiSandbox) != 0) {
        ERROR("Failed to init %s api sandbox.", execId);
        return -1;
    }
    if (DoSandboxUpdate(apiSandbox) != 0) {
        ERROR("Failed to update %s api sandbox.", execId);
        return -1;
    }
    if (!SaveSandboxTasks()) {
        ERROR("Failed to Save %s sandbox tasks.", containerId);
        return -1;
    }
    return 0;
}

}