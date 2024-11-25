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
 * Author: jikai
 * Create: 2023-08-09
 * Description: provide sandbox api definition
 ******************************************************************************/
#include "sandbox_ops.h"

#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/log.h>
#include <isula_libutils/sandbox_sandbox.h>
#include <google/protobuf/util/time_util.h>

#include "controller_manager.h"
#include "sandbox_manager.h"
#include "sandbox.h"
#include "namespace.h"
#include "utils.h"
#include "utils_timestamp.h"
#include "utils_array.h"

const std::string SANDBOX_EXTENSIONS_TASKS = "extensions.tasks";
const std::string SANDBOX_TASKS_KEY = "tasks";
const std::string SANDBOX_TASKS_TYPEURL = "github.com/containerd/containerd/Tasks";

static inline bool validate_sandbox_info(const container_sandbox_info *sandbox)
{
    return (sandbox != NULL && sandbox->sandboxer != NULL &&
            sandbox->id != NULL);
}

static int generate_ctrl_rootfs(sandbox_task *task,
                                const container_config_v2_common_config *config)
{
    size_t len = 1;
    if (nullptr == config->base_fs) {
        ERROR("Container %s has no base fs", config->id);
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
    task->rootfs[0]->source = util_strdup_s(config->base_fs);

    return 0;
}

static int do_sandbox_update(std::shared_ptr<sandbox::Sandbox> &sandbox, sandbox_sandbox *apiSandbox)
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

    auto controller = sandbox::ControllerManager::GetInstance()->GetController(sandbox->GetSandboxer());
    if (nullptr == controller) {
        ERROR("Invalid sandboxer name: %s", sandbox->GetSandboxer().c_str());
        return -1;
    }

    if (!controller->Update(apiSandbox, fields, err)) {
        ERROR("Failed to update in container controller update: %s", err.GetCMessage());
        return -1;
    }

    return 0;
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

static std::shared_ptr<sandbox::Sandbox> get_prepare_sandbox(const container_config_v2_common_config *config)
{
    if (nullptr == config || nullptr == config->id) {
        ERROR("Invalid parameter: config");
        return nullptr;
    }

    auto sandbox_info = config->sandbox_info;
    if (false == validate_sandbox_info(sandbox_info)) {
        ERROR("Invalid parameter: sandbox");
        return nullptr;
    }

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(sandbox_info->id);
    if (nullptr == sandbox) {
        ERROR("Sandbox not found");
        return nullptr;
    }
    return sandbox;
}

static sandbox_sandbox_runtime *init_sandbox_runtime(std::shared_ptr<sandbox::Sandbox> sandbox)
{
    sandbox_sandbox_runtime *runtime = nullptr;

    auto runtime_wrapper = makeUniquePtrCStructWrapper<sandbox_sandbox_runtime>(free_sandbox_sandbox_runtime);
    if (runtime_wrapper == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }
    runtime = runtime_wrapper->get();
    runtime->name = util_strdup_s(sandbox->GetRuntime().c_str());
    // Just ignore options for now

    return runtime_wrapper->move();
}

static json_map_string_string *init_sandbox_labels(std::shared_ptr<sandbox::Sandbox> sandbox)
{
    json_map_string_string *labels = nullptr;

    auto labels_wrapper = makeUniquePtrCStructWrapper<json_map_string_string>(free_json_map_string_string);
    if (labels_wrapper == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }
    labels = labels_wrapper->get();
    if (append_json_map_string_string(labels, "name", sandbox->GetName().c_str()) != 0) {
        ERROR("Out of memory");
        return nullptr;
    }
    
    return labels_wrapper->move();
}

static defs_map_string_object_any *init_sandbox_extensions(std::shared_ptr<sandbox::Sandbox> sandbox)
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
    extensions->len = len;
    extensions->values = (defs_map_string_object_any_element **)
        util_smart_calloc_s(sizeof(defs_map_string_object_any_element *), len);
    if (extensions->values == nullptr) {
        ERROR("Out of memory.");
        return nullptr;
    }
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
    task_json = sandbox->GetAnySandboxTasks();
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

static int init_api_sandbox(std::shared_ptr<sandbox::Sandbox> sandbox, sandbox_sandbox *apiSandbox)
{
    apiSandbox->sandbox_id = util_strdup_s(sandbox->GetId().c_str());
    apiSandbox->runtime = init_sandbox_runtime(sandbox);
    if (apiSandbox->runtime == nullptr) {
        ERROR("Failed to init sandbox runtime");
        return -1;
    }
    // Just ignore spec
    apiSandbox->labels = init_sandbox_labels(sandbox);
    if (apiSandbox->labels == nullptr) {
        ERROR("Failed to init sandbox runtime");
        return -1;
    }
    apiSandbox->created_at = sandbox->GetCreatedAt();
    apiSandbox->updated_at = util_get_now_time_nanos();
    apiSandbox->extensions = init_sandbox_extensions(sandbox);
    if (apiSandbox->extensions == nullptr) {
        ERROR("Failed to init sandbox runtime");
        return -1;
    }
    apiSandbox->sandboxer = util_strdup_s(sandbox->GetSandboxer().c_str());

    return 0;
}

int sandbox_prepare_container(const container_config_v2_common_config *config,
                              const oci_runtime_spec *oci_spec,
                              const char * console_fifos[], bool tty)
{
    sandbox_task *task = nullptr;
    sandbox_sandbox *apiSandbox = nullptr;
    int ret = -1;

    INFO("Prepare container for sandbox");

    if (nullptr == console_fifos) {
        ERROR("Invlaid parameter: console_fifos");
        return -1;
    }

    auto sandbox = get_prepare_sandbox(config);
    if (sandbox == nullptr) {
        ERROR("Sandbox not found");
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

    task->task_id = util_strdup_s(config->id);
    task->spec = clone_oci_runtime_spec(oci_spec);
    if (task->spec == nullptr) {
        ERROR("Out of memory.");
        return -1;
    }
    if (generate_ctrl_rootfs(task, config) != 0) {
        ERROR("Invalid rootfs");
        return -1;
    }
    task->stdin = util_strdup_s((nullptr == console_fifos[0]) ? "" : console_fifos[0]);
    task->stdout = util_strdup_s((nullptr == console_fifos[1]) ? "" : console_fifos[1]);
    task->stderr = util_strdup_s((nullptr == console_fifos[2]) ? "" : console_fifos[2]);

    if (!sandbox->AddSandboxTasks(task)) {
        ERROR("Failed to add sandbox %s task.", config->id);
        return -1;
    }
    task = task_wrapper->move();
    ret = init_api_sandbox(sandbox, apiSandbox);
    if (ret != 0) {
        ERROR("Failed to init %s api sandbox.", config->id);
        goto del_out;
    }
    ret = do_sandbox_update(sandbox, apiSandbox);

del_out:
    if (ret != 0) {
        sandbox->DeleteSandboxTasks(config->id);
    }
    if (!sandbox->SaveSandboxTasks()) {
        ERROR("Failed to Save %s sandbox tasks.", config->id);
        ret = -1;
    }

    return ret;
}

int sandbox_prepare_exec(const container_config_v2_common_config *config,
                         const char *exec_id, defs_process *process_spec,
                         const char * console_fifos[], bool tty)
{
    sandbox_process *process = nullptr;
    sandbox_sandbox *apiSandbox = nullptr;
    int ret = -1;

    INFO("Prepare exec for container in sandbox");

    if (nullptr == console_fifos) {
        ERROR("Invlaid parameter: console_fifos");
        return -1;
    }

    auto sandbox = get_prepare_sandbox(config);
    if (sandbox == nullptr) {
        ERROR("Sandbox not found");
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

    process->exec_id = util_strdup_s(exec_id);
    process->spec = clone_defs_process(process_spec);
    if (process->spec == nullptr) {
        ERROR("Out of memory.");
        return -1;
    }
    process->stdin = util_strdup_s((nullptr == console_fifos[0]) ? "" : console_fifos[0]);
    process->stdout = util_strdup_s((nullptr == console_fifos[1]) ? "" : console_fifos[1]);
    process->stderr = util_strdup_s((nullptr == console_fifos[2]) ? "" : console_fifos[2]);

    if (!sandbox->AddSandboxTasksProcess(config->id, process)) {
        ERROR("Failed to add sandbox %s process.", config->id);
        return -1;
    }
    process = process_wrapper->move();
    ret = init_api_sandbox(sandbox, apiSandbox);
    if (ret != 0) {
        ERROR("Failed to init %s api sandbox.", config->id);
        goto del_out;
    }
    ret = do_sandbox_update(sandbox, apiSandbox);

del_out:
    if (ret != 0) {
        sandbox->DeleteSandboxTasksProcess(config->id, exec_id);
    }
    if (!sandbox->SaveSandboxTasks()) {
        ERROR("Failed to Save %s sandbox tasks.", config->id);
        ret = -1;
    }

    return ret;
}

int sandbox_purge_container(const container_config_v2_common_config *config)
{
    sandbox_sandbox *apiSandbox = nullptr;

    INFO("Purge container for sandbox");

    auto sandbox = get_prepare_sandbox(config);
    if (sandbox == nullptr) {
        ERROR("Sandbox not found");
        return -1;
    }

    auto apiSandbox_wrapper = makeUniquePtrCStructWrapper<sandbox_sandbox>(free_sandbox_sandbox);
    if (apiSandbox_wrapper == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    apiSandbox = apiSandbox_wrapper->get();

    sandbox->DeleteSandboxTasks(config->id);
    if (!sandbox->SaveSandboxTasks()) {
        ERROR("Failed to Save %s sandbox tasks.", config->id);
        return -1;
    }

    if (init_api_sandbox(sandbox, apiSandbox) != 0) {
        ERROR("Failed to init %s api sandbox.", config->id);
        return -1;
    }
    return do_sandbox_update(sandbox, apiSandbox);
}

int sandbox_purge_exec(const container_config_v2_common_config *config, const char *exec_id)
{
    sandbox_sandbox *apiSandbox = nullptr;

    INFO("Purge exec for container in sandbox");

    auto sandbox = get_prepare_sandbox(config);
    if (sandbox == nullptr) {
        ERROR("Sandbox not found");
        return -1;
    }

    auto apiSandbox_wrapper = makeUniquePtrCStructWrapper<sandbox_sandbox>(free_sandbox_sandbox);
    if (apiSandbox_wrapper == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    apiSandbox = apiSandbox_wrapper->get();

    sandbox->DeleteSandboxTasksProcess(config->id, exec_id);
    if (!sandbox->SaveSandboxTasks()) {
        ERROR("Failed to Save %s sandbox tasks.", config->id);
        return -1;
    }

    if (init_api_sandbox(sandbox, apiSandbox) != 0) {
        ERROR("Failed to init %s api sandbox.", exec_id);
        return -1;
    }

    return do_sandbox_update(sandbox, apiSandbox);
}

int sandbox_on_sandbox_exit(const char *sandbox_id, int exit_code)
{
    if (nullptr == sandbox_id) {
        ERROR("Invalid parameter: sandbox_id");
        return -1;
    }

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(sandbox_id);
    if (nullptr == sandbox) {
        ERROR("Sandbox %s not found", sandbox_id);
        return -1;
    }

    sandbox::ControllerExitInfo info;
    auto currentTime = std::chrono::high_resolution_clock::now();
    auto duration = currentTime.time_since_epoch();
    info.exitedAt = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
    info.exitStatus = exit_code;
    sandbox->OnSandboxExit(info);
    return 0;
}
