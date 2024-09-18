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
#include <google/protobuf/util/time_util.h>

#include "controller_manager.h"
#include "sandbox_manager.h"
#include "sandbox.h"
#include "namespace.h"
#include "utils.h"
#include "utils_timestamp.h"

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

static int do_sandbox_prepare(std::shared_ptr<sandbox::Sandbox> &sandbox, containerd::types::Sandbox &apiSandbox)
{
    Errors err;
    std::vector<std::string> fields;
    
    fields.push_back(SANDBOX_EXTENSIONS_TASKS);

    auto controller = sandbox::ControllerManager::GetInstance()->GetController(sandbox->GetSandboxer());
    if (nullptr == controller) {
        ERROR("Invalid sandboxer name: %s", sandbox->GetSandboxer().c_str());
        return -1;
    }

    if (!controller->Prepare(apiSandbox, fields, err)) {
        ERROR("Failed to prepare in container controller prepare: %s", err.GetCMessage());
        return -1;
    }

    return 0;
}

static int do_sandbox_purge(std::shared_ptr<sandbox::Sandbox> &sandbox, containerd::types::Sandbox &apiSandbox)
{
    Errors err;
    std::vector<std::string> fields;
    
    fields.push_back(SANDBOX_EXTENSIONS_TASKS);

    auto controller = sandbox::ControllerManager::GetInstance()->GetController(sandbox->GetSandboxer());
    if (nullptr == controller) {
        ERROR("Invalid sandboxer name: %s", sandbox->GetSandboxer().c_str());
        return -1;
    }

    if (!controller->Purge(apiSandbox, fields, err)) {
        ERROR("Failed to purge: %s", err.GetCMessage());
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

static int init_prepare_api_sandbox(std::shared_ptr<sandbox::Sandbox> sandbox, const char *containerId,
                                     containerd::types::Sandbox &apiSandbox)
{
    google::protobuf::Map<std::string, std::string> *labels = apiSandbox.mutable_labels();
    google::protobuf::Map<std::string, google::protobuf::Any> *extensions = apiSandbox.mutable_extensions();
    google::protobuf::Any any;
    auto created_at = new (std::nothrow) google::protobuf::Timestamp;
    auto updated_at = new (std::nothrow) google::protobuf::Timestamp;
    
    apiSandbox.set_sandbox_id(sandbox->GetId());
    apiSandbox.mutable_runtime()->set_name(sandbox->GetRuntime());
    // TODO how get options
    // apiSandbox.mutable_runtime()->set_options(sandbox->GetRuntime());
    // Just ignore spec
    (*labels)[std::string("name")] = sandbox->GetName();

    *created_at = google::protobuf::util::TimeUtil::NanosecondsToTimestamp(
                              sandbox->GetCreatedAt());
    apiSandbox.set_allocated_created_at(created_at);
    *updated_at = google::protobuf::util::TimeUtil::NanosecondsToTimestamp(util_get_now_time_nanos());
    apiSandbox.set_allocated_updated_at(updated_at);

    auto any_type_url = any.mutable_type_url();
    *any_type_url = SANDBOX_TASKS_TYPEURL;
    auto any_value = any.mutable_value();
    *any_value = sandbox->GetAnySandboxTasks();
    if ((*any_value).empty()) {
        ERROR("Failed to get any sandbox tasks");
        return -1;
    }
    DEBUG("Get any sandbox tasks %s", (*any_value).c_str());
    (*extensions)[SANDBOX_TASKS_KEY] = any;

    apiSandbox.set_sandboxer(sandbox->GetSandboxer());

    return 0;
}

int sandbox_prepare_container(const container_config_v2_common_config *config,
                              const oci_runtime_spec *oci_spec,
                              const char * console_fifos[], bool tty)
{
    sandbox_task *task = nullptr;
    containerd::types::Sandbox apiSandbox;
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

    task = (sandbox_task *)util_common_calloc_s(sizeof(sandbox_task));
    if (task == nullptr) {
        ERROR("Out of memory.");
        return -1;
    }
    task->task_id = util_strdup_s(config->id);
    task->spec = clone_oci_runtime_spec(oci_spec);
    if (task->spec == nullptr) {
        ERROR("Out of memory.");
        goto free_out;
    }
    if (generate_ctrl_rootfs(task, config) != 0) {
        ERROR("Invalid rootfs");
        goto free_out;
    }
    task->stdin = util_strdup_s((nullptr == console_fifos[0]) ? "" : console_fifos[0]);
    task->stdout = util_strdup_s((nullptr == console_fifos[1]) ? "" : console_fifos[1]);
    task->stderr = util_strdup_s((nullptr == console_fifos[2]) ? "" : console_fifos[2]);

    if (!sandbox->AddSandboxTasks(task)) {
        ERROR("Failed to add sandbox %s task.", config->id);
        goto free_out;
    }
    task = nullptr;
    ret = init_prepare_api_sandbox(sandbox, config->id, apiSandbox);
    if (ret != 0) {
        ERROR("Failed to init %s api sandbox.", config->id);
        goto del_out;
    }
    ret = do_sandbox_prepare(sandbox, apiSandbox);

del_out:
    if (ret != 0) {
        sandbox->DeleteSandboxTasks(config->id);
    }
    if (!sandbox->SaveSandboxTasks()) {
        ERROR("Failed to Save %s sandbox tasks.", config->id);
        ret = -1;
    }
free_out:
    free_sandbox_task(task);
    return ret;
}

int sandbox_prepare_exec(const container_config_v2_common_config *config,
                         const char *exec_id, defs_process *process_spec,
                         const char * console_fifos[], bool tty)
{
    sandbox_process *process = nullptr;
    containerd::types::Sandbox apiSandbox;
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

    process = (sandbox_process *)util_common_calloc_s(sizeof(sandbox_process));
    if (process == nullptr) {
        ERROR("Out of memory.");
        return -1;
    }
    process->exec_id = util_strdup_s(exec_id);
    process->spec = clone_defs_process(process_spec);
    if (process->spec == nullptr) {
        ERROR("Out of memory.");
        goto free_out;
    }
    process->stdin = util_strdup_s((nullptr == console_fifos[0]) ? "" : console_fifos[0]);
    process->stdout = util_strdup_s((nullptr == console_fifos[1]) ? "" : console_fifos[1]);
    process->stderr = util_strdup_s((nullptr == console_fifos[2]) ? "" : console_fifos[2]);

    if (!sandbox->AddSandboxTasksProcess(config->id, process)) {
        ERROR("Failed to add sandbox %s process.", config->id);
        goto free_out;
    }
    process = nullptr;
    ret = init_prepare_api_sandbox(sandbox, config->id, apiSandbox);
    if (ret != 0) {
        ERROR("Failed to init %s api sandbox.", config->id);
        goto del_out;
    }
    ret = do_sandbox_prepare(sandbox, apiSandbox);

del_out:
    if (ret != 0) {
        sandbox->DeleteSandboxTasksProcess(config->id, exec_id);
    }
    if (!sandbox->SaveSandboxTasks()) {
        ERROR("Failed to Save %s sandbox tasks.", config->id);
        ret = -1;
    }
free_out:
    free_sandbox_process(process);
    return ret;
}

int sandbox_purge_container(const container_config_v2_common_config *config)
{
    containerd::types::Sandbox apiSandbox;

    INFO("Purge container for sandbox");

    auto sandbox = get_prepare_sandbox(config);
    if (sandbox == nullptr) {
        ERROR("Sandbox not found");
        return -1;
    }

    sandbox->DeleteSandboxTasks(config->id);
    if (!sandbox->SaveSandboxTasks()) {
        ERROR("Failed to Save %s sandbox tasks.", config->id);
        return -1;
    }

    if (init_prepare_api_sandbox(sandbox, config->id, apiSandbox) != 0) {
        ERROR("Failed to init %s api sandbox.", config->id);
        return -1;
    }
    return do_sandbox_purge(sandbox, apiSandbox);
}

int sandbox_purge_exec(const container_config_v2_common_config *config, const char *exec_id)
{
    containerd::types::Sandbox apiSandbox;

    INFO("Purge exec for container in sandbox");

    auto sandbox = get_prepare_sandbox(config);
    if (sandbox == nullptr) {
        ERROR("Sandbox not found");
        return -1;
    }

    sandbox->DeleteSandboxTasksProcess(config->id, exec_id);
    if (!sandbox->SaveSandboxTasks()) {
        ERROR("Failed to Save %s sandbox tasks.", config->id);
        return -1;
    }

    if (init_prepare_api_sandbox(sandbox, config->id, apiSandbox) != 0) {
        ERROR("Failed to init %s api sandbox.", exec_id);
        return -1;
    }

    return do_sandbox_purge(sandbox, apiSandbox);
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
