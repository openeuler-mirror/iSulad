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

#ifdef ENABLE_SANDBOXER
static inline bool validate_sandbox_info(const container_sandbox_info *sandbox)
{
    return (sandbox != NULL && sandbox->sandboxer != NULL &&
            sandbox->id != NULL);
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


int sandbox_prepare_container(const container_config_v2_common_config *config,
                              const oci_runtime_spec *oci_spec,
                              const char * console_fifos[], bool tty)
{
    if (nullptr == console_fifos) {
        ERROR("Invlaid parameter: console_fifos");
        return -1;
    }

    auto sandbox = get_prepare_sandbox(config);
    if (sandbox == nullptr) {
        ERROR("Sandbox not found");
        return -1;
    }

    return sandbox->PrepareContainer(config->id, config->base_fs, oci_spec, console_fifos);
}

int sandbox_prepare_exec(const container_config_v2_common_config *config,
                         const char *exec_id, defs_process *process_spec,
                         const char * console_fifos[], bool tty)
{
    if (nullptr == console_fifos) {
        ERROR("Invlaid parameter: console_fifos");
        return -1;
    }

    auto sandbox = get_prepare_sandbox(config);
    if (sandbox == nullptr) {
        ERROR("Sandbox not found");
        return -1;
    }

    return sandbox->PrepareExec(config->id, exec_id, process_spec, console_fifos);
}

int sandbox_purge_container(const container_config_v2_common_config *config)
{
    auto sandbox = get_prepare_sandbox(config);
    if (sandbox == nullptr) {
        ERROR("Sandbox not found");
        return -1;
    }

    return sandbox->PurgeContainer(config->id);
}

int sandbox_purge_exec(const container_config_v2_common_config *config, const char *exec_id)
{
    auto sandbox = get_prepare_sandbox(config);
    if (sandbox == nullptr) {
        ERROR("Sandbox not found");
        return -1;
    }

    return sandbox->PurgeExec(config->id, exec_id);
}
#endif /* ENABLE_SANDBOXER */

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
