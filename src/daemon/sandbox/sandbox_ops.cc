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

#include "controller_manager.h"
#include "sandbox_manager.h"
#include "namespace.h"
#include "utils.h"

static inline bool validate_sandbox_info(const container_sandbox_info *sandbox)
{
    return (sandbox != NULL && sandbox->sandboxer != NULL &&
            sandbox->id != NULL);
}

static int generate_ctrl_rootfs(sandbox::ControllerPrepareParams &params,
                                const container_config_v2_common_config *config)
{
    if (nullptr == config->base_fs) {
        ERROR("Container %s has no base fs", config->id);
        return -1;
    }

    // TODO: rootfs's options left to be configured
    std::unique_ptr<sandbox::ControllerMountInfo> mount_info(new sandbox::ControllerMountInfo());
    mount_info->type = MOUNT_TYPE_BIND;
    mount_info->source = config->base_fs;
    params.rootfs.push_back(std::move(mount_info));

    return 0;
}

static int do_sandbox_prepare(const container_config_v2_common_config *config,
                              const char *exec_id, const char *oci_spec,
                              const char * console_fifos[], bool tty)
{
    Errors err;
    sandbox::ControllerPrepareParams params;
    std::unique_ptr<sandbox::ControllerStreamInfo> stream_info(new sandbox::ControllerStreamInfo());
    const container_sandbox_info *sandbox_info = nullptr;

    if (nullptr == config || nullptr == config->id) {
        ERROR("Invalid parameter: config");
        return -1;
    }

    sandbox_info = config->sandbox_info;
    if (false == validate_sandbox_info(sandbox_info)) {
        ERROR("Invalid parameter: sandbox");
        return -1;
    }

    if (nullptr == console_fifos) {
        ERROR("Invlaid parameter: console_fifos");
        return -1;
    }

    params.containerId = config->id;
    params.execId = (nullptr == exec_id) ? "" : exec_id;
    params.spec = std::move(std::unique_ptr<std::string>(new std::string(oci_spec)));

    if (generate_ctrl_rootfs(params, config) != 0) {
        ERROR("Invalid rootfs");
        return -1;
    }

    stream_info->stdin = (nullptr == console_fifos[0]) ? "" : console_fifos[0];
    stream_info->stdout = (nullptr == console_fifos[1]) ? "" : console_fifos[1];
    stream_info->stderr = (nullptr == console_fifos[2]) ? "" : console_fifos[2];
    stream_info->terminal = tty;
    params.streamInfo = std::move(stream_info);

    auto controller = sandbox::ControllerManager::GetInstance()->GetController(sandbox_info->sandboxer);
    if (nullptr == controller) {
        ERROR("Invalid sandboxer name: %s", sandbox_info->sandboxer);
        return -1;
    }

    std::string bundle = controller->Prepare(sandbox_info->id, params, err);
    if (err.NotEmpty()) {
        ERROR("Failed to prepare in container controller prepare: %s", err.GetCMessage());
        return -1;
    }

    return 0;
}

static int do_sandbox_purge(const container_config_v2_common_config *config,
                            const char *exec_id)
{
    Errors err;
    const container_sandbox_info *sandbox_info = nullptr;

    if (nullptr == config || nullptr == config->id) {
        ERROR("Invalid parameter: config");
        return -1;
    }

    sandbox_info = config->sandbox_info;
    if (false == validate_sandbox_info(sandbox_info)) {
        ERROR("Invalid parameter: sandbox");
        return -1;
    }

    auto controller = sandbox::ControllerManager::GetInstance()->GetController(sandbox_info->sandboxer);
    if (nullptr == controller) {
        ERROR("Invalid sandboxer name: %s", sandbox_info->sandboxer);
        return -1;
    }

    if (!controller->Purge(sandbox_info->id, config->id,
                           (nullptr == exec_id) ? "" : exec_id, err)) {
        ERROR("Failed to purge: %s", err.GetCMessage());
        return -1;
    }

    return 0;
}

int sandbox_prepare_container(const container_config_v2_common_config *config,
                              const oci_runtime_spec *oci_spec,
                              const char * console_fifos[], bool tty)
{
    __isula_auto_free char *json_oci_spec = nullptr;
    __isula_auto_free parser_error err = nullptr;

    INFO("Prepare container for sandbox");

    json_oci_spec = oci_runtime_spec_generate_json(oci_spec, nullptr, &err);
    if (nullptr == json_oci_spec) {
        ERROR("Failed to generate container spec json: %s", err);
        return -1;
    }
    return do_sandbox_prepare(config, nullptr, json_oci_spec, console_fifos, tty);
}

int sandbox_prepare_exec(const container_config_v2_common_config *config,
                         const char *exec_id, defs_process *process_spec,
                         const char * console_fifos[], bool tty)
{
    __isula_auto_free char *json_process = nullptr;
    __isula_auto_free parser_error err = nullptr;

    INFO("Prepare exec for container in sandbox");

    json_process = defs_process_generate_json(process_spec, nullptr, &err);
    if (nullptr == json_process) {
        ERROR("Failed to generate process spec json: %s", err);
        return -1;
    }

    return do_sandbox_prepare(config, exec_id, json_process, console_fifos, tty);
}

int sandbox_purge_container(const container_config_v2_common_config *config)
{
    return do_sandbox_purge(config, nullptr);
}

int sandbox_purge_exec(const container_config_v2_common_config *config, const char *exec_id)
{
    return do_sandbox_purge(config, exec_id);
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
