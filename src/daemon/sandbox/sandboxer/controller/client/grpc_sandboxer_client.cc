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
 * Author: xuxuepeng
 * Create: 2023-07-10
 * Description: Sandboxer grpc client
 ******************************************************************************/

#include "grpc_sandboxer_client.h"

#include <grpc++/grpc++.h>
#include <iostream>
#include <memory>
#include <string>
#include <random>

#include <isula_libutils/log.h>

#include "utils.h"
#include "cstruct_wrapper.h"
#include "transform.h"
#include "sandbox_manager.h"

namespace sandbox {

SandboxerClient::SandboxerClient(const std::string &sandboxer, const std::string &address):
    m_sandboxer(sandboxer), m_address(address)
{
    std::string unixPrefix(UNIX_SOCKET_PREFIX);

    // Only support unix domain socket
    if (m_address.compare(0, unixPrefix.length(), unixPrefix) == 0) {
        m_address = m_address.substr(unixPrefix.length());
    }
    m_controller_handle = sandbox_api_build_controller(m_sandboxer.c_str(), m_address.c_str());
    if (m_controller_handle == nullptr) {
        ERROR("Failed to create sandboxer client, sandboxer: %s, address: %s", m_sandboxer.c_str(), m_address.c_str());
    }
}

auto SandboxerClient::InitMountInfo(sandbox_mount &m, const ControllerMountInfo &mountInfo) -> int
{
    m.type = util_strdup_s(mountInfo.type.c_str());
    m.source = util_strdup_s(mountInfo.source.c_str());
    m.target = util_strdup_s(mountInfo.destination.c_str());

    size_t mount_options_len = mountInfo.options.size();
    int ret = 0;
    for (size_t j = 0; j < mount_options_len; j++) {
        ret = util_array_append(&(m.options), mountInfo.options[j].c_str());
        if (ret != 0) {
            ERROR("append mount options to array failed");
            return -1;
        }
        m.options_len++;
    }
    return 0;
}

auto SandboxerClient::InitCreateRequest(sandbox_create_request &request,
                                        const std::string &sandboxId,
                                        const ControllerCreateParams &params) -> bool
{
    if (params.config == nullptr) {
        ERROR("Sandboxer controller create request failed, config is null");
        return false;
    }
    request.sandboxer = util_strdup_s(m_sandboxer.c_str());
    request.sandbox_id = util_strdup_s(sandboxId.c_str());
    std::string encoded;
    if (!params.config->SerializeToString(&encoded)) {
        ERROR("Failed to serialize config");
        return false;
    }
    request.options = (defs_any *)util_common_calloc_s(sizeof(defs_any));
    if (request.options == nullptr) {
        ERROR("Out of memory");
        return false;
    }
    request.options->value = (uint8_t *)util_common_calloc_s(encoded.size());
    if (request.options == nullptr) {
        ERROR("Out of memory");
        return false;
    }
    (void)memcpy(request.options->value, encoded.c_str(), encoded.size());
    request.options->value_len = encoded.size();
    request.netns_path = util_strdup_s(params.netNSPath.c_str());
    size_t mounts_len = params.mounts.size();
    if (mounts_len > 0) {
        request.rootfs = (sandbox_mount**)util_common_calloc_s(mounts_len * sizeof(sandbox_mount *));
        if (request.rootfs == nullptr) {
            ERROR("Out of memory");
            return false;
        }
        for (const auto &entry : params.mounts) {
            if (entry != nullptr) {
                sandbox_mount *m = (sandbox_mount *)util_common_calloc_s(sizeof(sandbox_mount));
                if (m == NULL) {
                    ERROR("Out of memory");
                    return false;
                }
                if (InitMountInfo(*m, *entry) != 0) {
                    ERROR("Failed to init mount info");
                    free(m);
                    return false;
                }
                request.rootfs[request.rootfs_len++] = m;
                m = NULL;
            }
        }
    }
    return true;
}

auto SandboxerClient::Create(const std::string &sandboxId, const ControllerCreateParams &params, Errors &error) -> bool
{
    sandbox_create_request *request { nullptr };
    sandbox_create_response *response { nullptr };

    auto create_request_wrapper = makeUniquePtrCStructWrapper<sandbox_create_request>(free_sandbox_create_request);
    if (create_request_wrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    request = create_request_wrapper->get();

    auto create_response_wrapper = makeUniquePtrCStructWrapper<sandbox_create_response>(free_sandbox_create_response);
    if (create_response_wrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    response = create_response_wrapper->get();
    
    if (!InitCreateRequest(*request, sandboxId, params)) {
        ERROR("Failed to init create request for sandboxer create request");
        error.SetError("Failed to init create request for sandboxer create request");
        return false;
    }
    int ret = sandbox_api_create(m_controller_handle, request, response);
    if (ret != 0) {
        ERROR("Failed to create sandbox");
        error.SetError("Failed to create sandbox");
        return false;
    }

    return true;
}

void SandboxerClient::StartResponseToSandboxInfo(sandbox_start_response &response,
                                                 ControllerSandboxInfo &sandboxInfo)
{
    sandboxInfo.id = std::string(response.sandbox_id);
    sandboxInfo.pid = response.pid;
    sandboxInfo.createdAt = response.created_at;
    sandboxInfo.taskAddress = std::string(response.address);
    sandboxInfo.version = response.version;
    Transform::JsonMapToProtobufMapForString(response.labels, sandboxInfo.labels);
}

auto SandboxerClient::Start(const std::string &sandboxId, ControllerSandboxInfo &sandboxInfo, Errors &error) -> bool
{
    sandbox_start_request *request { nullptr };
    sandbox_start_response *response { nullptr };

    auto start_request_wrapper = makeUniquePtrCStructWrapper<sandbox_start_request>(free_sandbox_start_request);
    if (start_request_wrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    request = start_request_wrapper->get();

    auto start_response_wrapper = makeUniquePtrCStructWrapper<sandbox_start_response>(free_sandbox_start_response);
    if (start_response_wrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    response = start_response_wrapper->get();

    request->sandboxer = util_strdup_s(m_sandboxer.c_str());
    request->sandbox_id = util_strdup_s(sandboxId.c_str());

    int ret = sandbox_api_start(m_controller_handle, request, response);
    if (ret != 0) {
        ERROR("Failed to start sandbox");
        error.SetError("Failed to start sandbox");
        return false;
    }

    StartResponseToSandboxInfo(*response, sandboxInfo);

    return true;
}

void SandboxerClient::InitUpdateRequest(sandbox_update_request &request,
                                         sandbox_sandbox *apiSandbox, string_array *fields)
{
    request.sandbox_id = util_strdup_s(apiSandbox->sandbox_id);
    request.sandboxer = util_strdup_s(apiSandbox->sandboxer);
    request.sandbox = apiSandbox;
    request.fields = fields->items;
    request.fields_len = fields->len;
}

auto SandboxerClient::Update(sandbox_sandbox *apiSandbox, string_array *fields, Errors &error) -> bool
{
    sandbox_update_request *request { nullptr };

    auto update_request_wrapper = makeUniquePtrCStructWrapper<sandbox_update_request>(free_sandbox_update_request);
    if (update_request_wrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    request = update_request_wrapper->get();

    InitUpdateRequest(*request, apiSandbox, fields);
    int ret = sandbox_api_update(m_controller_handle, request);
    request->sandbox = nullptr;
    request->fields = nullptr;
    request->fields_len = 0;
    if (ret != 0) {
        ERROR("Failed to update sandbox");
        error.SetError("Failed to update sandbox");
        return false;
    }

    return true;
}

void SandboxerClient::PlatformResponseToPlatformInfo(sandbox_platform_response &response,
                                                     ControllerPlatformInfo &platformInfo)
{
    platformInfo.os = std::string(response.os);
    platformInfo.arch = std::string(response.architecture);
    platformInfo.variant = std::string(response.variant);
}

auto SandboxerClient::Platform(const std::string &sandboxId, ControllerPlatformInfo &platformInfo,
                               Errors &error) -> bool
{
    sandbox_platform_request *request { nullptr };
    sandbox_platform_response *response { nullptr };

    auto platform_request_wrapper = makeUniquePtrCStructWrapper<sandbox_platform_request>(free_sandbox_platform_request);
    if (platform_request_wrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    request = platform_request_wrapper->get();

    auto platform_response_wrapper = makeUniquePtrCStructWrapper<sandbox_platform_response>(free_sandbox_platform_response);
    if (platform_response_wrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    response = platform_response_wrapper->get();

    request->sandboxer = util_strdup_s(m_sandboxer.c_str());
    request->sandbox_id = util_strdup_s(sandboxId.c_str());
    int ret = sandbox_api_platform(m_controller_handle, request, response);
    if (ret != 0) {
        ERROR("Failed to platform sandbox");
        error.SetError("Failed to platform sandbox");
        return false;
    }

    PlatformResponseToPlatformInfo(*response, platformInfo);

    return true;
}

auto SandboxerClient::Stop(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error) -> bool
{
    sandbox_stop_request *request { nullptr };

    auto stop_request_wrapper = makeUniquePtrCStructWrapper<sandbox_stop_request>(free_sandbox_stop_request);
    if (stop_request_wrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    request = stop_request_wrapper->get();

    request->sandboxer = util_strdup_s(m_sandboxer.c_str());
    request->sandbox_id = util_strdup_s(sandboxId.c_str());
    request->timeout_secs = timeoutSecs;
    int ret = sandbox_api_stop(m_controller_handle, request);
    if (ret != 0) {
        ERROR("Failed to stop sandbox");
        error.SetError("Failed to stop sandbox");
        return false;
    }

    return true;
}

void SandboxerClient::StatusResponseToSandboxStatus(sandbox_status_response
                                                    &response,
                                                    ControllerSandboxStatus &sandboxStatus)
{
    sandboxStatus.id = std::string(response.sandbox_id);
    sandboxStatus.pid = response.pid;
    sandboxStatus.state = std::string(response.state);
    Transform::JsonMapToProtobufMapForString(response.info, sandboxStatus.info);
    sandboxStatus.createdAt = response.created_at;
    sandboxStatus.exitedAt = response.exited_at;
    if (response.extra != nullptr && response.extra->value != nullptr) {
        sandboxStatus.extra = std::string(response.extra->value,
            response.extra->value + response.extra->value_len);
    } else {
        sandboxStatus.extra = std::string("");
    }
    sandboxStatus.taskAddress = std::string(response.address);
    sandboxStatus.version = response.version;
}

auto SandboxerClient::Status(const std::string &sandboxId, bool verbose, ControllerSandboxStatus &sandboxStatus,
                             Errors &error) -> bool
{
    sandbox_status_request *request { nullptr };
    sandbox_status_response *response { nullptr };

    auto status_request_wrapper = makeUniquePtrCStructWrapper<sandbox_status_request>(free_sandbox_status_request);
    if (status_request_wrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    request = status_request_wrapper->get();

    auto status_response_wrapper = makeUniquePtrCStructWrapper<sandbox_status_response>(free_sandbox_status_response);
    if (status_response_wrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    response = status_response_wrapper->get();

    request->sandboxer = util_strdup_s(m_sandboxer.c_str());
    request->sandbox_id = util_strdup_s(sandboxId.c_str());
    request->verbose = verbose;
    int ret = sandbox_api_status(m_controller_handle, request, response);
    if (ret != 0) {
        ERROR("Failed to status sandbox");
        error.SetError("Failed to status sandbox");
        return false;
    }

    StatusResponseToSandboxStatus(*response, sandboxStatus);

    return true;
}

auto SandboxerClient::Shutdown(const std::string &sandboxId, Errors &error) -> bool
{
    sandbox_shutdown_request *request { nullptr };

    auto shutdown_request_wrapper = makeUniquePtrCStructWrapper<sandbox_shutdown_request>(free_sandbox_shutdown_request);
    if (shutdown_request_wrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    request = shutdown_request_wrapper->get();

    request->sandboxer = util_strdup_s(m_sandboxer.c_str());
    request->sandbox_id = util_strdup_s(sandboxId.c_str());
    int ret = sandbox_api_shutdown(m_controller_handle, request);
    if (ret != 0) {
        ERROR("Failed to shutdown sandbox");
        error.SetError("Failed to shutdown sandbox");
        return false;
    }

    return true;
}

static int sandbox_api_ready(const char *sandbox_id)
{
    std::string sandboxId = std::string(sandbox_id);
    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(sandboxId);
    if (nullptr == sandbox) {
        ERROR("Sandbox not found");
        return -1;
    }

    sandbox->OnSandboxReady();
    return 0;
} 

static int sandbox_api_pending(const char *sandbox_id)
{
    std::string sandboxId = std::string(sandbox_id);
    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(sandboxId);
    if (nullptr == sandbox) {
        ERROR("Sandbox not found");
        return -1;
    }

    sandbox->OnSandboxPending();
    return 0;
}

static int sandbox_api_exit(const char *sandbox_id, const sandbox_wait_response *response)
{
    ControllerExitInfo exitInfo;
    std::string sandboxId = std::string(sandbox_id);
    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(sandboxId);
    if (nullptr == sandbox) {
        ERROR("Sandbox not found");
        return -1;
    }

    exitInfo.exitStatus = response->exit_status;
    exitInfo.exitedAt = response->exited_at;
    sandbox->OnSandboxExit(exitInfo);
    return 0;
}  

auto SandboxerClient::Wait(std::shared_ptr<SandboxStatusCallback> cb, const std::string &sandboxId,
                           Errors &error) -> bool
{
    sandbox_wait_request *request { nullptr };
    sandbox_api_wait_callback callback;

    auto wait_request_wrapper = makeUniquePtrCStructWrapper<sandbox_wait_request>(free_sandbox_wait_request);
    if (wait_request_wrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    request = wait_request_wrapper->get();

    request->sandboxer = util_strdup_s(m_sandboxer.c_str());
    request->sandbox_id = util_strdup_s(sandboxId.c_str());
    callback.ready = sandbox_api_ready;
    callback.pending = sandbox_api_pending;
    callback.exit = sandbox_api_exit;
    int ret = sandbox_api_wait(m_controller_handle, request, callback);
    if (ret != 0) {
        ERROR("Failed to wait sandbox");
        error.SetError("Failed to wait sandbox");
        return false;
    }
    
    return true;
}

} // namespace
