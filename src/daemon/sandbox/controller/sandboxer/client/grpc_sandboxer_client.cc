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

#include "sandbox/types/platform.pb.h"
#include "sandbox.pb.h"
#include "sandbox.grpc.pb.h"
#include "utils.h"
#include "isula_libutils/log.h"

#include "grpc_client_utils.h"

namespace sandbox {

SandboxerClient::SandboxerClient(const std::string &sandboxer, const std::string &address):
    m_sandboxer(sandboxer), m_address(address)
{
    std::string unixPrefix(UNIX_SOCKET_PREFIX);

    // Only support unix domain socket
    if (m_address.compare(0, unixPrefix.length(), unixPrefix) != 0) {
        m_address = unixPrefix + m_address;
    }
    m_channel = grpc::CreateChannel(m_address, grpc::InsecureChannelCredentials());
    m_stub = containerd::services::sandbox::v1::Controller::NewStub(m_channel);
    // Monitor shares the same channel with client and has its own stub
    m_monitor = std::unique_ptr<SandboxerClientMonitor>(new SandboxerClientMonitor(m_channel, m_sandboxer));
}

void SandboxerClient::InitMountInfo(Mount &mount, const ControllerMountInfo &mountInfo)
{
    mount.set_type(mountInfo.type);
    mount.set_source(mountInfo.source);
    mount.set_target(mountInfo.destination);
    for (const auto &option : mountInfo.options) {
        mount.add_options(option);
    }
}

auto SandboxerClient::InitCreateRequest(containerd::services::sandbox::v1::ControllerCreateRequest &request,
                                        const std::string &sandboxId,
                                        const ControllerCreateParams &params) -> bool
{
    if (params.config == nullptr) {
        ERROR("Sandboxer controller create request failed, config is null");
        return false;
    }
    request.mutable_options()->PackFrom(*params.config);
    request.set_sandboxer(m_sandboxer);
    request.set_sandbox_id(sandboxId);
    for (const auto &entry : params.mounts) {
        if (entry != nullptr) {
            Mount* mount = request.add_rootfs();
            InitMountInfo(*mount, *entry);
        }
    }
    request.set_netns_path(params.netNSPath);
    return true;
}

void SandboxerClient::Init(Errors &error)
{
    m_monitor->Start();
}

void SandboxerClient::Destroy()
{
    m_monitor->Stop();
}

auto SandboxerClient::Create(const std::string &sandboxId, const ControllerCreateParams &params, Errors &error) -> bool
{
    grpc::ClientContext context;
    containerd::services::sandbox::v1::ControllerCreateRequest request;
    containerd::services::sandbox::v1::ControllerCreateResponse response;
    grpc::Status status;

    if (!InitCreateRequest(request, sandboxId, params)) {
        error.SetError("Failed to init create request for sandboxer create request, sandbox id: " + sandboxId);
        return false;
    }

    status = m_stub->Create(&context, request, &response);
    if (!status.ok()) {
        error.SetError(status.error_message());
        ERROR("Sandboxer controller create request failed, error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return false;
    }

    return true;
}

void SandboxerClient::StartResponseToSandboxInfo(const containerd::services::sandbox::v1::ControllerStartResponse &response,
                                                 ControllerSandboxInfo &sandboxInfo)
{
    sandboxInfo.id = response.sandbox_id();
    sandboxInfo.pid = response.pid();
    sandboxInfo.createdAt = TimestampToNanos(response.created_at());
    sandboxInfo.taskAddress = response.task_address();
    sandboxInfo.labels = response.labels();
}

auto SandboxerClient::Start(const std::string &sandboxId, ControllerSandboxInfo &sandboxInfo, Errors &error) -> bool
{
    grpc::ClientContext context;
    containerd::services::sandbox::v1::ControllerStartRequest request;
    containerd::services::sandbox::v1::ControllerStartResponse response;
    grpc::Status status;

    request.set_sandboxer(m_sandboxer);
    request.set_sandbox_id(sandboxId);

    status = m_stub->Start(&context, request, &response);
    if (!status.ok()) {
        error.SetError(status.error_message());
        ERROR("Sandboxer controller start request failed, error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return false;
    }

    StartResponseToSandboxInfo(response, sandboxInfo);

    return true;
}

auto SandboxerClient::InitPrepareRequest(containerd::services::sandbox::v1::PrepareRequest &request,
                                         const std::string &sandboxId, const ControllerPrepareParams &params) -> bool
{
    if (params.spec == nullptr) {
        ERROR("Sandboxer controller prepare request failed, spec is null");
        return false;
    }
    request.mutable_spec()->set_value(*(params.spec));
    request.set_sandboxer(m_sandboxer);
    request.set_sandbox_id(sandboxId);
    request.set_container_id(params.containerId);
    request.set_exec_id(params.execId);
    for (const auto &entry : params.rootfs) {
        if (entry != nullptr) {
            Mount* mount = request.add_rootfs();
            InitMountInfo(*mount, *entry);
        }
    }
    if (params.streamInfo != nullptr) {
        request.set_stdin(params.streamInfo->stdin);
        request.set_stdout(params.streamInfo->stdout);
        request.set_stderr(params.streamInfo->stderr);
        request.set_terminal(params.streamInfo->terminal);
    } else {
        request.set_stdin("");
        request.set_stdout("");
        request.set_stderr("");
        request.set_terminal(false);
    }

    return true;
}

auto SandboxerClient::Prepare(const std::string &sandboxId, const ControllerPrepareParams &params, std::string &bundle, Errors &error) -> bool
{
    grpc::ClientContext context;
    containerd::services::sandbox::v1::PrepareRequest request;
    containerd::services::sandbox::v1::PrepareResponse response;
    grpc::Status status;

    if (!InitPrepareRequest(request, sandboxId, params)) {
        error.SetError("Failed to init prepare request for sandboxer prepare request, sandbox id: " + sandboxId);
        return false;
    }

    status = m_stub->Prepare(&context, request, &response);
    if (!status.ok()) {
        error.SetError(status.error_message());
        ERROR("Sandboxer controller prepare request failed, error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return false;
    }

    bundle = response.bundle();

    return true;
}

auto SandboxerClient::Purge(const std::string &sandboxId, const std::string &containerId,
                           const std::string &execId, Errors &error) -> bool
{
    grpc::ClientContext context;
    containerd::services::sandbox::v1::PurgeRequest request;
    containerd::services::sandbox::v1::PurgeResponse response;
    grpc::Status status;

    request.set_sandboxer(m_sandboxer);
    request.set_sandbox_id(sandboxId);
    request.set_container_id(containerId);
    request.set_exec_id(execId);

    status = m_stub->Purge(&context, request, &response);
    if (!status.ok()) {
        error.SetError(status.error_message());
        ERROR("Sandboxer controller purge request failed, error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return false;
    }

    return true;
}

auto SandboxerClient::InitUpdateResourcesRequest(containerd::services::sandbox::v1::UpdateResourcesRequest &request,
                                                 const std::string &sandboxId,
                                                 const ControllerUpdateResourcesParams &params) -> bool
{
    if (params.resources == nullptr) {
        ERROR("Sandboxer controller update resources request failed, resources is null");
        return false;
    }
    request.mutable_resources()->set_value(*(params.resources));
    request.set_sandboxer(m_sandboxer);
    request.set_sandbox_id(sandboxId);
    request.set_container_id(params.containerId);
    request.mutable_annotations()->insert(params.annotations.begin(), params.annotations.end());
    return true;
}

auto SandboxerClient::UpdateResources(const std::string &sandboxId, const ControllerUpdateResourcesParams &params, Errors &error) -> bool
{
    grpc::ClientContext context;
    containerd::services::sandbox::v1::UpdateResourcesRequest request;
    containerd::services::sandbox::v1::UpdateResourcesResponse response;
    grpc::Status status;

    if (!InitUpdateResourcesRequest(request, sandboxId, params)) {
        error.SetError("Failed to init update-resources request for sandboxer update-resources request, sandbox id: " + sandboxId);
        return false;
    }

    status = m_stub->UpdateResources(&context, request, &response);
    if (!status.ok()) {
        error.SetError(status.error_message());
        ERROR("Sandboxer controller update resources request failed, error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return false;
    }

    return true;
}

void SandboxerClient::PlatformResponseToPlatformInfo(const containerd::services::sandbox::v1::ControllerPlatformResponse &response,
                                                     ControllerPlatformInfo &platformInfo)
{
    auto &platform = response.platform();
    platformInfo.os = platform.os();
    platformInfo.arch = platform.architecture();
    platformInfo.variant = platform.variant();
}

auto SandboxerClient::Platform(const std::string &sandboxId, ControllerPlatformInfo &platformInfo, Errors &error) -> bool
{
    grpc::ClientContext context;
    containerd::services::sandbox::v1::ControllerPlatformRequest request;
    containerd::services::sandbox::v1::ControllerPlatformResponse response;
    grpc::Status status;

    request.set_sandboxer(m_sandboxer);
    request.set_sandbox_id(sandboxId);

    status = m_stub->Platform(&context, request, &response);
    if (!status.ok()) {
        error.SetError(status.error_message());
        ERROR("Sandboxer controller platform request failed, error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return false;
    }

    PlatformResponseToPlatformInfo(response, platformInfo);

    return true;
}

auto SandboxerClient::Stop(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error) -> bool
{
    grpc::ClientContext context;
    containerd::services::sandbox::v1::ControllerStopRequest request;
    containerd::services::sandbox::v1::ControllerStopResponse response;
    grpc::Status status;

    request.set_sandboxer(m_sandboxer);
    request.set_sandbox_id(sandboxId);
    request.set_timeout_secs(timeoutSecs);

    status = m_stub->Stop(&context, request, &response);
    if (!status.ok()) {
        error.SetError(status.error_message());
        ERROR("Sandboxer controller stop request failed, error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return false;
    }

    return true;
}

void SandboxerClient::StatusResponseToSandboxStatus(const containerd::services::sandbox::v1::ControllerStatusResponse &response,
                                                    ControllerSandboxStatus &sandboxStatus)
{
    sandboxStatus.id = response.sandbox_id();
    sandboxStatus.pid = response.pid();
    sandboxStatus.state = response.state();
    sandboxStatus.taskAddress = response.task_address();
    sandboxStatus.info.insert(response.info().begin(), response.info().end());
    sandboxStatus.createdAt = TimestampToNanos(response.created_at());
    sandboxStatus.exitedAt = TimestampToNanos(response.exited_at());
    sandboxStatus.extra = response.extra().value();
}

auto SandboxerClient::Status(const std::string &sandboxId, bool verbose, ControllerSandboxStatus &sandboxStatus, Errors &error) -> bool
{
    grpc::ClientContext context;
    containerd::services::sandbox::v1::ControllerStatusRequest request;
    containerd::services::sandbox::v1::ControllerStatusResponse response;
    grpc::Status status;

    request.set_sandboxer(m_sandboxer);
    request.set_sandbox_id(sandboxId);
    request.set_verbose(verbose);

    status = m_stub->Status(&context, request, &response);
    if (!status.ok()) {
        error.SetError(status.error_message());
        ERROR("Sandboxer controller status request failed, error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return false;
    }

    StatusResponseToSandboxStatus(response, sandboxStatus);

    return true;
}

auto SandboxerClient::Shutdown(const std::string &sandboxId, Errors &error) -> bool
{
    grpc::ClientContext context;
    containerd::services::sandbox::v1::ControllerShutdownRequest request;
    containerd::services::sandbox::v1::ControllerShutdownResponse response;
    grpc::Status status;

    request.set_sandboxer(m_sandboxer);
    request.set_sandbox_id(sandboxId);

    status = m_stub->Shutdown(&context, request, &response);
    if (!status.ok()) {
        error.SetError(status.error_message());
        ERROR("Sandboxer controller shutdown request failed, error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return false;
    }

    return true;
}

auto SandboxerClient::Wait(std::shared_ptr<SandboxStatusCallback> cb, const std::string &sandboxId, Errors &error) -> bool
{
    if (m_monitor == nullptr) {
        error.SetError("Cannot wait for sandbox, sandboxer client monitor is not initialized, "
                       "sandboxer: " + m_sandboxer);
        return false;
    }
    SandboxerAsyncWaitCall *call = new SandboxerAsyncWaitCall(cb, sandboxId, m_sandboxer);
    // Transfer ownership of call to monitor
    return m_monitor->Monitor(call);
}

} // namespace
