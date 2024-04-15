/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide runtime functions
 ******************************************************************************/
#include "cri_runtime_runtime_service.h"
#include <string>
#include <memory>
#include <vector>

#include <isula_libutils/log.h>
#include "network_plugin.h"
#include "cri_runtime_service_impl.h"

using namespace CRI;

grpc::Status RuntimeRuntimeServiceImpl::ToGRPCStatus(Errors &error)
{
    if (error.Empty()) {
        return grpc::Status::OK;
    }
    if (error.GetMessage().find("Failed to find") != std::string::npos) {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, error.GetMessage());
    }

    // Attach exceeded timeout for lxc and Exec container error;exec timeout for runc
    if (error.GetMessage().find("Attach exceeded timeout") != std::string::npos
        || error.GetMessage().find("Exec container error;exec timeout") != std::string::npos) {
        return grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, error.GetMessage());
    }
    return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
}

void RuntimeRuntimeServiceImpl::Init(std::string &podSandboxImage,
                                     std::shared_ptr<Network::PluginManager> networkPlugin, Errors &err)
{
    // Assembly implementation for CRIRuntimeServiceImpl
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr) {
        ERROR("Init isulad service executor failure.");
        err.SetError("Init isulad service executor failure.");
        return;
    }

    m_rService = std::unique_ptr<CRI::CRIRuntimeService>(new CRIRuntimeServiceImpl(podSandboxImage, cb, networkPlugin));
}

void RuntimeRuntimeServiceImpl::Wait()
{
}

void RuntimeRuntimeServiceImpl::Shutdown()
{
}

grpc::Status RuntimeRuntimeServiceImpl::Version(grpc::ServerContext *context,
                                                const runtime::v1alpha2::VersionRequest *request,
                                                runtime::v1alpha2::VersionResponse *reply)
{
    Errors error;
    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    m_rService->Version(request->version(), reply, error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::CreateContainer(grpc::ServerContext *context,
                                                        const runtime::v1alpha2::CreateContainerRequest *request,
                                                        runtime::v1alpha2::CreateContainerResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    EVENT("Event: {Object: CRI, Type: Creating Container for sandbox: %s}", request->pod_sandbox_id().c_str());

    std::string responseID =
        m_rService->CreateContainer(request->pod_sandbox_id(), request->config(), request->sandbox_config(), error);
    if (!error.Empty() || responseID.empty()) {
        ERROR("Object: CRI, Type: Failed to create container");
        return ToGRPCStatus(error);
    }
    reply->set_container_id(responseID);

    EVENT("Event: {Object: CRI, Type: Created Container %s}", responseID.c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::StartContainer(grpc::ServerContext *context,
                                                       const runtime::v1alpha2::StartContainerRequest *request,
                                                       runtime::v1alpha2::StartContainerResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    EVENT("Event: {Object: CRI, Type: Starting Container: %s}", request->container_id().c_str());

    m_rService->StartContainer(request->container_id(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to start container %s", request->container_id().c_str());
        return ToGRPCStatus(error);
    }

    EVENT("Event: {Object: CRI, Type: Started Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::StopContainer(grpc::ServerContext *context,
                                                      const runtime::v1alpha2::StopContainerRequest *request,
                                                      runtime::v1alpha2::StopContainerResponse *reply)
{
    Errors error;

    if (request == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    EVENT("Event: {Object: CRI, Type: Stopping Container: %s}", request->container_id().c_str());

    m_rService->StopContainer(request->container_id(), (int64_t)request->timeout(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to stop container %s", request->container_id().c_str());
        return ToGRPCStatus(error);
    }

    EVENT("Event: {Object: CRI, Type: Stopped Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::RemoveContainer(grpc::ServerContext *context,
                                                        const runtime::v1alpha2::RemoveContainerRequest *request,
                                                        runtime::v1alpha2::RemoveContainerResponse *reply)
{
    Errors error;

    if (request == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    EVENT("Event: {Object: CRI, Type: Removing Container: %s}", request->container_id().c_str());

    m_rService->RemoveContainer(request->container_id(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to remove container %s", request->container_id().c_str());
        return ToGRPCStatus(error);
    }

    EVENT("Event: {Object: CRI, Type: Removed Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ListContainers(grpc::ServerContext *context,
                                                       const runtime::v1alpha2::ListContainersRequest *request,
                                                       runtime::v1alpha2::ListContainersResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    INFO("Event: {Object: CRI, Type: Listing all Container}");

    std::vector<std::unique_ptr<runtime::v1alpha2::Container>> containers;
    m_rService->ListContainers(request->has_filter() ? &request->filter() : nullptr, containers, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to list all containers %s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    for (auto iter = containers.begin(); iter != containers.end(); ++iter) {
        runtime::v1alpha2::Container *container = reply->add_containers();
        if (container == nullptr) {
            ERROR("Object: CRI, Type: Failed to list all containers: out of memory");
            return grpc::Status(grpc::StatusCode::UNKNOWN, "Out of memory");
        }
        *container = *(iter->get());
    }

    INFO("Event: {Object: CRI, Type: Listed all Container}");

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ContainerStats(grpc::ServerContext *context,
                                                       const runtime::v1alpha2::ContainerStatsRequest *request,
                                                       runtime::v1alpha2::ContainerStatsResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    INFO("Event: {Object: CRI, Type: Getting Container Stats: %s}", request->container_id().c_str());

    std::unique_ptr<runtime::v1alpha2::ContainerStats> contStats =
        m_rService->ContainerStats(request->container_id(), error);
    if (!error.Empty() || !contStats) {
        ERROR("Object: CRI, Type: Failed to get container stats %s", request->container_id().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_stats()) = *contStats;

    INFO("Event: {Object: CRI, Type: Got Container stats: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ListContainerStats(grpc::ServerContext *context,
                                                           const runtime::v1alpha2::ListContainerStatsRequest *request,
                                                           runtime::v1alpha2::ListContainerStatsResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    INFO("Event: {Object: CRI, Type: Listing all Container stats}");

    std::vector<std::unique_ptr<runtime::v1alpha2::ContainerStats>> containers;
    m_rService->ListContainerStats(request->has_filter() ? &request->filter() : nullptr, containers, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to list all containers stat %s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    for (auto iter = containers.begin(); iter != containers.end(); ++iter) {
        runtime::v1alpha2::ContainerStats *container = reply->add_stats();
        if (container == nullptr) {
            ERROR("Object: CRI, Type: Failed to list all containers stats: out of memory");
            return grpc::Status(grpc::StatusCode::UNKNOWN, "Out of memory");
        }
        *container = *(iter->get());
    }

    INFO("Event: {Object: CRI, Type: Listed all Container stats}");

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ContainerStatus(grpc::ServerContext *context,
                                                        const runtime::v1alpha2::ContainerStatusRequest *request,
                                                        runtime::v1alpha2::ContainerStatusResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    INFO("Event: {Object: CRI, Type: Statusing Container: %s}", request->container_id().c_str());

    std::unique_ptr<runtime::v1alpha2::ContainerStatus> contStatus =
        m_rService->ContainerStatus(request->container_id(), error);
    if (!error.Empty() || !contStatus) {
        ERROR("Object: CRI, Type: Failed to get container status %s", request->container_id().c_str());
        return ToGRPCStatus(error);
    }
    *(reply->mutable_status()) = *contStatus;

    INFO("Event: {Object: CRI, Type: Statused Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ExecSync(grpc::ServerContext *context,
                                                 const runtime::v1alpha2::ExecSyncRequest *request,
                                                 runtime::v1alpha2::ExecSyncResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    WARN("Event: {Object: CRI, Type: sync execing Container: %s}", request->container_id().c_str());

    m_rService->ExecSync(request->container_id(), request->cmd(), request->timeout(), reply, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to sync exec container: %s", request->container_id().c_str());
        return ToGRPCStatus(error);
    }

    WARN("Event: {Object: CRI, Type: sync execed Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::RunPodSandbox(grpc::ServerContext *context,
                                                      const runtime::v1alpha2::RunPodSandboxRequest *request,
                                                      runtime::v1alpha2::RunPodSandboxResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    if (request->has_config() && request->config().has_metadata()) {
        EVENT("Event: {Object: CRI, Type: Running Pod: %s}", request->config().metadata().name().c_str());
    } else {
        EVENT("Event: {Object: CRI, Type: Running Pod}");
    }

    std::string responseID = m_rService->RunPodSandbox(request->config(), request->runtime_handler(), error);
    if (!error.Empty() || responseID.empty()) {
        ERROR("Object: CRI, Type: Failed to run pod:%s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    reply->set_pod_sandbox_id(responseID);

    EVENT("Event: {Object: CRI, Type: Run Pod: %s success}", responseID.c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::StopPodSandbox(grpc::ServerContext *context,
                                                       const runtime::v1alpha2::StopPodSandboxRequest *request,
                                                       runtime::v1alpha2::StopPodSandboxResponse *reply)
{
    Errors error;

    if (request == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    EVENT("Event: {Object: CRI, Type: Stopping Pod: %s}", request->pod_sandbox_id().c_str());

    m_rService->StopPodSandbox(request->pod_sandbox_id(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to stop pod:%s due to %s", request->pod_sandbox_id().c_str(),
              error.GetMessage().c_str());
        return ToGRPCStatus(error);
    }

    EVENT("Event: {Object: CRI, Type: Stopped Pod: %s}", request->pod_sandbox_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::RemovePodSandbox(grpc::ServerContext *context,
                                                         const runtime::v1alpha2::RemovePodSandboxRequest *request,
                                                         runtime::v1alpha2::RemovePodSandboxResponse *reply)
{
    Errors error;

    if (request == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    EVENT("Event: {Object: CRI, Type: Removing Pod: %s}", request->pod_sandbox_id().c_str());

    m_rService->RemovePodSandbox(request->pod_sandbox_id(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to remove pod:%s due to %s", request->pod_sandbox_id().c_str(),
              error.GetMessage().c_str());
        return ToGRPCStatus(error);
    }

    EVENT("Event: {Object: CRI, Type: Removed Pod: %s}", request->pod_sandbox_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::PodSandboxStatus(grpc::ServerContext *context,
                                                         const runtime::v1alpha2::PodSandboxStatusRequest *request,
                                                         runtime::v1alpha2::PodSandboxStatusResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    INFO("Event: {Object: CRI, Type: Status Pod: %s}", request->pod_sandbox_id().c_str());

    std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> podStatus;
    podStatus = m_rService->PodSandboxStatus(request->pod_sandbox_id(), error);
    if (!error.Empty() || !podStatus) {
        ERROR("Object: CRI, Type: Failed to status pod:%s due to %s", request->pod_sandbox_id().c_str(),
              error.GetMessage().c_str());
        return ToGRPCStatus(error);
    }
    *(reply->mutable_status()) = *podStatus;

    INFO("Event: {Object: CRI, Type: Statused Pod: %s}", request->pod_sandbox_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ListPodSandbox(grpc::ServerContext *context,
                                                       const runtime::v1alpha2::ListPodSandboxRequest *request,
                                                       runtime::v1alpha2::ListPodSandboxResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    INFO("Event: {Object: CRI, Type: Listing all Pods}");

    std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> pods;
    m_rService->ListPodSandbox(request->has_filter() ? &request->filter() : nullptr, pods, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to list all pods: %s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    for (auto iter = pods.begin(); iter != pods.end(); ++iter) {
        runtime::v1alpha2::PodSandbox *pod = reply->add_items();
        if (pod == nullptr) {
            ERROR("Object: CRI, Type: Failed to list all pods:Out of memory");
            return grpc::Status(grpc::StatusCode::UNKNOWN, "Out of memory");
        }
        *pod = *(iter->get());
    }

    INFO("Event: {Object: CRI, Type: Listed all Pods}");

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::PodSandboxStats(grpc::ServerContext *context,
                                                        const runtime::v1alpha2::PodSandboxStatsRequest *request,
                                                        runtime::v1alpha2::PodSandboxStatsResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    INFO("Event: {Object: CRI, Type: Stats Pod: %s}", request->pod_sandbox_id().c_str());

    std::unique_ptr<runtime::v1alpha2::PodSandboxStats> podStats;
    podStats = m_rService->PodSandboxStats(request->pod_sandbox_id(), error);
    if (!error.Empty() || podStats == nullptr) {
        ERROR("Object: CRI, Type: Failed to stats pod:%s due to %s", request->pod_sandbox_id().c_str(),
              error.GetCMessage());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_stats()) = *podStats;

    INFO("Event: {Object: CRI, Type: Statsed Pod: %s}", request->pod_sandbox_id().c_str());

    return grpc::Status::OK;
}

grpc::Status
RuntimeRuntimeServiceImpl::ListPodSandboxStats(grpc::ServerContext *context,
                                               const runtime::v1alpha2::ListPodSandboxStatsRequest *request,
                                               runtime::v1alpha2::ListPodSandboxStatsResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    INFO("Event: {Object: CRI, Type: Listing Pods Stats}");

    std::vector<std::unique_ptr<runtime::v1alpha2::PodSandboxStats>> podsStats;
    m_rService->ListPodSandboxStats(request->has_filter() ? &request->filter() : nullptr, podsStats, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to list pods stats: %s", error.GetCMessage());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    for (auto iter = podsStats.begin(); iter != podsStats.end(); ++iter) {
        runtime::v1alpha2::PodSandboxStats *podStats = reply->add_stats();
        if (podStats == nullptr) {
            ERROR("Object: CRI, Type: Failed to list pods stats: Out of memory");
            return grpc::Status(grpc::StatusCode::UNKNOWN, "Out of memory");
        }
        *podStats = *(iter->get());
    }

    INFO("Event: {Object: CRI, Type: Listed Pods Stats}");

    return grpc::Status::OK;
}

grpc::Status
RuntimeRuntimeServiceImpl::UpdateContainerResources(grpc::ServerContext *context,
                                                    const runtime::v1alpha2::UpdateContainerResourcesRequest *request,
                                                    runtime::v1alpha2::UpdateContainerResourcesResponse *reply)
{
    Errors error;

    if (request == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    WARN("Event: {Object: CRI, Type: Updating container resources: %s}", request->container_id().c_str());

    m_rService->UpdateContainerResources(request->container_id(), request->linux(), error);
    if (error.NotEmpty()) {
        ERROR("Object: CRI, Type: Failed to update container:%s due to %s", request->container_id().c_str(),
              error.GetMessage().c_str());
        return ToGRPCStatus(error);
    }

    WARN("Event: {Object: CRI, Type: Updated container resources: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::Exec(grpc::ServerContext *context,
                                             const runtime::v1alpha2::ExecRequest *request,
                                             runtime::v1alpha2::ExecResponse *response)
{
    Errors error;

    if (request == nullptr || response == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    EVENT("Event: {Object: CRI, Type: execing Container: %s}", request->container_id().c_str());

    m_rService->Exec(*request, response, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to exec container:%s due to %s", request->container_id().c_str(),
              error.GetMessage().c_str());
        return ToGRPCStatus(error);
    }

    EVENT("Event: {Object: CRI, Type: execed Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::Attach(grpc::ServerContext *context,
                                               const runtime::v1alpha2::AttachRequest *request,
                                               runtime::v1alpha2::AttachResponse *response)
{
    Errors error;

    if (request == nullptr || response == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    EVENT("Event: {Object: CRI, Type: attaching Container: %s}", request->container_id().c_str());

    m_rService->Attach(*request, response, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to attach container:%s due to %s", request->container_id().c_str(),
              error.GetMessage().c_str());
        return ToGRPCStatus(error);
    }

    EVENT("Event: {Object: CRI, Type: attched Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status
RuntimeRuntimeServiceImpl::UpdateRuntimeConfig(grpc::ServerContext *context,
                                               const runtime::v1alpha2::UpdateRuntimeConfigRequest *request,
                                               runtime::v1alpha2::UpdateRuntimeConfigResponse *reply)
{
    Errors error;

    if (request == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    EVENT("Event: {Object: CRI, Type: Updating Runtime Config}");

    m_rService->UpdateRuntimeConfig(request->runtime_config(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to update runtime config:%s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: Updated Runtime Config}");

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::Status(grpc::ServerContext *context,
                                               const runtime::v1alpha2::StatusRequest *request,
                                               runtime::v1alpha2::StatusResponse *reply)
{
    Errors error;

    if (request == nullptr || reply == nullptr) {
        ERROR("Invalid input arguments");
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid input arguments");
    }

    INFO("Event: {Object: CRI, Type: Statusing daemon}");

    std::unique_ptr<runtime::v1alpha2::RuntimeStatus> status = m_rService->Status(error);
    if (status == nullptr || error.NotEmpty()) {
        ERROR("Object: CRI, Type: Failed to status daemon:%s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_status()) = *status;

    INFO("Event: {Object: CRI, Type: Statused daemon}");

    return grpc::Status::OK;
}
