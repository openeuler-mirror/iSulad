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
#include "cri_v1_runtime_runtime_service.h"
#include <string>
#include <memory>
#include <vector>

#include <isula_libutils/log.h>

#include "callback.h"
#include "network_plugin.h"
#include "v1_cri_runtime_service_impl.h"

using namespace CRIV1;

void RuntimeV1RuntimeServiceImpl::Init(std::string &podSandboxImage, std::shared_ptr<Network::PluginManager> networkPlugin, Errors &err)
{
    // Assembly implementation for CRIRuntimeServiceImpl
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr) {
        ERROR("Init isulad service executor failure.");
        err.SetError("Init isulad service executor failure.");
        return;
    }

    m_rService = std::unique_ptr<CRIV1::CRIRuntimeService>(new CRIRuntimeServiceImpl(podSandboxImage, cb, networkPlugin));
}

void RuntimeV1RuntimeServiceImpl::Wait()
{
}

void RuntimeV1RuntimeServiceImpl::Shutdown()
{
}

grpc::Status RuntimeV1RuntimeServiceImpl::Version(grpc::ServerContext *context,
                                                const runtime::v1::VersionRequest *request,
                                                runtime::v1::VersionResponse *reply)
{
    Errors error;
    m_rService->Version(request->version(), reply, error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::CreateContainer(grpc::ServerContext *context,
                                                        const runtime::v1::CreateContainerRequest *request,
                                                        runtime::v1::CreateContainerResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Creating Container}");

    std::string responseID =
        m_rService->CreateContainer(request->pod_sandbox_id(), request->config(), request->sandbox_config(), error);
    if (!error.Empty() || responseID.empty()) {
        ERROR("Object: CRI, Type: Failed to create container");
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    reply->set_container_id(responseID);

    EVENT("Event: {Object: CRI, Type: Created Container %s}", responseID.c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::StartContainer(grpc::ServerContext *context,
                                                       const runtime::v1::StartContainerRequest *request,
                                                       runtime::v1::StartContainerResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Starting Container: %s}", request->container_id().c_str());

    m_rService->StartContainer(request->container_id(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to start container %s", request->container_id().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: Started Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::StopContainer(grpc::ServerContext *context,
                                                      const runtime::v1::StopContainerRequest *request,
                                                      runtime::v1::StopContainerResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Stopping Container: %s}", request->container_id().c_str());

    m_rService->StopContainer(request->container_id(), (int64_t)request->timeout(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to stop container %s", request->container_id().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: Stopped Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::RemoveContainer(grpc::ServerContext *context,
                                                        const runtime::v1::RemoveContainerRequest *request,
                                                        runtime::v1::RemoveContainerResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Removing Container: %s}", request->container_id().c_str());

    m_rService->RemoveContainer(request->container_id(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to remove container %s", request->container_id().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: Removed Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::ListContainers(grpc::ServerContext *context,
                                                       const runtime::v1::ListContainersRequest *request,
                                                       runtime::v1::ListContainersResponse *reply)
{
    Errors error;

    INFO("Event: {Object: CRI, Type: Listing all Container}");

    std::vector<std::unique_ptr<runtime::v1::Container>> containers;
    m_rService->ListContainers(request->has_filter() ? &request->filter() : nullptr, &containers, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to list all containers %s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    for (auto iter = containers.begin(); iter != containers.end(); ++iter) {
        runtime::v1::Container *container = reply->add_containers();
        if (container == nullptr) {
            ERROR("Object: CRI, Type: Failed to list all containers: out of memory");
            return grpc::Status(grpc::StatusCode::UNKNOWN, "Out of memory");
        }
        *container = *(iter->get());
    }

    INFO("Event: {Object: CRI, Type: Listed all Container}");

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::ContainerStats(grpc::ServerContext *context,
                                                       const runtime::v1::ContainerStatsRequest *request,
                                                       runtime::v1::ContainerStatsResponse *reply)
{
    Errors error;

    INFO("Event: {Object: CRI, Type: Getting Container Stats: %s}", request->container_id().c_str());

    std::unique_ptr<runtime::v1::ContainerStats> contStats =
        m_rService->ContainerStats(request->container_id(), error);
    if (!error.Empty() || !contStats) {
        ERROR("Object: CRI, Type: Failed to get container stats %s", request->container_id().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_stats()) = *contStats;

    INFO("Event: {Object: CRI, Type: Got Container stats: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::ListContainerStats(grpc::ServerContext *context,
                                                           const runtime::v1::ListContainerStatsRequest *request,
                                                           runtime::v1::ListContainerStatsResponse *reply)
{
    Errors error;

    INFO("Event: {Object: CRI, Type: Listing all Container stats}");

    std::vector<std::unique_ptr<runtime::v1::ContainerStats>> containers;
    m_rService->ListContainerStats(request->has_filter() ? &request->filter() : nullptr, &containers, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to list all containers stat %s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    for (auto iter = containers.begin(); iter != containers.end(); ++iter) {
        runtime::v1::ContainerStats *container = reply->add_stats();
        if (container == nullptr) {
            ERROR("Object: CRI, Type: Failed to list all containers stats: out of memory");
            return grpc::Status(grpc::StatusCode::UNKNOWN, "Out of memory");
        }
        *container = *(iter->get());
    }

    INFO("Event: {Object: CRI, Type: Listed all Container stats}");

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::ContainerStatus(grpc::ServerContext *context,
                                                        const runtime::v1::ContainerStatusRequest *request,
                                                        runtime::v1::ContainerStatusResponse *reply)
{
    Errors error;

    INFO("Event: {Object: CRI, Type: Statusing Container: %s}", request->container_id().c_str());

    std::unique_ptr<runtime::v1::ContainerStatus> contStatus =
        m_rService->ContainerStatus(request->container_id(), error);
    if (!error.Empty() || !contStatus) {
        ERROR("Object: CRI, Type: Failed to get container status %s", request->container_id().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_status()) = *contStatus;

    INFO("Event: {Object: CRI, Type: Statused Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::ExecSync(grpc::ServerContext *context,
                                                 const runtime::v1::ExecSyncRequest *request,
                                                 runtime::v1::ExecSyncResponse *reply)
{
    Errors error;

    WARN("Event: {Object: CRI, Type: sync execing Container: %s}", request->container_id().c_str());

    m_rService->ExecSync(request->container_id(), request->cmd(), request->timeout(), reply, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to sync exec container: %s", request->container_id().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    WARN("Event: {Object: CRI, Type: sync execed Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::RunPodSandbox(grpc::ServerContext *context,
                                                      const runtime::v1::RunPodSandboxRequest *request,
                                                      runtime::v1::RunPodSandboxResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Running Pod}");

    std::string responseID = m_rService->RunPodSandbox(request->config(), request->runtime_handler(), error);
    if (!error.Empty() || responseID.empty()) {
        ERROR("Object: CRI, Type: Failed to run pod:%s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    reply->set_pod_sandbox_id(responseID);

    EVENT("Event: {Object: CRI, Type: Run Pod success}");

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::StopPodSandbox(grpc::ServerContext *context,
                                                       const runtime::v1::StopPodSandboxRequest *request,
                                                       runtime::v1::StopPodSandboxResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Stopping Pod: %s}", request->pod_sandbox_id().c_str());

    m_rService->StopPodSandbox(request->pod_sandbox_id(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to stop pod:%s due to %s", request->pod_sandbox_id().c_str(),
              error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: Stopped Pod: %s}", request->pod_sandbox_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::RemovePodSandbox(grpc::ServerContext *context,
                                                         const runtime::v1::RemovePodSandboxRequest *request,
                                                         runtime::v1::RemovePodSandboxResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Removing Pod: %s}", request->pod_sandbox_id().c_str());

    m_rService->RemovePodSandbox(request->pod_sandbox_id(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to remove pod:%s due to %s", request->pod_sandbox_id().c_str(),
              error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: Removed Pod: %s}", request->pod_sandbox_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::PodSandboxStatus(grpc::ServerContext *context,
                                                         const runtime::v1::PodSandboxStatusRequest *request,
                                                         runtime::v1::PodSandboxStatusResponse *reply)
{
    Errors error;

    INFO("Event: {Object: CRI, Type: Status Pod: %s}", request->pod_sandbox_id().c_str());

    std::unique_ptr<runtime::v1::PodSandboxStatus> podStatus;
    podStatus = m_rService->PodSandboxStatus(request->pod_sandbox_id(), error);
    if (!error.Empty() || !podStatus) {
        ERROR("Object: CRI, Type: Failed to status pod:%s due to %s", request->pod_sandbox_id().c_str(),
              error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_status()) = *podStatus;

    INFO("Event: {Object: CRI, Type: Statused Pod: %s}", request->pod_sandbox_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::ListPodSandbox(grpc::ServerContext *context,
                                                       const runtime::v1::ListPodSandboxRequest *request,
                                                       runtime::v1::ListPodSandboxResponse *reply)
{
    Errors error;

    INFO("Event: {Object: CRI, Type: Listing all Pods}");

    std::vector<std::unique_ptr<runtime::v1::PodSandbox>> pods;
    runtime::v1::PodSandboxFilter emptyFilters;
    m_rService->ListPodSandbox(request->has_filter() ? request->filter() : emptyFilters, pods, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to list all pods: %s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    for (auto iter = pods.begin(); iter != pods.end(); ++iter) {
        runtime::v1::PodSandbox *pod = reply->add_items();
        if (pod == nullptr) {
            ERROR("Object: CRI, Type: Failed to list all pods:Out of memory");
            return grpc::Status(grpc::StatusCode::UNKNOWN, "Out of memory");
        }
        *pod = *(iter->get());
    }

    INFO("Event: {Object: CRI, Type: Listed all Pods}");

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::PodSandboxStats(grpc::ServerContext *context,
                                                        const runtime::v1::PodSandboxStatsRequest *request,
                                                        runtime::v1::PodSandboxStatsResponse *reply)
{
    Errors error;

    INFO("Event: {Object: CRI, Type: Stats Pod: %s}", request->pod_sandbox_id().c_str());

    std::unique_ptr<runtime::v1::PodSandboxStats> podStats;
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
RuntimeV1RuntimeServiceImpl::ListPodSandboxStats(grpc::ServerContext *context,
                                               const runtime::v1::ListPodSandboxStatsRequest *request,
                                               runtime::v1::ListPodSandboxStatsResponse *reply)
{
    Errors error;

    INFO("Event: {Object: CRI, Type: Listing Pods Stats}");

    std::vector<std::unique_ptr<runtime::v1::PodSandboxStats>> podsStats;
    m_rService->ListPodSandboxStats(request->has_filter() ? &request->filter() : nullptr, &podsStats, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to list pods stats: %s", error.GetCMessage());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    for (auto iter = podsStats.begin(); iter != podsStats.end(); ++iter) {
        runtime::v1::PodSandboxStats *podStats = reply->add_stats();
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
RuntimeV1RuntimeServiceImpl::UpdateContainerResources(grpc::ServerContext *context,
                                                    const runtime::v1::UpdateContainerResourcesRequest *request,
                                                    runtime::v1::UpdateContainerResourcesResponse *reply)
{
    Errors error;

    WARN("Event: {Object: CRI, Type: Updating container resources: %s}", request->container_id().c_str());

    m_rService->UpdateContainerResources(request->container_id(), request->linux(), error);
    if (error.NotEmpty()) {
        ERROR("Object: CRI, Type: Failed to update container:%s due to %s", request->container_id().c_str(),
              error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    WARN("Event: {Object: CRI, Type: Updated container resources: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::Exec(grpc::ServerContext *context,
                                             const runtime::v1::ExecRequest *request,
                                             runtime::v1::ExecResponse *response)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: execing Container: %s}", request->container_id().c_str());

    m_rService->Exec(*request, response, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to exec container:%s due to %s", request->container_id().c_str(),
              error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: execed Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::Attach(grpc::ServerContext *context,
                                               const runtime::v1::AttachRequest *request,
                                               runtime::v1::AttachResponse *response)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: attaching Container: %s}", request->container_id().c_str());

    m_rService->Attach(*request, response, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to attach container:%s due to %s", request->container_id().c_str(),
              error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: attched Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status
RuntimeV1RuntimeServiceImpl::UpdateRuntimeConfig(grpc::ServerContext *context,
                                               const runtime::v1::UpdateRuntimeConfigRequest *request,
                                               runtime::v1::UpdateRuntimeConfigResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Updating Runtime Config}");

    m_rService->UpdateRuntimeConfig(request->runtime_config(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to update runtime config:%s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: Updated Runtime Config}");

    return grpc::Status::OK;
}

grpc::Status RuntimeV1RuntimeServiceImpl::Status(grpc::ServerContext *context,
                                               const runtime::v1::StatusRequest *request,
                                               runtime::v1::StatusResponse *reply)
{
    Errors error;

    INFO("Event: {Object: CRI, Type: Statusing daemon}");

    std::unique_ptr<runtime::v1::RuntimeStatus> status = m_rService->Status(error);
    if (status == nullptr || error.NotEmpty()) {
        ERROR("Object: CRI, Type: Failed to status daemon:%s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_status()) = *status;

    INFO("Event: {Object: CRI, Type: Statused daemon}");

    return grpc::Status::OK;
}
