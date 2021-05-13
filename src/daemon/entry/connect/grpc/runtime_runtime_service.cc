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
#include "runtime_runtime_service.h"
#include <string>
#include <memory>
#include <vector>
#include "stream_server.h"
#include "route_callback_register.h"
#include "isula_libutils/log.h"
#include "cri_runtime_service_impl.h"
#include "cri_runtime_versioner_service_impl.h"
#include "cri_container_manager_service_impl.h"
#include "cri_pod_sandbox_manager_service_impl.h"
#include "cri_runtime_manager_service_impl.h"
#include "cri_helpers.h"

using namespace CRI;

void RuntimeRuntimeServiceImpl::Init(Network::NetworkPluginConf mConf, isulad_daemon_configs *config, Errors &err)
{
    std::string podSandboxImage;
    if (config->pod_sandbox_image != nullptr) {
        podSandboxImage = config->pod_sandbox_image;
    } else {
        podSandboxImage = CRIHelpers::GetDefaultSandboxImage(err);
        if (err.NotEmpty()) {
            return;
        }
    }
    // Assembly implementation for CRIRuntimeServiceImpl
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr) {
        ERROR("Get callback failed");
        return;
    }

    std::vector<std::shared_ptr<Network::NetworkPlugin>> plugins;
    Network::ProbeNetworkPlugins(mConf.GetPluginConfDir(), mConf.GetPluginBinDir(), &plugins);

    std::shared_ptr<Network::NetworkPlugin> chosen { nullptr };
    Network::InitNetworkPlugin(&plugins, mConf.GetPluginName(), mConf.GetHairpinMode(), mConf.GetNonMasqueradeCIDR(),
                               mConf.GetMTU(), &chosen, err);
    if (err.NotEmpty()) {
        ERROR("Init network plugin failed: %s", err.GetCMessage());
        return;
    }

    auto pluginManager = std::make_shared<Network::PluginManager>(chosen);

    RuntimeVersionerService *runtimeVersioner = new RuntimeVersionerServiceImpl(cb);
    ContainerManagerService *containerManager = new ContainerManagerServiceImpl(cb);
    PodSandboxManagerService *podSandboxManager = new PodSandboxManagerServiceImpl(podSandboxImage, cb, pluginManager);
    RuntimeManagerService *runtimeManager = new RuntimeManagerServiceImpl(cb, pluginManager);
    std::unique_ptr<CRI::CRIRuntimeService> service(
        new CRIRuntimeServiceImpl(runtimeVersioner, containerManager, podSandboxManager, runtimeManager));
    rService = std::move(service);

    websocket_server_init(err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetMessage().c_str());
        return;
    }
}

void RuntimeRuntimeServiceImpl::Wait()
{
    websocket_server_wait();
}

void RuntimeRuntimeServiceImpl::Shutdown()
{
    websocket_server_shutdown();
}

grpc::Status RuntimeRuntimeServiceImpl::Version(grpc::ServerContext *context,
                                                const runtime::v1alpha2::VersionRequest *request,
                                                runtime::v1alpha2::VersionResponse *reply)
{
    Errors error;
    rService->Version(request->version(), reply, error);
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

    EVENT("Event: {Object: CRI, Type: Creating Container}");

    std::string responseID =
        rService->CreateContainer(request->pod_sandbox_id(), request->config(), request->sandbox_config(), error);
    if (!error.Empty() || responseID.empty()) {
        ERROR("Object: CRI, Type: Failed to create container");
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
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

    EVENT("Event: {Object: CRI, Type: Starting Container: %s}", request->container_id().c_str());

    rService->StartContainer(request->container_id(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to start container %s", request->container_id().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: Started Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::StopContainer(grpc::ServerContext *context,
                                                      const runtime::v1alpha2::StopContainerRequest *request,
                                                      runtime::v1alpha2::StopContainerResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Stopping Container: %s}", request->container_id().c_str());

    rService->StopContainer(request->container_id(), (int64_t)request->timeout(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to stop container %s", request->container_id().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: Stopped Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::RemoveContainer(grpc::ServerContext *context,
                                                        const runtime::v1alpha2::RemoveContainerRequest *request,
                                                        runtime::v1alpha2::RemoveContainerResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Removing Container: %s}", request->container_id().c_str());

    rService->RemoveContainer(request->container_id(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to remove container %s", request->container_id().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: Removed Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ListContainers(grpc::ServerContext *context,
                                                       const runtime::v1alpha2::ListContainersRequest *request,
                                                       runtime::v1alpha2::ListContainersResponse *reply)
{
    Errors error;

    WARN("Event: {Object: CRI, Type: Listing all Container}");

    std::vector<std::unique_ptr<runtime::v1alpha2::Container>> containers;
    rService->ListContainers(request->has_filter() ? &request->filter() : nullptr, &containers, error);
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

    WARN("Event: {Object: CRI, Type: Listed all Container}");

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ListContainerStats(grpc::ServerContext *context,
                                                           const runtime::v1alpha2::ListContainerStatsRequest *request,
                                                           runtime::v1alpha2::ListContainerStatsResponse *reply)
{
    Errors error;

    WARN("Event: {Object: CRI, Type: Listing all Container stats}");

    std::vector<std::unique_ptr<runtime::v1alpha2::ContainerStats>> containers;
    rService->ListContainerStats(request->has_filter() ? &request->filter() : nullptr, &containers, error);
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

    WARN("Event: {Object: CRI, Type: Listed all Container stats}");

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ContainerStatus(grpc::ServerContext *context,
                                                        const runtime::v1alpha2::ContainerStatusRequest *request,
                                                        runtime::v1alpha2::ContainerStatusResponse *reply)
{
    Errors error;

    WARN("Event: {Object: CRI, Type: Statusing Container: %s}", request->container_id().c_str());

    std::unique_ptr<runtime::v1alpha2::ContainerStatus> contStatus =
        rService->ContainerStatus(request->container_id(), error);
    if (!error.Empty() || !contStatus) {
        ERROR("Object: CRI, Type: Failed to get container status %s", request->container_id().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_status()) = *contStatus;

    WARN("Event: {Object: CRI, Type: Statused Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ExecSync(grpc::ServerContext *context,
                                                 const runtime::v1alpha2::ExecSyncRequest *request,
                                                 runtime::v1alpha2::ExecSyncResponse *reply)
{
    Errors error;

    WARN("Event: {Object: CRI, Type: sync execing Container: %s}", request->container_id().c_str());

    rService->ExecSync(request->container_id(), request->cmd(), request->timeout(), reply, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to sync exec container: %s", request->container_id().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    WARN("Event: {Object: CRI, Type: sync execed Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::RunPodSandbox(grpc::ServerContext *context,
                                                      const runtime::v1alpha2::RunPodSandboxRequest *request,
                                                      runtime::v1alpha2::RunPodSandboxResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Running Pod}");

    std::string responseID = rService->RunPodSandbox(request->config(), request->runtime_handler(), error);
    if (!error.Empty() || responseID.empty()) {
        ERROR("Object: CRI, Type: Failed to run pod:%s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    reply->set_pod_sandbox_id(responseID);

    EVENT("Event: {Object: CRI, Type: Run Pod success}");

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::StopPodSandbox(grpc::ServerContext *context,
                                                       const runtime::v1alpha2::StopPodSandboxRequest *request,
                                                       runtime::v1alpha2::StopPodSandboxResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Stopping Pod: %s}", request->pod_sandbox_id().c_str());

    rService->StopPodSandbox(request->pod_sandbox_id(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to stop pod:%s due to %s", request->pod_sandbox_id().c_str(),
              error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: Stopped Pod: %s}", request->pod_sandbox_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::RemovePodSandbox(grpc::ServerContext *context,
                                                         const runtime::v1alpha2::RemovePodSandboxRequest *request,
                                                         runtime::v1alpha2::RemovePodSandboxResponse *reply)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: Removing Pod: %s}", request->pod_sandbox_id().c_str());

    rService->RemovePodSandbox(request->pod_sandbox_id(), error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to remove pod:%s due to %s", request->pod_sandbox_id().c_str(),
              error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: Removed Pod: %s}", request->pod_sandbox_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::PodSandboxStatus(grpc::ServerContext *context,
                                                         const runtime::v1alpha2::PodSandboxStatusRequest *request,
                                                         runtime::v1alpha2::PodSandboxStatusResponse *reply)
{
    Errors error;

    WARN("Event: {Object: CRI, Type: Status Pod: %s}", request->pod_sandbox_id().c_str());

    std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> podStatus;
    podStatus = rService->PodSandboxStatus(request->pod_sandbox_id(), error);
    if (!error.Empty() || !podStatus) {
        ERROR("Object: CRI, Type: Failed to status pod:%s due to %s", request->pod_sandbox_id().c_str(),
              error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_status()) = *podStatus;

    WARN("Event: {Object: CRI, Type: Statused Pod: %s}", request->pod_sandbox_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ListPodSandbox(grpc::ServerContext *context,
                                                       const runtime::v1alpha2::ListPodSandboxRequest *request,
                                                       runtime::v1alpha2::ListPodSandboxResponse *reply)
{
    Errors error;

    WARN("Event: {Object: CRI, Type: Listing all Pods}");

    std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> pods;
    rService->ListPodSandbox(request->has_filter() ? &request->filter() : nullptr, &pods, error);
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

    WARN("Event: {Object: CRI, Type: Listed all Pods}");

    return grpc::Status::OK;
}

grpc::Status
RuntimeRuntimeServiceImpl::UpdateContainerResources(grpc::ServerContext *context,
                                                    const runtime::v1alpha2::UpdateContainerResourcesRequest *request,
                                                    runtime::v1alpha2::UpdateContainerResourcesResponse *reply)
{
    Errors error;

    WARN("Event: {Object: CRI, Type: Updating container resources: %s}", request->container_id().c_str());

    rService->UpdateContainerResources(request->container_id(), request->linux(), error);
    if (error.NotEmpty()) {
        ERROR("Object: CRI, Type: Failed to update container:%s due to %s", request->container_id().c_str(),
              error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    WARN("Event: {Object: CRI, Type: Updated container resources: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::Exec(grpc::ServerContext *context,
                                             const runtime::v1alpha2::ExecRequest *request,
                                             runtime::v1alpha2::ExecResponse *response)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: execing Container: %s}", request->container_id().c_str());

    rService->Exec(*request, response, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to exec container:%s due to %s", request->container_id().c_str(),
              error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    EVENT("Event: {Object: CRI, Type: execed Container: %s}", request->container_id().c_str());

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::Attach(grpc::ServerContext *context,
                                               const runtime::v1alpha2::AttachRequest *request,
                                               runtime::v1alpha2::AttachResponse *response)
{
    Errors error;

    EVENT("Event: {Object: CRI, Type: attaching Container: %s}", request->container_id().c_str());

    rService->Attach(*request, response, error);
    if (!error.Empty()) {
        ERROR("Object: CRI, Type: Failed to attach container:%s due to %s", request->container_id().c_str(),
              error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
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

    EVENT("Event: {Object: CRI, Type: Updating Runtime Config}");

    rService->UpdateRuntimeConfig(request->runtime_config(), error);
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

    WARN("Event: {Object: CRI, Type: Statusing daemon}");

    std::unique_ptr<runtime::v1alpha2::RuntimeStatus> status = rService->Status(error);
    if (status == nullptr || error.NotEmpty()) {
        ERROR("Object: CRI, Type: Failed to status daemon:%s", error.GetMessage().c_str());
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_status()) = *status;

    WARN("Event: {Object: CRI, Type: Statused daemon}");

    return grpc::Status::OK;
}
