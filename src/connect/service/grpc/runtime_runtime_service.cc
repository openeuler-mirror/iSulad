/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
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
#include "log.h"

void RuntimeRuntimeServiceImpl::Init(Network::NetworkPluginConf mConf, isulad_daemon_configs *config, Errors &err)
{
    std::string podSandboxImage;
    if (config->pod_sandbox_image != nullptr) {
        podSandboxImage = config->pod_sandbox_image;
    }
    rService.Init(mConf, podSandboxImage, err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetMessage().c_str());
        return;
    }
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

grpc::Status RuntimeRuntimeServiceImpl::Version(grpc::ServerContext *context, const runtime::VersionRequest *request,
                                                runtime::VersionResponse *reply)
{
    Errors error;
    rService.Version(request->version(), reply, error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::CreateContainer(grpc::ServerContext *context,
                                                        const runtime::CreateContainerRequest *request,
                                                        runtime::CreateContainerResponse *reply)
{
    Errors error;
    std::string responseID = rService.CreateContainer(request->pod_sandbox_id(), request->config(),
                                                      request->sandbox_config(), error);
    if (!error.Empty() || responseID.empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    reply->set_container_id(responseID);

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::StartContainer(grpc::ServerContext *context,
                                                       const runtime::StartContainerRequest *request,
                                                       runtime::StartContainerResponse *reply)
{
    Errors error;
    rService.StartContainer(request->container_id(), error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::StopContainer(grpc::ServerContext *context,
                                                      const runtime::StopContainerRequest *request,
                                                      runtime::StopContainerResponse *reply)
{
    Errors error;
    rService.StopContainer(request->container_id(), (int64_t)request->timeout(), error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::RemoveContainer(grpc::ServerContext *context,
                                                        const runtime::RemoveContainerRequest *request,
                                                        runtime::RemoveContainerResponse *reply)
{
    Errors error;
    rService.RemoveContainer(request->container_id(), error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ListContainers(grpc::ServerContext *context,
                                                       const runtime::ListContainersRequest *request,
                                                       runtime::ListContainersResponse *reply)
{
    Errors error;
    std::vector<std::unique_ptr<runtime::Container>> containers;
    rService.ListContainers(request->has_filter() ? &request->filter() : nullptr, &containers, error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    for (auto iter = containers.begin(); iter != containers.end(); ++iter) {
        runtime::Container *container = reply->add_containers();
        if (container == nullptr) {
            return grpc::Status(grpc::StatusCode::UNKNOWN, "Out of memory");
        }
        *container = *(iter->get());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ListContainerStats(grpc::ServerContext *context,
                                                           const runtime::ListContainerStatsRequest *request,
                                                           runtime::ListContainerStatsResponse *reply)
{
    Errors error;

    std::vector<std::unique_ptr<runtime::ContainerStats>> containers;
    rService.ListContainerStats(request->has_filter() ? &request->filter() : nullptr, &containers, error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    for (auto iter = containers.begin(); iter != containers.end(); ++iter) {
        runtime::ContainerStats *container = reply->add_stats();
        if (container == nullptr) {
            return grpc::Status(grpc::StatusCode::UNKNOWN, "Out of memory");
        }
        *container = *(iter->get());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ContainerStatus(grpc::ServerContext *context,
                                                        const runtime::ContainerStatusRequest *request,
                                                        runtime::ContainerStatusResponse *reply)
{
    Errors error;
    std::unique_ptr<runtime::ContainerStatus> contStatus = rService.ContainerStatus(request->container_id(), error);
    if (!error.Empty() || !contStatus) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_status()) = *contStatus;

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ExecSync(grpc::ServerContext *context, const runtime::ExecSyncRequest *request,
                                                 runtime::ExecSyncResponse *reply)
{
    Errors error;
    rService.ExecSync(request->container_id(), request->cmd(), request->timeout(), reply, error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::RunPodSandbox(
    grpc::ServerContext *context, const runtime::RunPodSandboxRequest *request,
    runtime::RunPodSandboxResponse *reply)
{
    Errors error;
    std::string responseID = rService.RunPodSandbox(request->config(), error);
    if (!error.Empty() || responseID.empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    reply->set_pod_sandbox_id(responseID);

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::StopPodSandbox(
    grpc::ServerContext *context, const runtime::StopPodSandboxRequest *request,
    runtime::StopPodSandboxResponse *reply)
{
    Errors error;
    rService.StopPodSandbox(request->pod_sandbox_id(), error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::RemovePodSandbox(
    grpc::ServerContext *context, const runtime::RemovePodSandboxRequest *request,
    runtime::RemovePodSandboxResponse *reply)
{
    Errors error;
    rService.RemovePodSandbox(request->pod_sandbox_id(), error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::PodSandboxStatus(
    grpc::ServerContext *context, const runtime::PodSandboxStatusRequest *request,
    runtime::PodSandboxStatusResponse *reply)
{
    Errors error;
    std::unique_ptr<runtime::PodSandboxStatus> podStatus;
    podStatus = rService.PodSandboxStatus(request->pod_sandbox_id(), error);
    if (!error.Empty() || !podStatus) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_status()) = *podStatus;

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::ListPodSandbox(
    grpc::ServerContext *context, const runtime::ListPodSandboxRequest *request,
    runtime::ListPodSandboxResponse *reply)
{
    Errors error;
    std::vector<std::unique_ptr<runtime::PodSandbox>> pods;
    rService.ListPodSandbox(request->has_filter() ? &request->filter() : nullptr, &pods, error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    for (auto iter = pods.begin(); iter != pods.end(); ++iter) {
        runtime::PodSandbox *pod = reply->add_items();
        if (pod == nullptr) {
            return grpc::Status(grpc::StatusCode::UNKNOWN, "Out of memory");
        }
        *pod = *(iter->get());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::UpdateContainerResources(
    grpc::ServerContext *context, const runtime::UpdateContainerResourcesRequest *request,
    runtime::UpdateContainerResourcesResponse *reply)
{
    Errors error;
    rService.UpdateContainerResources(request->container_id(), request->linux(), error);
    if (error.NotEmpty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    return grpc::Status::OK;
}


grpc::Status RuntimeRuntimeServiceImpl::Exec(grpc::ServerContext *context, const runtime::ExecRequest *request,
                                             runtime::ExecResponse *response)
{
    Errors error;
    rService.Exec(*request, response, error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::Attach(grpc::ServerContext *context, const runtime::AttachRequest *request,
                                               runtime::AttachResponse *response)
{
    Errors error;
    rService.Attach(*request, response, error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::UpdateRuntimeConfig(grpc::ServerContext *context,
                                                            const runtime::UpdateRuntimeConfigRequest *request,
                                                            runtime::UpdateRuntimeConfigResponse *reply)
{
    Errors error;
    rService.UpdateRuntimeConfig(request->runtime_config(), error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeRuntimeServiceImpl::Status(grpc::ServerContext *context, const runtime::StatusRequest *request,
                                               runtime::StatusResponse *reply)
{
    Errors error;
    std::unique_ptr<runtime::RuntimeStatus> status = rService.Status(error);
    if (status == nullptr || error.NotEmpty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    *(reply->mutable_status()) = *status;

    return grpc::Status::OK;
}

