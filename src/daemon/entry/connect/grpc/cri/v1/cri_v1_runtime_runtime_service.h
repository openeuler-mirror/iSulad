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
 * Description: provide container runtime functions
 ******************************************************************************/

#ifndef DAEMON_ENTRY_CONNECT_GRPC_CRI_V1_RUNTIME_RUNTIME_SERVICE_H
#define DAEMON_ENTRY_CONNECT_GRPC_CRI_V1_RUNTIME_RUNTIME_SERVICE_H

#include "api_v1.grpc.pb.h"
#include <memory>

#include <isula_libutils/isulad_daemon_configs.h>
#include "v1_cri_runtime_service.h"
#include "errors.h"

// Implement of runtime RuntimeService
class RuntimeV1RuntimeServiceImpl : public runtime::v1::RuntimeService::Service {
public:
    void Init(std::string &podSandboxImage, std::shared_ptr<Network::PluginManager> networkPlugin, Errors &err);
    void Wait();
    void Shutdown();
    grpc::Status Version(grpc::ServerContext *context, const runtime::v1::VersionRequest *request,
                         runtime::v1::VersionResponse *reply) override;

    grpc::Status CreateContainer(grpc::ServerContext *context, const runtime::v1::CreateContainerRequest *request,
                                 runtime::v1::CreateContainerResponse *reply) override;

    grpc::Status StartContainer(grpc::ServerContext *context, const runtime::v1::StartContainerRequest *request,
                                runtime::v1::StartContainerResponse *reply) override;

    grpc::Status StopContainer(grpc::ServerContext *context, const runtime::v1::StopContainerRequest *request,
                               runtime::v1::StopContainerResponse *reply) override;

    grpc::Status RemoveContainer(grpc::ServerContext *context, const runtime::v1::RemoveContainerRequest *request,
                                 runtime::v1::RemoveContainerResponse *reply) override;

    grpc::Status ListContainers(grpc::ServerContext *context, const runtime::v1::ListContainersRequest *request,
                                runtime::v1::ListContainersResponse *reply) override;

    grpc::Status ListContainerStats(grpc::ServerContext *context,
                                    const runtime::v1::ListContainerStatsRequest *request,
                                    runtime::v1::ListContainerStatsResponse *reply) override;

    grpc::Status ContainerStats(grpc::ServerContext *context, const runtime::v1::ContainerStatsRequest *request,
                                runtime::v1::ContainerStatsResponse *reply) override;

    grpc::Status ContainerStatus(grpc::ServerContext *context, const runtime::v1::ContainerStatusRequest *request,
                                 runtime::v1::ContainerStatusResponse *reply) override;

    grpc::Status ExecSync(grpc::ServerContext *context, const runtime::v1::ExecSyncRequest *request,
                          runtime::v1::ExecSyncResponse *reply) override;

    grpc::Status RunPodSandbox(grpc::ServerContext *context, const runtime::v1::RunPodSandboxRequest *request,
                               runtime::v1::RunPodSandboxResponse *reply) override;

    grpc::Status StopPodSandbox(grpc::ServerContext *context, const runtime::v1::StopPodSandboxRequest *request,
                                runtime::v1::StopPodSandboxResponse *reply) override;

    grpc::Status RemovePodSandbox(grpc::ServerContext *context,
                                  const runtime::v1::RemovePodSandboxRequest *request,
                                  runtime::v1::RemovePodSandboxResponse *reply) override;

    grpc::Status PodSandboxStatus(grpc::ServerContext *context,
                                  const runtime::v1::PodSandboxStatusRequest *request,
                                  runtime::v1::PodSandboxStatusResponse *reply) override;

    grpc::Status ListPodSandbox(grpc::ServerContext *context, const runtime::v1::ListPodSandboxRequest *request,
                                runtime::v1::ListPodSandboxResponse *reply) override;

    grpc::Status PodSandboxStats(grpc::ServerContext* context, const runtime::v1::PodSandboxStatsRequest* request,
                                 runtime::v1::PodSandboxStatsResponse* reply) override;

    grpc::Status ListPodSandboxStats(grpc::ServerContext *context,
                                     const runtime::v1::ListPodSandboxStatsRequest *request,
                                     runtime::v1::ListPodSandboxStatsResponse *reply) override;

    grpc::Status UpdateContainerResources(grpc::ServerContext *context,
                                          const runtime::v1::UpdateContainerResourcesRequest *request,
                                          runtime::v1::UpdateContainerResourcesResponse *reply) override;

    grpc::Status Exec(grpc::ServerContext *context, const runtime::v1::ExecRequest *request,
                      runtime::v1::ExecResponse *response) override;

    grpc::Status Attach(grpc::ServerContext *context, const runtime::v1::AttachRequest *request,
                        runtime::v1::AttachResponse *response) override;

    grpc::Status UpdateRuntimeConfig(grpc::ServerContext *context,
                                     const runtime::v1::UpdateRuntimeConfigRequest *request,
                                     runtime::v1::UpdateRuntimeConfigResponse *reply) override;

    grpc::Status Status(grpc::ServerContext *context, const runtime::v1::StatusRequest *request,
                        runtime::v1::StatusResponse *reply) override;

    grpc::Status RuntimeConfig(grpc::ServerContext *context,
                               const runtime::v1::RuntimeConfigRequest *request,
                               runtime::v1::RuntimeConfigResponse *reply) override;

private:
    std::unique_ptr<CRIV1::CRIRuntimeService> m_rService;
};

#endif // DAEMON_ENTRY_CONNECT_GRPC_CRI_V1_RUNTIME_RUNTIME_SERVICE_H
