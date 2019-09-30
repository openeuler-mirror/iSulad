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
 * Description: provide container runtime functions
 ******************************************************************************/

#ifndef _RUNTIME_RUNTIME_SERVICES_IMPL_H_
#define _RUNTIME_RUNTIME_SERVICES_IMPL_H_

#include "api.grpc.pb.h"
#include "callback.h"
#include "cri_runtime_service.h"
#include "network_plugin.h"
#include "isulad_daemon_configs.h"
#include "errors.h"

// Implement of runtime RuntimeService
class RuntimeRuntimeServiceImpl : public runtime::RuntimeService::Service {
public:
    void Init(Network::NetworkPluginConf mConf, isulad_daemon_configs *config, Errors &err);
    void Wait();
    void Shutdown();
    grpc::Status Version(grpc::ServerContext *context, const runtime::VersionRequest *request,
                         runtime::VersionResponse *reply) override;

    grpc::Status CreateContainer(grpc::ServerContext *context, const runtime::CreateContainerRequest *request,
                                 runtime::CreateContainerResponse *reply) override;

    grpc::Status StartContainer(grpc::ServerContext *context, const runtime::StartContainerRequest *request,
                                runtime::StartContainerResponse *reply) override;

    grpc::Status StopContainer(grpc::ServerContext *context, const runtime::StopContainerRequest *request,
                               runtime::StopContainerResponse *reply) override;

    grpc::Status RemoveContainer(grpc::ServerContext *context, const runtime::RemoveContainerRequest *request,
                                 runtime::RemoveContainerResponse *reply) override;

    grpc::Status ListContainers(grpc::ServerContext *context, const runtime::ListContainersRequest *request,
                                runtime::ListContainersResponse *reply) override;

    grpc::Status ListContainerStats(grpc::ServerContext *context, const runtime::ListContainerStatsRequest *request,
                                    runtime::ListContainerStatsResponse *reply) override;

    grpc::Status ContainerStatus(grpc::ServerContext *context, const runtime::ContainerStatusRequest *request,
                                 runtime::ContainerStatusResponse *reply) override;

    grpc::Status ExecSync(grpc::ServerContext *context, const runtime::ExecSyncRequest *request,
                          runtime::ExecSyncResponse *reply) override;

    grpc::Status RunPodSandbox(grpc::ServerContext *context, const runtime::RunPodSandboxRequest *request,
                               runtime::RunPodSandboxResponse *reply) override;

    grpc::Status StopPodSandbox(grpc::ServerContext *context, const runtime::StopPodSandboxRequest *request,
                                runtime::StopPodSandboxResponse *reply) override;

    grpc::Status RemovePodSandbox(grpc::ServerContext *context, const runtime::RemovePodSandboxRequest *request,
                                  runtime::RemovePodSandboxResponse *reply) override;

    grpc::Status PodSandboxStatus(grpc::ServerContext *context, const runtime::PodSandboxStatusRequest *request,
                                  runtime::PodSandboxStatusResponse *reply) override;

    grpc::Status ListPodSandbox(grpc::ServerContext *context, const runtime::ListPodSandboxRequest *request,
                                runtime::ListPodSandboxResponse *reply) override;

    grpc::Status UpdateContainerResources(grpc::ServerContext *context,
                                          const runtime::UpdateContainerResourcesRequest *request,
                                          runtime::UpdateContainerResourcesResponse *reply) override;

    grpc::Status Exec(grpc::ServerContext *context, const runtime::ExecRequest *request,
                      runtime::ExecResponse *response) override;

    grpc::Status Attach(grpc::ServerContext *context, const runtime::AttachRequest *request,
                        runtime::AttachResponse *response) override;

    grpc::Status UpdateRuntimeConfig(grpc::ServerContext *context, const runtime::UpdateRuntimeConfigRequest *request,
                                     runtime::UpdateRuntimeConfigResponse *reply) override;

    grpc::Status Status(grpc::ServerContext *context, const runtime::StatusRequest *request,
                        runtime::StatusResponse *reply) override;

private:
    CRIRuntimeServiceImpl rService;
};

#endif /* _RUNTIME_RUNTIME_SERVICES_IMPL_H_ */
