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

#ifndef _RUNTIME_RUNTIME_SERVICES_IMPL_H_
#define _RUNTIME_RUNTIME_SERVICES_IMPL_H_

#include "api.grpc.pb.h"
#include "callback.h"
#include "cri_runtime_service.h"
#include "network_plugin.h"
#include "isula_libutils/isulad_daemon_configs.h"
#include "errors.h"

// Implement of runtime RuntimeService
class RuntimeRuntimeServiceImpl : public runtime::v1alpha2::RuntimeService::Service {
public:
    void Init(Network::NetworkPluginConf mConf, isulad_daemon_configs *config, Errors &err);
    void Wait();
    void Shutdown();
    grpc::Status Version(grpc::ServerContext *context,
                         const runtime::v1alpha2::VersionRequest *request,
                         runtime::v1alpha2::VersionResponse *reply) override;

    grpc::Status CreateContainer(grpc::ServerContext *context,
                                 const runtime::v1alpha2::CreateContainerRequest *request,
                                 runtime::v1alpha2::CreateContainerResponse *reply) override;

    grpc::Status StartContainer(grpc::ServerContext *context,
                                const runtime::v1alpha2::StartContainerRequest *request,
                                runtime::v1alpha2::StartContainerResponse *reply) override;

    grpc::Status StopContainer(grpc::ServerContext *context,
                               const runtime::v1alpha2::StopContainerRequest *request,
                               runtime::v1alpha2::StopContainerResponse *reply) override;

    grpc::Status RemoveContainer(grpc::ServerContext *context,
                                 const runtime::v1alpha2::RemoveContainerRequest *request,
                                 runtime::v1alpha2::RemoveContainerResponse *reply) override;

    grpc::Status ListContainers(grpc::ServerContext *context,
                                const runtime::v1alpha2::ListContainersRequest *request,
                                runtime::v1alpha2::ListContainersResponse *reply) override;

    grpc::Status ListContainerStats(grpc::ServerContext *context,
                                    const runtime::v1alpha2::ListContainerStatsRequest *request,
                                    runtime::v1alpha2::ListContainerStatsResponse *reply) override;

    grpc::Status ContainerStatus(grpc::ServerContext *context,
                                 const runtime::v1alpha2::ContainerStatusRequest *request,
                                 runtime::v1alpha2::ContainerStatusResponse *reply) override;

    grpc::Status ExecSync(grpc::ServerContext *context,
                          const runtime::v1alpha2::ExecSyncRequest *request,
                          runtime::v1alpha2::ExecSyncResponse *reply) override;

    grpc::Status RunPodSandbox(grpc::ServerContext *context,
                               const runtime::v1alpha2::RunPodSandboxRequest *request,
                               runtime::v1alpha2::RunPodSandboxResponse *reply) override;

    grpc::Status StopPodSandbox(grpc::ServerContext *context,
                                const runtime::v1alpha2::StopPodSandboxRequest *request,
                                runtime::v1alpha2::StopPodSandboxResponse *reply) override;

    grpc::Status RemovePodSandbox(grpc::ServerContext *context,
                                  const runtime::v1alpha2::RemovePodSandboxRequest *request,
                                  runtime::v1alpha2::RemovePodSandboxResponse *reply) override;

    grpc::Status PodSandboxStatus(grpc::ServerContext *context,
                                  const runtime::v1alpha2::PodSandboxStatusRequest *request,
                                  runtime::v1alpha2::PodSandboxStatusResponse *reply) override;

    grpc::Status ListPodSandbox(grpc::ServerContext *context,
                                const runtime::v1alpha2::ListPodSandboxRequest *request,
                                runtime::v1alpha2::ListPodSandboxResponse *reply) override;

    grpc::Status UpdateContainerResources(grpc::ServerContext *context,
                                          const runtime::v1alpha2::UpdateContainerResourcesRequest *request,
                                          runtime::v1alpha2::UpdateContainerResourcesResponse *reply) override;

    grpc::Status Exec(grpc::ServerContext *context, const runtime::v1alpha2::ExecRequest *request,
                      runtime::v1alpha2::ExecResponse *response) override;

    grpc::Status Attach(grpc::ServerContext *context, const runtime::v1alpha2::AttachRequest *request,
                        runtime::v1alpha2::AttachResponse *response) override;

    grpc::Status UpdateRuntimeConfig(grpc::ServerContext *context,
                                     const runtime::v1alpha2::UpdateRuntimeConfigRequest *request,
                                     runtime::v1alpha2::UpdateRuntimeConfigResponse *reply) override;

    grpc::Status Status(grpc::ServerContext *context, const runtime::v1alpha2::StatusRequest *request,
                        runtime::v1alpha2::StatusResponse *reply) override;

private:
    CRIRuntimeServiceImpl rService;
};

#endif /* _RUNTIME_RUNTIME_SERVICES_IMPL_H_ */

