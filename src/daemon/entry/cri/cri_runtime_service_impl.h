/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-12-15
 * Description: provide cri runtime service implementation definition
 **********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_CRI_RUNTIME_SERVICE_IMPL_H
#define DAEMON_ENTRY_CRI_CRI_RUNTIME_SERVICE_IMPL_H

#include "cri_runtime_service.h"
#include "cri_runtime_versioner_service.h"
#include "cri_container_manager_service.h"
#include "cri_pod_sandbox_manager_service.h"
#include "cri_runtime_manager_service.h"
#include "callback.h"

namespace CRI {
class CRIRuntimeServiceImpl : public CRIRuntimeService {
public:
    CRIRuntimeServiceImpl(RuntimeVersionerService* runtimeVersioner,
                          ContainerManagerService* containerManager,
                          PodSandboxManagerService* podSandboxManager,
                          RuntimeManagerService* runtimeManager) :
        m_runtimeVersioner(runtimeVersioner),
        m_containerManager(containerManager),
        m_podSandboxManager(podSandboxManager),
        m_runtimeManager(runtimeManager) {}
    CRIRuntimeServiceImpl(const CRIRuntimeServiceImpl &) = delete;
    auto operator=(const CRIRuntimeServiceImpl &) -> CRIRuntimeServiceImpl & = delete;
    virtual ~CRIRuntimeServiceImpl() = default;

    void Version(const std::string &apiVersion, runtime::v1alpha2::VersionResponse *versionResponse,
                 Errors &error) override;

    auto CreateContainer(const std::string &podSandboxID,
                         const runtime::v1alpha2::ContainerConfig &containerConfig,
                         const runtime::v1alpha2::PodSandboxConfig &podSandboxConfig,
                         Errors &error) -> std::string override;

    void StartContainer(const std::string &containerID, Errors &error) override;

    void StopContainer(const std::string &containerID, int64_t timeout, Errors &error) override;

    void RemoveContainer(const std::string &containerID, Errors &error) override;

    void ListContainers(const runtime::v1alpha2::ContainerFilter *filter,
                        std::vector<std::unique_ptr<runtime::v1alpha2::Container>> *containers, Errors &error) override;

    void ListContainerStats(const runtime::v1alpha2::ContainerStatsFilter *filter,
                            std::vector<std::unique_ptr<runtime::v1alpha2::ContainerStats>> *containerstats,
                            Errors &error) override;

    auto ContainerStatus(const std::string &containerID,
                         Errors &error) -> std::unique_ptr<runtime::v1alpha2::ContainerStatus> override;

    void ExecSync(const std::string &containerID, const google::protobuf::RepeatedPtrField<std::string> &cmd,
                  int64_t timeout, runtime::v1alpha2::ExecSyncResponse *reply, Errors &error) override;

    void Exec(const runtime::v1alpha2::ExecRequest &req, runtime::v1alpha2::ExecResponse *resp, Errors &error) override;

    void Attach(const runtime::v1alpha2::AttachRequest &req, runtime::v1alpha2::AttachResponse *resp,
                Errors &error) override;

    auto RunPodSandbox(const runtime::v1alpha2::PodSandboxConfig &config, const std::string &runtimeHandler,
                       Errors &error) -> std::string override;

    void StopPodSandbox(const std::string &podSandboxID, Errors &error) override;

    void RemovePodSandbox(const std::string &podSandboxID, Errors &error) override;

    auto PodSandboxStatus(const std::string &podSandboxID,
                          Errors &error) -> std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> override;

    void ListPodSandbox(const runtime::v1alpha2::PodSandboxFilter *filter,
                        std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods, Errors &error) override;

    void UpdateContainerResources(const std::string &containerID,
                                  const runtime::v1alpha2::LinuxContainerResources &resources, Errors &error) override;

    void UpdateRuntimeConfig(const runtime::v1alpha2::RuntimeConfig &config, Errors &error) override;

    auto Status(Errors &error) -> std::unique_ptr<runtime::v1alpha2::RuntimeStatus> override;

protected:
    std::unique_ptr<RuntimeVersionerService> m_runtimeVersioner;
    std::unique_ptr<ContainerManagerService> m_containerManager;
    std::unique_ptr<PodSandboxManagerService> m_podSandboxManager;
    std::unique_ptr<RuntimeManagerService> m_runtimeManager;

private:
    std::string m_podSandboxImage;
    std::shared_ptr<Network::PluginManager> m_pluginManager { nullptr };
};
} // namespace CRI
#endif // DAEMON_ENTRY_CRI_CRI_RUNTIME_SERVICE_IMPL_H
