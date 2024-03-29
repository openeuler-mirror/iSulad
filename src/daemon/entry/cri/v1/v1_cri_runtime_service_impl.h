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
#ifndef DAEMON_ENTRY_CRI_V1_CRI_RUNTIME_SERVICE_IMPL_H
#define DAEMON_ENTRY_CRI_V1_CRI_RUNTIME_SERVICE_IMPL_H

#include "v1_cri_runtime_service.h"
#include "v1_cri_runtime_versioner_service.h"
#include "v1_cri_container_manager_service.h"
#include "v1_cri_pod_sandbox_manager_service.h"
#include "v1_cri_runtime_manager_service.h"
#include "callback.h"

namespace CRIV1 {
class CRIRuntimeServiceImpl : public CRIRuntimeService {
public:
    CRIRuntimeServiceImpl(const std::string &podSandboxImage, service_executor_t *cb,
                          std::shared_ptr<Network::PluginManager> pluginManager,
                          bool enablePodEvents);
    CRIRuntimeServiceImpl(const CRIRuntimeServiceImpl &) = delete;
    auto operator=(const CRIRuntimeServiceImpl &) -> CRIRuntimeServiceImpl & = delete;
    virtual ~CRIRuntimeServiceImpl() = default;

    void Version(const std::string &apiVersion, runtime::v1::VersionResponse *versionResponse,
                 Errors &error) override;

    auto CreateContainer(const std::string &podSandboxID, const runtime::v1::ContainerConfig &containerConfig,
                         const runtime::v1::PodSandboxConfig &podSandboxConfig, Errors &error)
    -> std::string override;

    void StartContainer(const std::string &containerID, Errors &error) override;

    void StopContainer(const std::string &containerID, int64_t timeout, Errors &error) override;

    void RemoveContainer(const std::string &containerID, Errors &error) override;

    void ListContainers(const runtime::v1::ContainerFilter *filter,
                        std::vector<std::unique_ptr<runtime::v1::Container>> &containers, Errors &error) override;

    void ListContainerStats(const runtime::v1::ContainerStatsFilter *filter,
                            std::vector<std::unique_ptr<runtime::v1::ContainerStats>> &containerstats,
                            Errors &error) override;

    auto ContainerStats(const std::string &containerID, Errors &error)
    -> std::unique_ptr<runtime::v1::ContainerStats> override;

    auto ContainerStatus(const std::string &containerID, Errors &error)
    -> std::unique_ptr<runtime::v1::ContainerStatus> override;

    void ExecSync(const std::string &containerID, const google::protobuf::RepeatedPtrField<std::string> &cmd,
                  int64_t timeout, runtime::v1::ExecSyncResponse *reply, Errors &error) override;

    void Exec(const runtime::v1::ExecRequest &req, runtime::v1::ExecResponse *resp, Errors &error) override;

    void Attach(const runtime::v1::AttachRequest &req, runtime::v1::AttachResponse *resp,
                Errors &error) override;

    auto RunPodSandbox(const runtime::v1::PodSandboxConfig &config, const std::string &runtimeHandler,
                       Errors &error) -> std::string override;

    void StopPodSandbox(const std::string &podSandboxID, Errors &error) override;

    void RemovePodSandbox(const std::string &podSandboxID, Errors &error) override;

    void PodSandboxStatus(const std::string &podSandboxID, runtime::v1::PodSandboxStatusResponse *reply, Errors &error) override;

    void ListPodSandbox(const runtime::v1::PodSandboxFilter &filter,
                        std::vector<std::unique_ptr<runtime::v1::PodSandbox>> &pods, Errors &error) override;

    auto PodSandboxStats(const std::string &podSandboxID,
                         Errors &error) -> std::unique_ptr<runtime::v1::PodSandboxStats> override;

    void ListPodSandboxStats(const runtime::v1::PodSandboxStatsFilter *filter,
                             std::vector<std::unique_ptr<runtime::v1::PodSandboxStats>> &podsStats,
                             Errors &error) override;

    void UpdateContainerResources(const std::string &containerID,
                                  const runtime::v1::LinuxContainerResources &resources, Errors &error) override;

    void UpdateRuntimeConfig(const runtime::v1::RuntimeConfig &config, Errors &error) override;

    auto Status(Errors &error) -> std::unique_ptr<runtime::v1::RuntimeStatus> override;

    void RuntimeConfig(runtime::v1::RuntimeConfigResponse *reply, Errors &error) override;

protected:
    std::unique_ptr<RuntimeVersionerService> m_runtimeVersioner;
    std::unique_ptr<ContainerManagerService> m_containerManager;
    std::unique_ptr<PodSandboxManagerService> m_podSandboxManager;
    std::unique_ptr<RuntimeManagerService> m_runtimeManager;

private:
    std::string m_podSandboxImage;
    std::shared_ptr<Network::PluginManager> m_pluginManager { nullptr };
    bool m_enablePodEvents;
};
} // namespace CRIV1
#endif // DAEMON_ENTRY_CRI_V1_CRI_RUNTIME_SERVICE_IMPL_H
