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
 * Description: provide cri runtime service implementation function
 *********************************************************************************/
#include "v1_cri_runtime_service_impl.h"
#include "v1_cri_helpers.h"
#include "isula_libutils/log.h"
#include "v1_cri_runtime_versioner_service.h"

namespace CRIV1 {
CRIRuntimeServiceImpl::CRIRuntimeServiceImpl(const std::string &podSandboxImage, service_executor_t *cb,
                                             std::shared_ptr<Network::PluginManager> pluginManager, bool enablePodEvents)
    : m_runtimeVersioner(new RuntimeVersionerService(cb))
    , m_containerManager(new ContainerManagerService(cb))
    , m_podSandboxManager(new PodSandboxManagerService(podSandboxImage, cb, pluginManager, enablePodEvents))
    , m_runtimeManager(new RuntimeManagerService(cb, pluginManager))
    , m_enablePodEvents(enablePodEvents)
{
}

void CRIRuntimeServiceImpl::Version(const std::string &apiVersion, runtime::v1::VersionResponse *versionResponse,
                                    Errors &error)
{
    m_runtimeVersioner->Version(apiVersion, versionResponse, error);
}

auto CRIRuntimeServiceImpl::CreateContainer(const std::string &podSandboxID,
                                            const runtime::v1::ContainerConfig &containerConfig,
                                            const runtime::v1::PodSandboxConfig &podSandboxConfig, Errors &error)
-> std::string
{
    return m_containerManager->CreateContainer(podSandboxID, containerConfig, podSandboxConfig, error);
}

void CRIRuntimeServiceImpl::StartContainer(const std::string &containerID, Errors &error)
{
    m_containerManager->StartContainer(containerID, error);
}

void CRIRuntimeServiceImpl::StopContainer(const std::string &containerID, int64_t timeout, Errors &error)
{
    m_containerManager->StopContainer(containerID, timeout, error);
}

void CRIRuntimeServiceImpl::RemoveContainer(const std::string &containerID, Errors &error)
{
    m_containerManager->RemoveContainer(containerID, error);
}

void CRIRuntimeServiceImpl::ListContainers(const runtime::v1::ContainerFilter *filter,
                                           std::vector<std::unique_ptr<runtime::v1::Container>> &containers,
                                           Errors &error)
{
    m_containerManager->ListContainers(filter, containers, error);
}

void CRIRuntimeServiceImpl::ListContainerStats(
    const runtime::v1::ContainerStatsFilter *filter,
    std::vector<std::unique_ptr<runtime::v1::ContainerStats>> &containerstats, Errors &error)
{
    m_containerManager->ListContainerStats(filter, containerstats, error);
}

auto CRIRuntimeServiceImpl::ContainerStats(const std::string &containerID, Errors &error)
-> std::unique_ptr<runtime::v1::ContainerStats>
{
    return m_containerManager->ContainerStats(containerID, error);
}

auto CRIRuntimeServiceImpl::ContainerStatus(const std::string &containerID, Errors &error)
-> std::unique_ptr<runtime::v1::ContainerStatus>
{
    return m_containerManager->ContainerStatus(containerID, error);
}

void CRIRuntimeServiceImpl::UpdateContainerResources(const std::string &containerID,
                                                     const runtime::v1::LinuxContainerResources &resources,
                                                     Errors &error)
{
    m_containerManager->UpdateContainerResources(containerID, resources, error);
}

void CRIRuntimeServiceImpl::ExecSync(const std::string &containerID,
                                     const google::protobuf::RepeatedPtrField<std::string> &cmd, int64_t timeout,
                                     runtime::v1::ExecSyncResponse *reply, Errors &error)
{
    m_containerManager->ExecSync(containerID, cmd, timeout, reply, error);
}

void CRIRuntimeServiceImpl::Exec(const runtime::v1::ExecRequest &req, runtime::v1::ExecResponse *resp,
                                 Errors &error)
{
    m_containerManager->Exec(req, resp, error);
}

void CRIRuntimeServiceImpl::Attach(const runtime::v1::AttachRequest &req, runtime::v1::AttachResponse *resp,
                                   Errors &error)
{
    m_containerManager->Attach(req, resp, error);
}

auto CRIRuntimeServiceImpl::RunPodSandbox(const runtime::v1::PodSandboxConfig &config,
                                          const std::string &runtimeHandler, Errors &error) -> std::string
{
    return m_podSandboxManager->RunPodSandbox(config, runtimeHandler, error);
}

void CRIRuntimeServiceImpl::StopPodSandbox(const std::string &podSandboxID, Errors &error)
{
    m_podSandboxManager->StopPodSandbox(podSandboxID, error);
}

void CRIRuntimeServiceImpl::RemovePodSandbox(const std::string &podSandboxID, Errors &error)
{
    m_podSandboxManager->RemovePodSandbox(podSandboxID, error);
}

void CRIRuntimeServiceImpl::PodSandboxStatus(const std::string &podSandboxID, runtime::v1::PodSandboxStatusResponse *reply, Errors &error)
{
    m_podSandboxManager->PodSandboxStatus(podSandboxID, reply, error);
}

void CRIRuntimeServiceImpl::ListPodSandbox(const runtime::v1::PodSandboxFilter &filter,
                                           std::vector<std::unique_ptr<runtime::v1::PodSandbox>> &pods,
                                           Errors &error)
{
    m_podSandboxManager->ListPodSandbox(filter, pods, error);
}

auto CRIRuntimeServiceImpl::PodSandboxStats(const std::string &podSandboxID, Errors &error)
-> std::unique_ptr<runtime::v1::PodSandboxStats>
{
    return m_podSandboxManager->PodSandboxStats(podSandboxID, m_containerManager, error);
}

void
CRIRuntimeServiceImpl::ListPodSandboxStats(const runtime::v1::PodSandboxStatsFilter *filter,
                                           std::vector<std::unique_ptr<runtime::v1::PodSandboxStats>> &podsStats,
                                           Errors &error)
{
    m_podSandboxManager->ListPodSandboxStats(filter, m_containerManager, podsStats, error);
}

void CRIRuntimeServiceImpl::UpdateRuntimeConfig(const runtime::v1::RuntimeConfig &config, Errors &error)
{
    m_runtimeManager->UpdateRuntimeConfig(config, error);
}

auto CRIRuntimeServiceImpl::Status(Errors &error) -> std::unique_ptr<runtime::v1::RuntimeStatus>
{
    return m_runtimeManager->Status(error);
}

void CRIRuntimeServiceImpl::RuntimeConfig(runtime::v1::RuntimeConfigResponse *reply, Errors &error)
{
    m_runtimeManager->RuntimeConfig(reply, error);
}

} // namespace CRIV1
