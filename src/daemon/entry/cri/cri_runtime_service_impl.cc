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
#include "cri_runtime_service_impl.h"
#include "cri_helpers.h"
#include "isula_libutils/log.h"
#include "cri_runtime_versioner_service_impl.h"

namespace CRI {
void CRIRuntimeServiceImpl::Version(const std::string &apiVersion, runtime::v1alpha2::VersionResponse *versionResponse,
                                    Errors &error)
{
    m_runtimeVersioner->Version(apiVersion, versionResponse, error);
}

auto CRIRuntimeServiceImpl::CreateContainer(const std::string &podSandboxID,
                                            const runtime::v1alpha2::ContainerConfig &containerConfig,
                                            const runtime::v1alpha2::PodSandboxConfig &podSandboxConfig,
                                            Errors &error) -> std::string
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

void CRIRuntimeServiceImpl::ListContainers(const runtime::v1alpha2::ContainerFilter *filter,
                                           std::vector<std::unique_ptr<runtime::v1alpha2::Container>> *containers, Errors &error)
{
    m_containerManager->ListContainers(filter, containers, error);
}

void CRIRuntimeServiceImpl::ListContainerStats(const runtime::v1alpha2::ContainerStatsFilter *filter,
                                               std::vector<std::unique_ptr<runtime::v1alpha2::ContainerStats>> *containerstats,
                                               Errors &error)
{
    m_containerManager->ListContainerStats(filter, containerstats, error);
}

auto CRIRuntimeServiceImpl::ContainerStatus(const std::string &containerID,
                                            Errors &error) -> std::unique_ptr<runtime::v1alpha2::ContainerStatus>
{
    return m_containerManager->ContainerStatus(containerID, error);
}

void CRIRuntimeServiceImpl::UpdateContainerResources(const std::string &containerID,
                                                     const runtime::v1alpha2::LinuxContainerResources &resources, Errors &error)
{
    m_containerManager->UpdateContainerResources(containerID, resources, error);
}

void CRIRuntimeServiceImpl::ExecSync(const std::string &containerID,
                                     const google::protobuf::RepeatedPtrField<std::string> &cmd,
                                     int64_t timeout, runtime::v1alpha2::ExecSyncResponse *reply, Errors &error)
{
    m_containerManager->ExecSync(containerID, cmd, timeout, reply, error);
}

void CRIRuntimeServiceImpl::Exec(const runtime::v1alpha2::ExecRequest &req, runtime::v1alpha2::ExecResponse *resp,
                                 Errors &error)
{
    m_containerManager->Exec(req, resp, error);
}

void CRIRuntimeServiceImpl::Attach(const runtime::v1alpha2::AttachRequest &req, runtime::v1alpha2::AttachResponse *resp,
                                   Errors &error)
{
    m_containerManager->Attach(req, resp, error);
}

auto CRIRuntimeServiceImpl::RunPodSandbox(const runtime::v1alpha2::PodSandboxConfig &config,
                                          const std::string &runtimeHandler,
                                          Errors &error) -> std::string
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

auto CRIRuntimeServiceImpl::PodSandboxStatus(const std::string &podSandboxID,
                                             Errors &error) -> std::unique_ptr<runtime::v1alpha2::PodSandboxStatus>
{
    return m_podSandboxManager->PodSandboxStatus(podSandboxID, error);
}

void CRIRuntimeServiceImpl::ListPodSandbox(const runtime::v1alpha2::PodSandboxFilter *filter,
                                           std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods, Errors &error)
{
    m_podSandboxManager->ListPodSandbox(filter, pods, error);
}

void CRIRuntimeServiceImpl::UpdateRuntimeConfig(const runtime::v1alpha2::RuntimeConfig &config, Errors &error)
{
    m_runtimeManager->UpdateRuntimeConfig(config, error);
}

auto CRIRuntimeServiceImpl::Status(Errors &error) -> std::unique_ptr<runtime::v1alpha2::RuntimeStatus>
{
    return m_runtimeManager->Status(error);
}

} // namespace CRI