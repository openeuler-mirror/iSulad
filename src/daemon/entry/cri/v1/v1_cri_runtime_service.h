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
 * Description: provide cri runtime service interface definition
 **********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_V1_CRI_RUNTIME_SERVICE_INTERFACE_H
#define DAEMON_ENTRY_CRI_V1_CRI_RUNTIME_SERVICE_INTERFACE_H
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "api_v1.pb.h"
#include "network_plugin.h"

namespace CRIV1 {
class CRIRuntimeService {
public:
    CRIRuntimeService() = default;
    virtual ~ CRIRuntimeService() = default;

    virtual void Version(const std::string &apiVersion, runtime::v1::VersionResponse *versionResponse,
                         Errors &error) = 0;

    virtual auto CreateContainer(const std::string &podSandboxID,
                                 const runtime::v1::ContainerConfig &containerConfig,
                                 const runtime::v1::PodSandboxConfig &podSandboxConfig,
                                 Errors &error) -> std::string = 0;

    virtual void StartContainer(const std::string &containerID, Errors &error) = 0;

    virtual void StopContainer(const std::string &containerID, int64_t timeout, Errors &error) = 0;

    virtual void RemoveContainer(const std::string &containerID, Errors &error) = 0;

    virtual void ListContainers(const runtime::v1::ContainerFilter *filter,
                                std::vector<std::unique_ptr<runtime::v1::Container>> &containers, Errors &error) = 0;

    virtual void ListContainerStats(const runtime::v1::ContainerStatsFilter *filter,
                                    std::vector<std::unique_ptr<runtime::v1::ContainerStats>> &containerstats,
                                    Errors &error) = 0;

    virtual auto ContainerStats(const std::string &containerID,
                                Errors &error) -> std::unique_ptr<runtime::v1::ContainerStats> = 0;

    virtual auto ContainerStatus(const std::string &containerID,
                                 Errors &error) -> std::unique_ptr<runtime::v1::ContainerStatus> = 0;

    virtual void ExecSync(const std::string &containerID, const google::protobuf::RepeatedPtrField<std::string> &cmd,
                          int64_t timeout, runtime::v1::ExecSyncResponse *reply, Errors &error) = 0;

    virtual void Exec(const runtime::v1::ExecRequest &req, runtime::v1::ExecResponse *resp, Errors &error) = 0;

    virtual void Attach(const runtime::v1::AttachRequest &req, runtime::v1::AttachResponse *resp,
                        Errors &error) = 0;

    virtual auto RunPodSandbox(const runtime::v1::PodSandboxConfig &config, const std::string &runtimeHandler,
                               Errors &error) -> std::string = 0;

    virtual void StopPodSandbox(const std::string &podSandboxID, Errors &error) = 0;

    virtual void RemovePodSandbox(const std::string &podSandboxID, Errors &error) = 0;

    virtual void PodSandboxStatus(const std::string &podSandboxID, runtime::v1::PodSandboxStatusResponse *reply,
                                  Errors &error) = 0;

    virtual void ListPodSandbox(const runtime::v1::PodSandboxFilter &filter,
                                std::vector<std::unique_ptr<runtime::v1::PodSandbox>> &pods, Errors &error) = 0;

    virtual auto PodSandboxStats(const std::string &podSandboxID,
                                 Errors &error) -> std::unique_ptr<runtime::v1::PodSandboxStats> = 0;

    virtual void ListPodSandboxStats(const runtime::v1::PodSandboxStatsFilter *filter,
                                     std::vector<std::unique_ptr<runtime::v1::PodSandboxStats>> &podsStats,
                                     Errors &error) = 0;

    virtual void UpdateContainerResources(const std::string &containerID,
                                          const runtime::v1::LinuxContainerResources &resources, Errors &error) = 0;

    virtual void UpdateRuntimeConfig(const runtime::v1::RuntimeConfig &config, Errors &error) = 0;

    virtual auto Status(Errors &error) -> std::unique_ptr<runtime::v1::RuntimeStatus> = 0;

    virtual void RuntimeConfig(runtime::v1::RuntimeConfigResponse *reply, Errors &error) = 0;
};
} // namespace CRIV1
#endif // DAEMON_ENTRY_CRI_V1_CRI_RUNTIME_SERVICE_INTERFACE_H
