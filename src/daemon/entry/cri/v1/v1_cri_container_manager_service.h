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
 * Description: provide cri container manager service function implementation
 *********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_V1_CONTAINER_MANAGER_H
#define DAEMON_ENTRY_CRI_V1_CONTAINER_MANAGER_H
#include <memory>
#include <string>
#include <vector>

#include "api_v1.pb.h"
#include "errors.h"
#include "callback.h"
#include <isula_libutils/container_config.h>
#include <isula_libutils/host_config.h>
#include <isula_libutils/container_create_request.h>
#include <isula_libutils/container_list_response.h>
#include <isula_libutils/container_inspect.h>
#include <isula_libutils/container_exec_request.h>
#include <isula_libutils/container_inspect.h>
#include <isula_libutils/imagetool_fs_info.h>
#include <isula_libutils/container_sandbox_info.h>

#include "sandbox.h"

namespace CRIV1 {
class ContainerManagerService {
public:
    explicit ContainerManagerService(service_executor_t *cb)
        : m_cb(cb) {};
    virtual ~ContainerManagerService() = default;

    auto CreateContainer(const std::string &podSandboxID, const runtime::v1::ContainerConfig &containerConfig,
                         const runtime::v1::PodSandboxConfig &podSandboxConfig, Errors &error) -> std::string;

    void StartContainer(const std::string &containerID, Errors &error);

    void StopContainer(const std::string &containerID, int64_t timeout, Errors &error);

    void RemoveContainer(const std::string &containerID, Errors &error);

    void ListContainers(const runtime::v1::ContainerFilter *filter,
                        std::vector<std::unique_ptr<runtime::v1::Container>> &containers, Errors &error);

    void ListContainerStats(const runtime::v1::ContainerStatsFilter *filter,
                            std::vector<std::unique_ptr<runtime::v1::ContainerStats>> &containerstats,
                            Errors &error);

    auto ContainerStats(const std::string &containerID, Errors &error)
    -> std::unique_ptr<runtime::v1::ContainerStats>;

    auto ContainerStatus(const std::string &containerID, Errors &error)
    -> std::unique_ptr<runtime::v1::ContainerStatus>;

    void UpdateContainerResources(const std::string &containerID,
                                  const runtime::v1::LinuxContainerResources &resources, Errors &error);

    void ExecSync(const std::string &containerID, const google::protobuf::RepeatedPtrField<std::string> &cmd,
                  int64_t timeout, runtime::v1::ExecSyncResponse *reply, Errors &error);

    void Exec(const runtime::v1::ExecRequest &req, runtime::v1::ExecResponse *resp, Errors &error);

    void Attach(const runtime::v1::AttachRequest &req, runtime::v1::AttachResponse *resp, Errors &error);

private:
    auto GetContainerOrSandboxRuntime(const std::string &realID, Errors &error) -> std::string;
    auto GenerateCreateContainerRequest(sandbox::Sandbox &sandbox,
                                        const runtime::v1::ContainerConfig &containerConfig,
                                        const runtime::v1::PodSandboxConfig &podSandboxConfig,
                                        Errors &error)
    -> container_create_request *;
    auto GenerateCreateContainerHostConfig(sandbox::Sandbox &sandbox,
                                           const runtime::v1::ContainerConfig &containerConfig,
                                           Errors &error)
    -> host_config *;
    auto GenerateSandboxInfo(sandbox::Sandbox &sandbox, Errors &error) -> container_sandbox_info *;
    auto GenerateCreateContainerCustomConfig(const std::string &containerName, const std::string &realPodSandboxID,
                                             const runtime::v1::ContainerConfig &containerConfig,
                                             const runtime::v1::PodSandboxConfig &podSandboxConfig, Errors &error)
    -> container_config *;
    auto PackCreateContainerHostConfigDevices(const runtime::v1::ContainerConfig &containerConfig,
                                              host_config *hostconfig, Errors &error) -> int;
    auto PackCreateContainerHostConfigSecurityContext(const runtime::v1::ContainerConfig &containerConfig,
                                                      host_config *hostconfig, Errors &error) -> int;
    void DoUsePodLevelSELinuxConfig(const runtime::v1::ContainerConfig &containerConfig,
                                    host_config *hostconfig, sandbox::Sandbox &sandbox, Errors &error);
    void MakeContainerConfig(const runtime::v1::ContainerConfig &config, container_config *cConfig,
                             Errors &error);
    void ListContainersFromGRPC(const runtime::v1::ContainerFilter *filter, container_list_request **request,
                                Errors &error);
    void ListContainersToGRPC(container_list_response *response,
                              std::vector<std::unique_ptr<runtime::v1::Container>> &pods, Errors &error);
    auto PackContainerStatsFilter(const runtime::v1::ContainerStatsFilter *filter,
                                  container_stats_request *request, Errors &error) -> int;
    void ContainerStatsToGRPC(container_stats_response *response,
                              std::vector<std::unique_ptr<runtime::v1::ContainerStats>> &containerstats,
                              Errors &error);
    void PackContainerStatsAttributes(const char *id, std::unique_ptr<runtime::v1::ContainerStats> &container,
                                      Errors &error);
    void PackContainerStatsFilesystemUsage(const char *id, const char *image_type, int64_t timestamp,
                                           std::unique_ptr<runtime::v1::ContainerStats> &container);
    void SetFsUsage(const imagetool_fs_info *fs_usage, int64_t timestamp,
                    std::unique_ptr<runtime::v1::ContainerStats> &container);
    void ExecSyncFromGRPC(const std::string &containerID, const google::protobuf::RepeatedPtrField<std::string> &cmd,
                          int64_t timeout, container_exec_request **request, Errors &error);
    auto ValidateExecRequest(const runtime::v1::ExecRequest &req, Errors &error) -> int;
    auto BuildURL(const std::string &method, const std::string &token) -> std::string;
    auto InspectContainerState(const std::string &containerID, Errors &err) -> container_inspect_state *;
    auto ValidateAttachRequest(const runtime::v1::AttachRequest &req, Errors &error) -> int;
    auto IsSELinuxLabelEmpty(const ::runtime::v1::SELinuxOption &selinuxOption) -> bool;

private:
    service_executor_t *m_cb { nullptr };
};
} // namespace CRIV1

#endif // DAEMON_ENTRY_CRI_V1_CONTAINER_MANAGER_H
