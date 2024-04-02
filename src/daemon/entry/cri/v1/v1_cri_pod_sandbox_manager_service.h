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
 * Description: provide cri pod sandbox manager service implementation definition
 *********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_V1_POD_SANDBOX_MANAGER_H
#define DAEMON_ENTRY_CRI_V1_POD_SANDBOX_MANAGER_H
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <mutex>

#include "api_v1.pb.h"
#include "errors.h"
#include "callback.h"
#include "pthread.h"
#include "network_plugin.h"
#include "isula_libutils/host_config.h"
#include "isula_libutils/container_config.h"
#include "isula_libutils/container_inspect.h"
#include "checkpoint_handler.h"
#include "cgroup.h"
#include "sandbox.h"
#include "v1_cri_container_manager_service.h"
#include "cstruct_wrapper.h"

namespace CRIV1 {
class PodSandboxManagerService {
public:
    PodSandboxManagerService(const std::string &podSandboxImage, service_executor_t *cb,
                             std::shared_ptr<Network::PluginManager> pluginManager, bool enablePodEvents)
        : m_podSandboxImage(podSandboxImage)
        , m_cb(cb)
        , m_pluginManager(pluginManager)
        , m_enablePodEvents(enablePodEvents)
    {
    }
    PodSandboxManagerService(const PodSandboxManagerService &) = delete;
    auto operator=(const PodSandboxManagerService &) -> PodSandboxManagerService & = delete;
    virtual ~PodSandboxManagerService() = default;

    auto RunPodSandbox(const runtime::v1::PodSandboxConfig &config, const std::string &runtimeHandler,
                       Errors &error) -> std::string;

    void StopPodSandbox(const std::string &podSandboxID, Errors &error);

    void RemovePodSandbox(const std::string &podSandboxID, Errors &error);

    void PodSandboxStatus(const std::string &podSandboxID, runtime::v1::PodSandboxStatusResponse *reply, Errors &error);

    void ListPodSandbox(const runtime::v1::PodSandboxFilter &filter,
                        std::vector<std::unique_ptr<runtime::v1::PodSandbox>> &pods, Errors &error);

    auto PodSandboxStats(const std::string &podSandboxID,
                         const std::unique_ptr<ContainerManagerService> &containerManager,
                         Errors &error) -> std::unique_ptr<runtime::v1::PodSandboxStats>;

    void ListPodSandboxStats(const runtime::v1::PodSandboxStatsFilter *filter,
                             const std::unique_ptr<ContainerManagerService> &containerManager,
                             std::vector<std::unique_ptr<runtime::v1::PodSandboxStats>> &podsStats,
                             Errors &error);

    void PortForward(const runtime::v1::PortForwardRequest &req, runtime::v1::PortForwardResponse *resp,
                     Errors &error);

private:
    void PrepareSandboxData(const runtime::v1::PodSandboxConfig &config, const std::string &runtimeHandler,
                            std::string &sandboxName, sandbox::RuntimeInfo &runtimeInfo, std::string &networkMode,
                            Errors &error);
    auto EnsureSandboxImageExists(const std::string &image, const std::string &sandboxer, Errors &error) -> bool;
    void PrepareSandboxKey(std::string &sandboxKey, Errors &error);
    void ApplySandboxDefaultResources(runtime::v1::LinuxPodSandboxConfig *linuxConfig);
    auto ParseCheckpointProtocol(runtime::v1::Protocol protocol) -> std::string;
    void ConstructPodSandboxCheckpoint(const runtime::v1::PodSandboxConfig &config, CRI::PodSandboxCheckpoint &checkpoint);
    void PrepareSandboxCheckpoint(const runtime::v1::PodSandboxConfig &config, std::string &jsonCheckpoint, Errors &error);
    void UpdateSandboxConfig(runtime::v1::PodSandboxConfig &config, std::string &jsonCheckpoint, Errors &error);
    void SetupSandboxFiles(const std::string &resolvPath, const runtime::v1::PodSandboxConfig &config,
                           Errors &error);
    void SetupSandboxNetwork(const std::shared_ptr<sandbox::Sandbox> sandbox, std::string &network_settings_json,
                             Errors &error);
    void ClearCniNetwork(const std::shared_ptr<sandbox::Sandbox> sandbox, Errors &error);
    void StopContainerHelper(const std::string &containerID, Errors &error);
    auto GetContainerListResponse(const std::string &readSandboxID,
                                  std::vector<std::string> &errors) -> std::unique_ptr<CStructWrapper<container_list_response>>;
    auto StopAllContainersInSandbox(const std::string &readSandboxID, Errors &error) -> int;
    auto GetNetworkReady(const std::string &podSandboxID, Errors &error) -> bool;
    void RemoveAllContainersInSandbox(const std::string &readSandboxID, std::vector<std::string> &errors);
    void ClearNetworkReady(const std::string &podSandboxID);
    auto SharesHostNetwork(const container_inspect *inspect) -> runtime::v1::NamespaceMode;
    auto SharesHostPid(const container_inspect *inspect) -> runtime::v1::NamespaceMode;
    auto SharesHostIpc(const container_inspect *inspect) -> runtime::v1::NamespaceMode;
    void SetSandboxStatusNetwork(std::shared_ptr<sandbox::Sandbox> sandbox,
                                 std::unique_ptr<runtime::v1::PodSandboxStatus> &podStatus);
    void GetIPs(std::shared_ptr<sandbox::Sandbox> sandbox, std::vector<std::string> &ips);
    auto GenerateUpdateNetworkSettingsReqest(const std::string &id, const std::string &json, Errors &error)
    -> container_update_network_settings_request *;
    auto GetNsenterPath(Errors &error) -> std::string;
    auto GetAvailableBytes(const uint64_t &memoryLimit, const uint64_t &workingSetBytes) -> uint64_t;
    void GetPodSandboxCgroupMetrics(const std::string &cgroupParent, cgroup_metrics_t &cgroupMetrics,
                                    Errors &error);
    auto GetSandboxKey(const container_inspect *inspect_data) -> std::string;
    void GetPodSandboxNetworkMetrics(const std::string &netnsPath,
                                     std::map<std::string, std::string> &annotations,
                                     std::vector<Network::NetworkInterfaceStats> &netMetrics, Errors &error);
    void PackagePodSandboxStatsAttributes(const std::string &id,
                                          std::unique_ptr<runtime::v1::PodSandboxStats> &podStatsPtr,
                                          Errors &error);
    void PackagePodSandboxContainerStats(const std::string &id,
                                         const std::unique_ptr<ContainerManagerService> &containerManager,
                                         std::unique_ptr<runtime::v1::PodSandboxStats> &podStatsPtr,
                                         Errors &error);
    void PodSandboxStatsToGRPC(const std::string &id, const cgroup_metrics_t &cgroupMetrics,
                               const std::vector<Network::NetworkInterfaceStats> &netMetrics,
                               const std::unique_ptr<ContainerManagerService> &containerManager,
                               std::unique_ptr<runtime::v1::PodSandboxStats> &podStats,
                               sandbox::StatsInfo &statsInfo,
                               Errors &error);
    void GetFilterPodSandbox(const runtime::v1::PodSandboxStatsFilter *filter,
                             std::vector<std::string> &podSandboxIDs, Errors &error);
    void ApplySandboxLinuxOptions(const runtime::v1::LinuxPodSandboxConfig &lc, host_config *hc,
                                  container_config *custom_config, Errors &error);
    auto GetPodSandboxStatus(const std::string &podSandboxID, Errors &error) -> std::unique_ptr<runtime::v1::PodSandboxStatus>;
    void GetContainerStatuses(const std::string &podSandboxID, std::vector<std::unique_ptr<runtime::v1::ContainerStatus>> &containerStatuses,
                              std::vector<std::string> &errors);

private:
    std::string m_podSandboxImage;
    std::mutex m_networkReadyLock;
    std::map<std::string, bool> m_networkReady;
    service_executor_t *m_cb { nullptr };
    std::shared_ptr<Network::PluginManager> m_pluginManager { nullptr };
    bool m_enablePodEvents;
};
} // namespace CRI

#endif // DAEMON_ENTRY_CRI_V1_POD_SANDBOX_MANAGER_H
