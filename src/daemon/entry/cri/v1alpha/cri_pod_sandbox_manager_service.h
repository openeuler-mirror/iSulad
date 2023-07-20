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
#ifndef DAEMON_ENTRY_CRI_POD_SANDBOX_MANAGER_H
#define DAEMON_ENTRY_CRI_POD_SANDBOX_MANAGER_H
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <mutex>

#include "api.pb.h"
#include "errors.h"
#include "callback.h"
#include "pthread.h"
#include "network_plugin.h"
#include "isula_libutils/host_config.h"
#include "isula_libutils/container_config.h"
#include "isula_libutils/container_inspect.h"
#include "checkpoint_handler.h"
#include "cgroup.h"
#include "cri_container_manager_service.h"

namespace CRI {
class PodSandboxManagerService {
public:
    PodSandboxManagerService(const std::string &podSandboxImage, service_executor_t *cb,
                             std::shared_ptr<Network::PluginManager> pluginManager)
        : m_podSandboxImage(podSandboxImage)
        , m_cb(cb)
        , m_pluginManager(pluginManager)
    {
    }
    PodSandboxManagerService(const PodSandboxManagerService &) = delete;
    auto operator=(const PodSandboxManagerService &) -> PodSandboxManagerService & = delete;
    virtual ~PodSandboxManagerService() = default;

    auto RunPodSandbox(const runtime::v1alpha2::PodSandboxConfig &config, const std::string &runtimeHandler,
                       Errors &error) -> std::string;

    void StopPodSandbox(const std::string &podSandboxID, Errors &error);

    void RemovePodSandbox(const std::string &podSandboxID, Errors &error);

    auto PodSandboxStatus(const std::string &podSandboxID, Errors &error)
    -> std::unique_ptr<runtime::v1alpha2::PodSandboxStatus>;

    void ListPodSandbox(const runtime::v1alpha2::PodSandboxFilter *filter,
                        std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods, Errors &error);

    auto PodSandboxStats(const std::string &podSandboxID,
                         const std::unique_ptr<ContainerManagerService> &containerManager,
                         Errors &error) -> std::unique_ptr<runtime::v1alpha2::PodSandboxStats>;

    void ListPodSandboxStats(const runtime::v1alpha2::PodSandboxStatsFilter *filter,
                             const std::unique_ptr<ContainerManagerService> &containerManager,
                             std::vector<std::unique_ptr<runtime::v1alpha2::PodSandboxStats>> *podsStats,
                             Errors &error);

    void PortForward(const runtime::v1alpha2::PortForwardRequest &req, runtime::v1alpha2::PortForwardResponse *resp,
                     Errors &error);

private:
    auto EnsureSandboxImageExists(const std::string &image, Errors &error) -> bool;
    auto CreateSandboxContainer(const runtime::v1alpha2::PodSandboxConfig &config, const std::string &image,
                                std::string &jsonCheckpoint, const std::string &runtimeHandler, Errors &error)
    -> std::string;
    auto GenerateSandboxCreateContainerRequest(const runtime::v1alpha2::PodSandboxConfig &config,
                                               const std::string &image, std::string &jsonCheckpoint,
                                               const std::string &runtimeHandler, Errors &error)
    -> container_create_request *;
    void SetHostConfigDefaultValue(host_config *hc);
    void MakeSandboxIsuladConfig(const runtime::v1alpha2::PodSandboxConfig &c, host_config *hc,
                                 container_config *custom_config, Errors &error);
    void ApplySandboxLinuxOptions(const runtime::v1alpha2::LinuxPodSandboxConfig &lc, host_config *hc,
                                  container_config *custom_config, Errors &error);
    void ApplySandboxResources(const runtime::v1alpha2::LinuxPodSandboxConfig *lc, host_config *hc, Errors &error);
    void ConstructPodSandboxCheckpoint(const runtime::v1alpha2::PodSandboxConfig &config,
                                       CRI::PodSandboxCheckpoint &checkpoint);
    auto ParseCheckpointProtocol(runtime::v1alpha2::Protocol protocol) -> std::string;
    auto PackCreateContainerRequest(const runtime::v1alpha2::PodSandboxConfig &config, const std::string &image,
                                    host_config *hostconfig, container_config *custom_config,
                                    const std::string &runtimeHandler, Errors &error) -> container_create_request *;
    void SetNetworkReady(const std::string &podSandboxID, bool ready, Errors &error);
    void StartSandboxContainer(const std::string &response_id, Errors &error);
    auto GetSandboxKey(const container_inspect *inspect_data) -> std::string;
    void GetSandboxNetworkInfo(const runtime::v1alpha2::PodSandboxConfig &config, const std::string &jsonCheckpoint,
                               const container_inspect *inspect_data, std::string &sandbox_key,
                               std::map<std::string, std::string> &networkOptions,
                               std::map<std::string, std::string> &stdAnnos, Errors &error);
    void SetupSandboxNetwork(const runtime::v1alpha2::PodSandboxConfig &config, const std::string &response_id,
                             const container_inspect *inspect_data,
                             const std::map<std::string, std::string> &networkOptions,
                             const std::map<std::string, std::string> &stdAnnos, std::string &network_settings_json,
                             Errors &error);
    void SetupSandboxFiles(const std::string &resolvPath, const runtime::v1alpha2::PodSandboxConfig &config,
                           Errors &error);
    void StopContainerHelper(const std::string &containerID, Errors &error);
    auto GetRealSandboxIDToStop(const std::string &podSandboxID, bool &hostNetwork, std::string &name, std::string &ns,
                                std::string &realSandboxID, std::map<std::string, std::string> &stdAnnos, Errors &error)
    -> int;
    auto StopAllContainersInSandbox(const std::string &realSandboxID, Errors &error) -> int;
    auto ClearCniNetwork(const std::string &realSandboxID, bool hostNetwork, const std::string &ns,
                         const std::string &name, std::vector<std::string> &errlist,
                         std::map<std::string, std::string> &stdAnnos, Errors &error) -> int;
    auto GetNetworkReady(const std::string &podSandboxID, Errors &error) -> bool;
    auto RemoveAllContainersInSandbox(const std::string &realSandboxID, std::vector<std::string> &errors) -> int;
    int DoRemovePodSandbox(const std::string &realSandboxID, std::vector<std::string> &errors);
    void ClearNetworkReady(const std::string &podSandboxID);
    void PodSandboxStatusToGRPC(const container_inspect *inspect, const std::string &podSandboxID,
                                std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> &podStatus, Errors &error);
    auto SharesHostNetwork(const container_inspect *inspect) -> runtime::v1alpha2::NamespaceMode;
    auto SharesHostPid(const container_inspect *inspect) -> runtime::v1alpha2::NamespaceMode;
    auto SharesHostIpc(const container_inspect *inspect) -> runtime::v1alpha2::NamespaceMode;
    void SetSandboxStatusNetwork(const container_inspect *inspect, const std::string &podSandboxID,
                                 std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> &podStatus, Errors &error);
    void GetIPs(const std::string &podSandboxID, const container_inspect *inspect, const std::string &networkInterface,
                std::vector<std::string> &ips, Errors &error);
    void ListPodSandboxFromGRPC(const runtime::v1alpha2::PodSandboxFilter *filter, container_list_request **request,
                                bool *filterOutReadySandboxes, Errors &error);
    void ListPodSandboxToGRPC(container_list_response *response,
                              std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods,
                              bool filterOutReadySandboxes, Errors &error);
    void UpdatePodSandboxNetworkSettings(const std::string &id, const std::string &json, Errors &error);
    auto GetNsenterPath(Errors &error) -> std::string;
    auto GetAvailableBytes(const uint64_t &memoryLimit, const uint64_t &workingSetBytes) -> uint64_t;
    void GetPodSandboxCgroupMetrics(const container_inspect *inspectData, cgroup_metrics_t &cgroupMetrics,
                                    Errors &error);
    void GetPodSandboxNetworkMetrics(const container_inspect *inspectData,
                                     std::map<std::string, std::string> &annotations,
                                     std::vector<Network::NetworkInterfaceStats> &netMetrics, Errors &error);
    void PackagePodSandboxStatsAttributes(const std::string &id,
                                          std::unique_ptr<runtime::v1alpha2::PodSandboxStats> &podStatsPtr,
                                          Errors &error);
    void PackagePodSandboxContainerStats(const std::string &id,
                                         const std::unique_ptr<ContainerManagerService> &containerManager,
                                         std::unique_ptr<runtime::v1alpha2::PodSandboxStats> &podStatsPtr,
                                         Errors &error);
    void PodSandboxStatsToGRPC(const std::string &id, const cgroup_metrics_t &cgroupMetrics,
                               const std::vector<Network::NetworkInterfaceStats> &netMetrics,
                               const std::unique_ptr<ContainerManagerService> &containerManager,
                               std::unique_ptr<runtime::v1alpha2::PodSandboxStats> &podStats,
                               Errors &error);
    void GetFilterPodSandbox(const runtime::v1alpha2::PodSandboxStatsFilter *filter,
                             std::vector<std::string> &podSandboxIDs, Errors &error);

private:
    std::string m_podSandboxImage;
    std::mutex m_networkReadyLock;
    std::map<std::string, bool> m_networkReady;
    service_executor_t *m_cb { nullptr };
    std::shared_ptr<Network::PluginManager> m_pluginManager { nullptr };
};
} // namespace CRI

#endif // DAEMON_ENTRY_CRI_POD_SANDBOX_MANAGER_H
