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
 * Author: xuxuepeng
 * Create: 2023-01-28
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
#include "isula_libutils/sandbox_config.h"
#include "checkpoint_handler.h"

namespace CRI {
class PodSandboxManagerService {
public:
    PodSandboxManagerService(const std::string &podSandboxImage, service_executor_t *cb,
                             std::shared_ptr<Network::PluginManager> pluginManager)
        : m_cb(cb)
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

    void PortForward(const runtime::v1alpha2::PortForwardRequest &req, runtime::v1alpha2::PortForwardResponse *resp,
                     Errors &error);

private:
    void ApplySandboxResources(const runtime::v1alpha2::LinuxPodSandboxConfig *lc, host_config *hc, Errors &error);
    void AddPodSandboxCheckpoint(const runtime::v1alpha2::PodSandboxConfig &config,
                                 sandbox_config *sandboxconf, Errors &error);
    void ApplySandboxLinuxOptions(const runtime::v1alpha2::PodSandboxConfig &config,
                                  host_config *hostconf, sandbox_config *sandboxconf, Errors &error);
    void MakeIsuladSandboxConfig(const runtime::v1alpha2::PodSandboxConfig &config,
                                 const std::string &runtimeHandler,
                                 const std::string &sandboxId, host_config **hostconfig,
                                 sandbox_config **custom_config, Errors &error);
    auto NewSandboxNetNS(std::string &sandbox_netns) -> int;
    auto CreateNetworkNamespace(std::string &netns) -> int;
    void SetupPodSandboxCNINetwork(const runtime::v1alpha2::PodSandboxConfig &config,
                                   const std::string &sandbox_id, sandbox_config *sandboxconfig,
                                   std::string &netns, std::map<std::string, std::string> &stdAnnos,
                                   Errors &error);
    void SetupPodSandboxNetwork(const runtime::v1alpha2::PodSandboxConfig &config,
                                const std::string &sandbox_id, host_config *hostconfig,
                                sandbox_config *custom_config, std::map<std::string, std::string> &stdAnnos,
                                Errors &error);
    void ClearPodSandboxNetwork(const host_config *hostconf, const sandbox_config *sandboxconf,
                                const std::string &sandbox_id, std::vector<std::string> &errlist);
    sandbox_create_request *GenerateSandboxCreateRequest(const runtime::v1alpha2::PodSandboxConfig &config,
                                                         const std::string &runtimeHandler,
                                                         const std::string &sandboxName, const std::string &sandboxId,
                                                         const host_config *hostconfig, const sandbox_config *custom_config,
                                                         Errors &error);
    sandbox_stop_request *GenerateSandboxStopRequest(const std::string &podSandboxID, Errors &error);
    sandbox_inspect_request *GenerateSandboxInspectRequest(const std::string &podSandboxID, Errors &error);
    sandbox_status_request *GenerateSandboxStatusRequest(const std::string &podSandboxID, bool verbose, Errors &error);
    sandbox_inspect_response *InspectSandbox(const std::string &realPodSandboxID, Errors &error);
    void GetIPs(const std::string &podSandboxID, const sandbox_inspect_response *inspect_response, std::vector<std::string> &ips, Errors &error);
    void SetSandboxStatusNetwork(const sandbox_inspect_response *inspect_response, const std::string &podSandboxID,
                    std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> &podStatus, Errors &error);
    void SetSandboxMetadata(runtime::v1alpha2::PodSandboxMetadata* podMetadata, sandbox_config *config);
    auto SharesHostPid(const sandbox_inspect_response *inspect) -> runtime::v1alpha2::NamespaceMode;
    auto SharesHostIpc(const sandbox_inspect_response *inspect) -> runtime::v1alpha2::NamespaceMode;
    auto SharesHostNetwork(const sandbox_inspect_response *inspect) -> runtime::v1alpha2::NamespaceMode;
    auto GenerateSandboxIdentity(const runtime::v1alpha2::PodSandboxConfig &config, std::string &name,
                                 std::string &sandboxId, Errors &error) -> int;
    void CreateSandbox(const runtime::v1alpha2::PodSandboxConfig &config,
                       const std::string &runtimeHandler, const std::string& sandboxName,
                       const std::string &sandboxId, Errors &error);
    void StartSandbox(const std::string &sandbox_id, Errors &error);
    int StopAllContainersInSandbox(const std::string &realSandboxID, Errors &error);
    auto RemoveAllContainersInSandbox(const std::string &realSandboxID,
                                      std::vector<std::string> &errors) -> int;
    int DoRemovePodSandbox(const std::string &realSandboxID, std::vector<std::string> &errors);
    void SetHostConfigDefaultValue(host_config *hc);
    void ListPodSandboxToGRPC(sandbox_list_response *response,
                              std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods,
                              Errors &error);
    void ConstructPodSandboxCheckpoint(const runtime::v1alpha2::PodSandboxConfig &config,
                                       CRI::PodSandboxCheckpoint &checkpoint);
    auto ParseCheckpointProtocol(runtime::v1alpha2::Protocol protocol) -> std::string;
    void SetNetworkReady(const std::string &podSandboxID, bool ready, Errors &error);
    auto GetNetworkReady(const std::string &podSandboxID, Errors &error) -> bool;
    void ClearNetworkReady(const std::string &podSandboxID);

private:
    std::mutex m_networkReadyLock;
    std::map<std::string, bool> m_networkReady;
    service_executor_t *m_cb { nullptr };
    std::shared_ptr<Network::PluginManager> m_pluginManager { nullptr };
};
} // namespace CRI

#endif // DAEMON_ENTRY_CRI_POD_SANDBOX_MANAGER_H
