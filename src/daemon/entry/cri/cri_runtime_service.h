/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide cri runtime service function definition
 **********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_CRI_RUNTIME_SERVICE_H
#define DAEMON_ENTRY_CRI_CRI_RUNTIME_SERVICE_H

#include <map>
#include <memory>
#include <pthread.h>
#include <string>
#include <vector>

#include "callback.h"
#include "checkpoint_handler.h"
#include "cri_image_service.h"
#include "cri_services.h"
#include "errors.h"
#include "isula_libutils/container_inspect.h"
#include "isula_libutils/cri_pod_network.h"
#include "isula_libutils/host_config.h"
#include "network_plugin.h"

namespace CRIRuntimeService {
class Constants {
public:
    static std::string namespaceModeHost;

    // sandboxname default values
    static std::string nameDelimiter;
    static char nameDelimiterChar;
    static std::string kubePrefix;
    static std::string sandboxContainerName;
    static std::string kubeAPIVersion;
    static std::string iSulaRuntimeName;
    static constexpr int64_t DefaultMemorySwap { 0 };
    static constexpr int64_t DefaultSandboxCPUshares { 2 };
    static constexpr int64_t PodInfraOOMAdj { -998 };

    // container mounts files
    static std::string RESOLV_CONF_PATH;
    static constexpr int MAX_DNS_SEARCHES { 6 };
};
} // namespace CRIRuntimeService

class CRIRuntimeServiceImpl : public cri::RuntimeManager,
    public cri::RuntimeVersioner,
    public cri::PodSandboxManager,
    public cri::ContainerManager {
public:
    CRIRuntimeServiceImpl();
    CRIRuntimeServiceImpl(const CRIRuntimeServiceImpl &) = delete;
    auto operator=(const CRIRuntimeServiceImpl &) -> CRIRuntimeServiceImpl & = delete;

    virtual ~CRIRuntimeServiceImpl() = default;

    void Init(Network::NetworkPluginConf mConf, const std::string &podSandboxImage, Errors &err);

    auto GetRealContainerOrSandboxID(const std::string &id, bool isSandbox, Errors &error) -> std::string;

    auto GetContainerOrSandboxRuntime(const std::string &realID, Errors &error) -> std::string;

    auto InspectContainer(const std::string &containerID, Errors &err) -> container_inspect *;

    auto GetNetNS(const std::string &podSandboxID, Errors &err) -> std::string;

    void Version(const std::string &apiVersion, runtime::v1alpha2::VersionResponse *versionResponse,
                 Errors &error) override;

    void UpdateRuntimeConfig(const runtime::v1alpha2::RuntimeConfig &config, Errors &error) override;

    auto Status(Errors &error) -> std::unique_ptr<runtime::v1alpha2::RuntimeStatus> override;

    auto RunPodSandbox(const runtime::v1alpha2::PodSandboxConfig &config, const std::string &runtimeHandler,
                       Errors &error) -> std::string override;

    void StopPodSandbox(const std::string &podSandboxID, Errors &error) override;

    void RemovePodSandbox(const std::string &podSandboxID, Errors &error) override;

    auto PodSandboxStatus(const std::string &podSandboxID,
                          Errors &error) -> std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> override;

    void ListPodSandbox(const runtime::v1alpha2::PodSandboxFilter *filter,
                        std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods, Errors &error) override;

    void PortForward(const runtime::v1alpha2::PortForwardRequest &req, runtime::v1alpha2::PortForwardResponse *resp,
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

    void UpdateContainerResources(const std::string &containerID,
                                  const runtime::v1alpha2::LinuxContainerResources &resources, Errors &error) override;

    void ExecSync(const std::string &containerID, const google::protobuf::RepeatedPtrField<std::string> &cmd,
                  int64_t timeout, runtime::v1alpha2::ExecSyncResponse *reply, Errors &error) override;

    void Exec(const runtime::v1alpha2::ExecRequest &req, runtime::v1alpha2::ExecResponse *resp, Errors &error) override;

    void Attach(const runtime::v1alpha2::AttachRequest &req, runtime::v1alpha2::AttachResponse *resp,
                Errors &error) override;

private:
    void VersionResponseToGRPC(container_version_response *response, runtime::v1alpha2::VersionResponse *gResponse);

    static auto IsDefaultNetworkPlane(cri_pod_network_element *network) -> bool;
    void SetSandboxStatusNetwork(container_inspect *inspect, const std::string &podSandboxID,
                                 std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> &podStatus, Errors &error);

    void PodSandboxStatusToGRPC(container_inspect *inspect, const std::string &podSandboxID,
                                std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> &podStatus, Errors &error);

    static void ListPodSandboxToGRPC(container_list_response *response,
                                     std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods,
                                     bool filterOutReadySandboxes, Errors &error);

    void ListContainersToGRPC(container_list_response *response,
                              std::vector<std::unique_ptr<runtime::v1alpha2::Container>> *pods, Errors &error);

    void PackContainerStatsAttributes(const char *id, std::unique_ptr<runtime::v1alpha2::ContainerStats> &container,
                                      Errors &error);

    void PackContainerStatsFilesystemUsage(const char *id, const char *image_type,
                                           std::unique_ptr<runtime::v1alpha2::ContainerStats> &container);

    void ContainerStatsToGRPC(container_stats_response *response,
                              std::vector<std::unique_ptr<runtime::v1alpha2::ContainerStats>> *containerstats, Errors &error);

    void ContainerStatusToGRPC(container_inspect *inspect,
                               std::unique_ptr<runtime::v1alpha2::ContainerStatus> &contStatus, Errors &error);

    void ExecSyncFromGRPC(const std::string &containerID, const google::protobuf::RepeatedPtrField<std::string> &cmd,
                          int64_t timeout, container_exec_request **request, Errors &error);

    void ListContainersFromGRPC(const runtime::v1alpha2::ContainerFilter *filter, container_list_request **request,
                                Errors &error);

    static void ListPodSandboxFromGRPC(const runtime::v1alpha2::PodSandboxFilter *filter, container_list_request **request,
                                       bool *filterOutReadySandboxes, Errors &error);

    static void ApplySandboxResources(const runtime::v1alpha2::LinuxPodSandboxConfig *lc, host_config *hc, Errors &error);

    static void ApplySandboxLinuxOptions(const runtime::v1alpha2::LinuxPodSandboxConfig &lc, host_config *hc,
                                         container_config *custom_config, Errors &error);

    void MakeSandboxIsuladConfig(const runtime::v1alpha2::PodSandboxConfig &c, host_config *hc,
                                 container_config *custom_config, Errors &error);

    void MakeContainerConfig(const runtime::v1alpha2::ContainerConfig &config, container_config *cConfig,
                             Errors &error);

    void GetContainerLogPath(const std::string &containerID, char **path, char **realPath, Errors &error);

    void CreateContainerLogSymlink(const std::string &containerID, Errors &error);

    void RemoveContainerLogSymlink(const std::string &containerID, Errors &error);

    auto MakeSandboxName(const runtime::v1alpha2::PodSandboxMetadata &metadata) -> std::string;

    auto MakeContainerName(const runtime::v1alpha2::PodSandboxConfig &s,
                           const runtime::v1alpha2::ContainerConfig &c) -> std::string;

    void modifyContainerNamespaceOptions(bool hasOpts, const runtime::v1alpha2::NamespaceOption &nsOpts, const char *ID,
                                         host_config *hconf, Errors &err);

    static auto SharesHostNetwork(container_inspect *inspect) -> runtime::v1alpha2::NamespaceMode;
    static auto SharesHostPid(container_inspect *inspect) -> runtime::v1alpha2::NamespaceMode;
    static auto SharesHostIpc(container_inspect *inspect) -> runtime::v1alpha2::NamespaceMode;

    void GetContainerTimeStamps(container_inspect *inspect, int64_t *createdAt, int64_t *startedAt,
                                int64_t *finishedAt,
                                Errors &err);
    auto ValidateExecRequest(const runtime::v1alpha2::ExecRequest &req, Errors &error) -> int;

    auto BuildURL(const std::string &method, const std::string &token) -> std::string;

    auto ValidateAttachRequest(const runtime::v1alpha2::AttachRequest &req, Errors &error) -> int;

    static auto ParseCheckpointProtocol(runtime::v1alpha2::Protocol protocol) -> std::string;

    void ConstructPodSandboxCheckpoint(const runtime::v1alpha2::PodSandboxConfig &config,
                                       cri::PodSandboxCheckpoint &checkpoint);

    auto GetIP(const std::string &podSandboxID, container_inspect *inspect, const std::string &networkInterface,
               Errors &error) -> std::string;
    auto GetIPFromPlugin(container_inspect *inspect, const std::string &networkInterface, Errors &error) -> std::string;
    auto GetNetworkReady(const std::string &podSandboxID, Errors &error) -> bool;
    void SetNetworkReady(const std::string &podSandboxID, bool ready, Errors &error);
    void ClearNetworkReady(const std::string &podSandboxID);
    auto EnsureSandboxImageExists(const std::string &image, Errors &error) -> bool;
    void StopContainerHelper(const std::string &containerID, Errors &error);
    static void SetupSandboxFiles(const std::string &resolvPath, const runtime::v1alpha2::PodSandboxConfig &config,
                                  Errors &error);
    auto
    GenerateCreateContainerRequest(const std::string &realPodSandboxID,
                                   const runtime::v1alpha2::ContainerConfig &containerConfig,
                                   const runtime::v1alpha2::PodSandboxConfig &podSandboxConfig,
                                   const std::string &podSandboxRuntime, Errors &error) -> container_create_request *;
    auto GenerateCreateContainerHostConfig(const runtime::v1alpha2::ContainerConfig &containerConfig,
                                           Errors &error) -> host_config *;
    auto PackCreateContainerHostConfigSecurityContext(const runtime::v1alpha2::ContainerConfig &containerConfig,
                                                      host_config *hostconfig, Errors &error) -> int;
    auto PackCreateContainerHostConfigDevices(const runtime::v1alpha2::ContainerConfig &containerConfig,
                                              host_config *hostconfig, Errors &error) -> int;
    auto GenerateCreateContainerCustomConfig(const std::string &realPodSandboxID,
                                             const runtime::v1alpha2::ContainerConfig &containerConfig,
                                             const runtime::v1alpha2::PodSandboxConfig &podSandboxConfig,
                                             Errors &error) -> container_config *;
    auto PackContainerImageToStatus(container_inspect *inspect,
                                    std::unique_ptr<runtime::v1alpha2::ContainerStatus> &contStatus, Errors &error) -> int;
    void UpdateBaseStatusFromInspect(container_inspect *inspect, int64_t &createdAt, int64_t &startedAt,
                                     int64_t &finishedAt,
                                     std::unique_ptr<runtime::v1alpha2::ContainerStatus> &contStatus);
    void PackLabelsToStatus(container_inspect *inspect,
                            std::unique_ptr<runtime::v1alpha2::ContainerStatus> &contStatus);
    void ConvertMountsToStatus(container_inspect *inspect,
                               std::unique_ptr<runtime::v1alpha2::ContainerStatus> &contStatus);

    void SetupSandboxNetwork(const runtime::v1alpha2::PodSandboxConfig &config, const std::string &response_id,
                             const std::string &jsonCheckpoint, Errors &error);
    void SetupUserDefinedNetworkPlane(const runtime::v1alpha2::PodSandboxConfig &config, const std::string &response_id,
                                      container_inspect *inspect_data, std::map<std::string, std::string> &stdAnnos,
                                      std::map<std::string, std::string> &options, Errors &error);
    void StartSandboxContainer(const std::string &response_id, Errors &error);
    auto CreateSandboxContainer(const runtime::v1alpha2::PodSandboxConfig &config, const std::string &image,
                                std::string &jsonCheckpoint, const std::string &runtimeHandler,
                                Errors &error) -> std::string;
    auto GenerateSandboxCreateContainerRequest(const runtime::v1alpha2::PodSandboxConfig &config,
                                               const std::string &image,
                                               std::string &jsonCheckpoint,
                                               const std::string &runtimeHandler,
                                               Errors &error) -> container_create_request *;
    static auto PackCreateContainerRequest(const runtime::v1alpha2::PodSandboxConfig &config,
                                           const std::string &image, host_config *hostconfig,
                                           container_config *custom_config,
                                           const std::string &runtimeHandler,
                                           Errors &error) -> container_create_request *;
    auto GetRealSandboxIDToStop(const std::string &podSandboxID, bool &hostNetwork, std::string &name, std::string &ns,
                                std::string &realSandboxID, std::map<std::string, std::string> &stdAnnos, Errors &error) -> int;
    auto StopAllContainersInSandbox(const std::string &realSandboxID, Errors &error) -> int;
    auto TearDownPodCniNetwork(const std::string &realSandboxID, std::vector<std::string> &errlist,
                               std::map<std::string, std::string> &stdAnnos, const std::string &ns,
                               const std::string &name, Errors &error) -> int;
    auto ClearCniNetwork(const std::string &realSandboxID, bool hostNetwork, const std::string &ns,
                         const std::string &name, std::vector<std::string> &errlist,
                         std::map<std::string, std::string> &stdAnnos, Errors &error) -> int;
    auto RemoveAllContainersInSandbox(const std::string &realSandboxID, std::vector<std::string> &errors) -> int;
    auto DoRemovePodSandbox(const std::string &realSandboxID, std::vector<std::string> &errors) -> int;
    static void MergeSecurityContextToHostConfig(const runtime::v1alpha2::PodSandboxConfig &c, host_config *hc,
                                                 Errors &error);
    auto PackContainerStatsFilter(const runtime::v1alpha2::ContainerStatsFilter *filter,
                                  container_stats_request *request, Errors &error) -> int;


    service_executor_t *m_cb { nullptr };

    std::shared_ptr<Network::PluginManager> m_pluginManager { nullptr };

    std::map<std::string, bool> m_networkReady;
    pthread_mutex_t m_networkReadyLock = PTHREAD_MUTEX_INITIALIZER;
    CRIImageServiceImpl rImageService;
    std::string m_podSandboxImage;
};

#endif // DAEMON_ENTRY_CRI_CRI_RUNTIME_SERVICE_H
