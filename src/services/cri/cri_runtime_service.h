/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide cri runtime service function definition
 **********************************************************************************/
#ifndef _CRI_RUNTIME_SERVICES_IMPL_H_
#define _CRI_RUNTIME_SERVICES_IMPL_H_

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <pthread.h>

#include "checkpoint_handler.h"
#include "network_plugin.h"
#include "cri_services.h"
#include "callback.h"
#include "container_inspect.h"
#include "host_config.h"
#include "container_custom_config.h"
#include "errors.h"
#include "cri_image_service.h"
#include "cri_pod_network.h"

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
}  // namespace CRIRuntimeService

class CRIRuntimeServiceImpl : public cri::RuntimeManager,
    public cri::RuntimeVersioner,
    public cri::PodSandboxManager,
    public cri::ContainerManager {
public:
    CRIRuntimeServiceImpl();
    CRIRuntimeServiceImpl(const CRIRuntimeServiceImpl &) = delete;
    CRIRuntimeServiceImpl &operator=(const CRIRuntimeServiceImpl &) = delete;

    virtual ~CRIRuntimeServiceImpl() = default;

    void Init(Network::NetworkPluginConf mConf, const std::string &podSandboxImage, Errors &err);

    std::string GetRealContainerOrSandboxID(const std::string &id, bool isSandbox, Errors &error);

    container_inspect *InspectContainer(const std::string &containerID, Errors &err);

    std::string GetNetNS(const std::string &podSandboxID, Errors &err);

    void Version(const std::string &apiVersion, runtime::VersionResponse *versionResponse,
                 Errors &error) override;

    void UpdateRuntimeConfig(const runtime::RuntimeConfig &config, Errors &error) override;

    std::unique_ptr<runtime::RuntimeStatus> Status(Errors &error) override;

    std::string RunPodSandbox(const runtime::PodSandboxConfig &config, Errors &error) override;

    void StopPodSandbox(const std::string &podSandboxID, Errors &error) override;

    void RemovePodSandbox(const std::string &podSandboxID, Errors &error) override;

    std::unique_ptr<runtime::PodSandboxStatus> PodSandboxStatus(const std::string &podSandboxID,
                                                                Errors &error) override;

    void ListPodSandbox(const runtime::PodSandboxFilter *filter,
                        std::vector<std::unique_ptr<runtime::PodSandbox>> *pods, Errors &error) override;

    void PortForward(const runtime::PortForwardRequest &req, runtime::PortForwardResponse *resp,
                     Errors &error) override;

    std::string CreateContainer(const std::string &podSandboxID,
                                const runtime::ContainerConfig &containerConfig,
                                const runtime::PodSandboxConfig &podSandboxConfig, Errors &error) override;

    void StartContainer(const std::string &containerID, Errors &error) override;

    void StopContainer(const std::string &containerID, int64_t timeout, Errors &error) override;

    void RemoveContainer(const std::string &containerID, Errors &error) override;

    void ListContainers(const runtime::ContainerFilter *filter,
                        std::vector<std::unique_ptr<runtime::Container>> *containers, Errors &error) override;

    void ListContainerStats(const runtime::ContainerStatsFilter *filter,
                            std::vector<std::unique_ptr<runtime::ContainerStats>> *containerstats,
                            Errors &error) override;

    std::unique_ptr<runtime::ContainerStatus> ContainerStatus(const std::string &containerID,
                                                              Errors &error) override;

    void UpdateContainerResources(const std::string &containerID,
                                  const runtime::LinuxContainerResources &resources, Errors &error) override;

    void ExecSync(const std::string &containerID, const google::protobuf::RepeatedPtrField<std::string> &cmd,
                  int64_t timeout, runtime::ExecSyncResponse *reply, Errors &error) override;

    void Exec(const runtime::ExecRequest &req, runtime::ExecResponse *resp, Errors &error) override;

    void Attach(const runtime::AttachRequest &req, runtime::AttachResponse *resp, Errors &error) override;

private:
    void VersionResponseToGRPC(container_version_response *response, runtime::VersionResponse *gResponse,
                               Errors &error);
    bool IsDefaultNetworkPlane(cri_pod_network_element *network);
    void SetSandboxStatusNetwork(container_inspect *inspect, const std::string &podSandboxID,
                                 std::unique_ptr<runtime::PodSandboxStatus> &podStatus, Errors &error);

    void PodSandboxStatusToGRPC(container_inspect *inspect, const std::string &podSandboxID,
                                std::unique_ptr<runtime::PodSandboxStatus> &podStatus, Errors &error);

    void ListPodSandboxToGRPC(container_list_response *response,
                              std::vector<std::unique_ptr<runtime::PodSandbox>> *pods, bool filterOutReadySandboxes,
                              Errors &error);

    void ListContainersToGRPC(container_list_response *response, std::vector<std::unique_ptr<runtime::Container>> *pods,
                              Errors &error);

    void ContainerStatsToGRPC(container_stats_response *response,
                              std::vector<std::unique_ptr<runtime::ContainerStats>> *pods, Errors &error);

    void ContainerStatusToGRPC(container_inspect *inspect, std::unique_ptr<runtime::ContainerStatus> &contStatus,
                               Errors &error);

    void ExecSyncFromGRPC(const std::string &containerID, const google::protobuf::RepeatedPtrField<std::string> &cmd,
                          int64_t timeout, container_exec_request **request, Errors &error);

    void ListContainersFromGRPC(const runtime::ContainerFilter *filter, container_list_request **request,
                                Errors &error);

    void ListPodSandboxFromGRPC(const runtime::PodSandboxFilter *filter, container_list_request **request,
                                bool *filterOutReadySandboxes, Errors &error);

    void ApplySandboxResources(const runtime::LinuxPodSandboxConfig *lc, host_config *hc, Errors &error);

    void ApplySandboxLinuxOptions(const runtime::LinuxPodSandboxConfig &lc, host_config *hc,
                                  container_custom_config *custom_config, Errors &error);

    void MakeSandboxIsuladConfig(const runtime::PodSandboxConfig &c, host_config *hc,
                                 container_custom_config *custom_config, Errors &error);

    void MakeContainerConfig(const runtime::ContainerConfig &config, container_custom_config *cConfig, Errors &error);

    void GetContainerLogPath(const std::string &containerID, char **path, char **realPath, Errors &error);

    void CreateContainerLogSymlink(const std::string &containerID, Errors &error);

    void RemoveContainerLogSymlink(const std::string &containerID, Errors &error);

    std::string MakeSandboxName(const runtime::PodSandboxMetadata &metadata);

    std::string MakeContainerName(const runtime::PodSandboxConfig &s, const runtime::ContainerConfig &c);

    void modifyContainerNamespaceOptions(bool hasOpts, const runtime::NamespaceOption &nsOpts, const char *ID,
                                         host_config *hconf, Errors &err);

    bool SharesHostNetwork(container_inspect *inspect);
    bool SharesHostPid(container_inspect *inspect);
    bool SharesHostIpc(container_inspect *inspect);

    void GetContainerTimeStamps(container_inspect *inspect, int64_t *createdAt, int64_t *startedAt, int64_t *finishedAt,
                                Errors &err);
    int ValidateExecRequest(const runtime::ExecRequest &req, Errors &error);

    std::string BuildURL(const std::string &method, const std::string &token);

    int ValidateAttachRequest(const runtime::AttachRequest &req, Errors &error);

    std::string ParseCheckpointProtocol(runtime::Protocol protocol);

    void ConstructPodSandboxCheckpoint(const runtime::PodSandboxConfig &config, cri::PodSandboxCheckpoint &checkpoint);

    std::string GetIP(const std::string &podSandboxID, container_inspect *inspect, const std::string &networkInterface,
                      Errors &error);
    std::string GetIPFromPlugin(container_inspect *inspect, std::string networkInterface, Errors &error);
    bool GetNetworkReady(const std::string &podSandboxID, Errors &error);
    void SetNetworkReady(const std::string &podSandboxID, bool ready, Errors &error);
    void ClearNetworkReady(const std::string &podSandboxID);
    bool EnsureSandboxImageExists(const std::string &image, Errors &error);
    void StopContainerHelper(const std::string &containerID, Errors &error);
    void SetupSandboxFiles(const std::string &podID, const runtime::PodSandboxConfig &config, Errors &error);
    container_create_request *GenerateCreateContainerRequest(const std::string &realPodSandboxID,
                                                             const runtime::ContainerConfig &containerConfig,
                                                             const runtime::PodSandboxConfig &podSandboxConfig,
                                                             Errors &error);
    host_config *GenerateCreateContainerHostConfig(const runtime::ContainerConfig &containerConfig, Errors &error);
    int PackCreateContainerHostConfigSecurityContext(const runtime::ContainerConfig &containerConfig,
                                                     host_config *hostconfig, Errors &error);
    int PackCreateContainerHostConfigDevices(const runtime::ContainerConfig &containerConfig, host_config *hostconfig,
                                             Errors &error);
    container_custom_config *GenerateCreateContainerCustomConfig(const std::string &realPodSandboxID,
                                                                 const runtime::ContainerConfig &containerConfig,
                                                                 const runtime::PodSandboxConfig &podSandboxConfig,
                                                                 Errors &error);
    int PackContainerImageToStatus(container_inspect *inspect, std::unique_ptr<runtime::ContainerStatus> &contStatus,
                                   Errors &error);
    void UpdateBaseStatusFromInspect(container_inspect *inspect, int64_t &createdAt, int64_t &startedAt,
                                     int64_t &finishedAt, std::unique_ptr<runtime::ContainerStatus> &contStatus);
    void PackLabelsToStatus(container_inspect *inspect, std::unique_ptr<runtime::ContainerStatus> &contStatus);
    void ConvertMountsToStatus(container_inspect *inspect, std::unique_ptr<runtime::ContainerStatus> &contStatus);

    void SetupSandboxNetwork(const runtime::PodSandboxConfig &config, const std::string &response_id,
                             const std::string &jsonCheckpoint, Errors &error);
    void SetupUserDefinedNetworkPlane(const runtime::PodSandboxConfig &config, const std::string &response_id,
                                      container_inspect *inspect_data, std::map<std::string, std::string> &stdAnnos,
                                      Errors &error);
    void StartSandboxContainer(const std::string &response_id, Errors &error);
    std::string CreateSandboxContainer(const runtime::PodSandboxConfig &config, const std::string &image,
                                       std::string &jsonCheckpoint, Errors &error);
    container_create_request *GenerateSandboxCreateContainerRequest(const runtime::PodSandboxConfig &config,
                                                                    const std::string &image,
                                                                    std::string &jsonCheckpoint, Errors &error);
    container_create_request *PackCreateContainerRequest(const runtime::PodSandboxConfig &config,
                                                         const std::string &image, host_config *hostconfig,
                                                         container_custom_config *custom_config, Errors &error);
    int GetRealSandboxIDToStop(const std::string &podSandboxID, bool &hostNetwork, std::string &name, std::string &ns,
                               std::string &realSandboxID, std::map<std::string, std::string> &stdAnnos, Errors &error);
    int StopAllContainersInSandbox(const std::string &realSandboxID, Errors &error);
    int TearDownPodCniNetwork(const std::string &realSandboxID, std::vector<std::string> &errlist,
                              std::map<std::string, std::string> &stdAnnos, const std::string &ns,
                              const std::string &name, Errors &error);
    int ClearCniNetwork(const std::string &realSandboxID, bool hostNetwork, const std::string &ns,
                        const std::string &name, std::vector<std::string> &errlist,
                        std::map<std::string, std::string> &stdAnnos, Errors &error);
    int RemoveAllContainersInSandbox(const std::string &realSandboxID, std::vector<std::string> &errors);
    int DoRemovePodSandbox(const std::string &realSandboxID, std::vector<std::string> &errors);

private:
    service_callback_t *m_cb { nullptr };

    std::shared_ptr<Network::PluginManager> m_pluginManager { nullptr };

    std::map<std::string, bool> m_networkReady;
    pthread_mutex_t m_networkReadyLock = PTHREAD_MUTEX_INITIALIZER;
    CRIImageServiceImpl rImageService;
    std::string m_podSandboxImage;
};

#endif /* _CRI_RUNTIME_SERVICES_IMPL_H_ */
