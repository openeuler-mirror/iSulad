/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2023-06-19
 * Description: provide sandbox class definition
 *********************************************************************************/

#ifndef DAEMON_SANDBOX_SANDBOX_H
#define DAEMON_SANDBOX_SANDBOX_H

#include <string>
#include <mutex>
#include <google/protobuf/map.h>

#include <isula_libutils/container_network_settings.h>
#include <isula_libutils/sandbox_state.h>
#include <isula_libutils/sandbox_metadata.h>

#include "api_v1.grpc.pb.h"
#include "errors.h"
#include "controller.h"
#include "controller_manager.h"
#include "cstruct_wrapper.h"
#include "read_write_lock.h"

namespace sandbox {

const std::string SANDBOX_METADATA_JSON = "sandbox_metadata.json";
const std::string SANDBOX_STATE_JSON = "sandbox_state.json";
const std::string NETWORK_SETTINGS_JSON = "network_settings.json";

// Keep consistent with the default values set in containerd and cri-o.
const uint32_t DEFAULT_STOP_TIMEOUT = 10;
const std::string DEFAULT_NETMODE = "cni";

enum SandboxStatus {
    SANDBOX_STATUS_UNKNOWN = 0,
    SANDBOX_STATUS_RUNNING,
    SANDBOX_STATUS_PENDING,
    SANDBOX_STATUS_STOPPED,
    SANDBOX_STATUS_REMOVING,
};

struct StatsInfo {
    int64_t timestamp;
    uint64_t cpuUseNanos;
};

struct RuntimeInfo {
    // container runtime
    std::string runtime;
    // sandbox type
    std::string sandboxer;
    // cri runtime handler
    std::string runtimeHandler;
};

struct SandboxState {
    uint32_t pid;
    uint64_t createdAt;
    // now, updatedAt is unused
    uint64_t updatedAt;
    uint64_t exitedAt;
    uint32_t exitStatus;
    SandboxStatus status;
};

class Sandbox : public SandboxStatusCallback, public std::enable_shared_from_this<Sandbox> {
public:
    Sandbox(const std::string id, const std::string &rootdir, const std::string &statedir, const std::string name = "",
            const RuntimeInfo info = {"", "", ""}, std::string netMode = DEFAULT_NETMODE, std::string netNsPath = "",
            const runtime::v1::PodSandboxConfig sandboxConfig = runtime::v1::PodSandboxConfig::default_instance(),
            const std::string image = "");
    virtual ~Sandbox() = default;

    auto IsReady() -> bool;

    auto GetId() const -> const std::string &;
    auto GetName() const -> const std::string &;
    auto GetRuntime() const -> const std::string &;
    auto GetSandboxer() const -> const std::string &;
    auto GetRuntimeHandle() const -> const std::string &;
    auto GetSandboxConfig() const -> const runtime::v1::PodSandboxConfig &;
    auto GetMutableSandboxConfig() -> std::shared_ptr<runtime::v1::PodSandboxConfig>;
    auto GetRootDir() const -> const std::string &;
    auto GetStateDir() const -> const std::string &;
    auto GetResolvPath() const -> std::string;
    auto GetHostnamePath() const -> std::string;
    auto GetHostsPath() const -> std::string;
    auto GetShmPath() const -> std::string;
    auto GetStatsInfo() -> StatsInfo;
    auto GetNetworkReady() const -> bool;
    auto GetNetMode() const -> const std::string &;
    auto GetNetNsPath() const -> const std::string &;
    auto GetNetworkSettings() -> const std::string &;
    auto GetCreatedAt() -> uint64_t;
    auto GetPid() -> uint32_t;
    auto GetTaskAddress() const -> const std::string &;
    auto GetImage() -> const std::string &;
    void SetNetMode(const std::string &mode);
    void SetController(std::shared_ptr<Controller> controller);
    void AddAnnotations(const std::string &key, const std::string &value);
    void RemoveAnnotations(const std::string &key);
    void AddLabels(const std::string &key, const std::string &value);
    void RemoveLabels(const std::string &key);
    void UpdateNetworkSettings(const std::string &settingsJson, Errors &error);
    auto UpdateStatsInfo(const StatsInfo &info) -> StatsInfo;
    void SetNetworkReady(bool ready);
    void SetNetworkMode(const std::string &networkMode);
    auto FindAvailableVsockPort(uint32_t &port) -> bool;
    void ReleaseVsockPort(uint32_t port);
    auto CleanupSandboxFiles(Errors &error) -> bool;
    void PrepareSandboxDirs(Errors &error);
    void CleanupSandboxDirs();

    // Save to file
    auto Save(Errors &error) -> bool;
    // Load from file
    auto Load(Errors &error) -> bool;

    void OnSandboxReady();
    void OnSandboxPending();
    void OnSandboxExit(const ControllerExitInfo &exitInfo);

    auto UpdateStatus(Errors &error) -> bool;

    auto Create(Errors &error) -> bool;
    auto Start(Errors &error) -> bool;
    auto Stop(uint32_t timeoutSecs, Errors &error) -> bool;
    auto Remove(Errors &error) -> bool;
    void Status(runtime::v1::PodSandboxStatus &status);

private:
    auto SaveState(Errors &error) -> bool;
    auto SaveMetadata(Errors &error) -> bool;
    auto SaveNetworkSetting(Errors &error) -> bool;

    auto LoadState(Errors &error) -> bool;
    auto LoadMetadata(Errors &error) -> bool;
    void LoadNetworkSetting();

    void SetSandboxConfig(const runtime::v1::PodSandboxConfig &config);
    void SetNetworkSettings(const std::string &settings, Errors &error);
    auto CreateHostname(bool shareHost, Errors &error) -> bool;
    auto CreateHosts(bool shareHost, Errors &error) -> bool;
    auto CreateResolvConf(Errors &error) -> bool;
    auto CreateShmDev(Errors &error) -> bool;
    auto SetupSandboxFiles(Errors &error) -> bool;
    void DoUpdateStatus(std::unique_ptr<ControllerSandboxStatus> status, Errors &error);
    void DoUpdateExitedStatus(const ControllerExitInfo &exitInfo);
    bool DoStatusUpdateAndWaitInLoad(const std::string &sandboxID, Errors &error);

    auto GetMetadataJsonPath() ->  std::string;
    auto GetStatePath() -> std::string;
    auto GetNetworkSettingsPath() -> std::string;

    void FillSandboxState(sandbox_state *state);
    void FillSandboxMetadata(sandbox_metadata* metadata, Errors &error);

    auto GenerateSandboxStateJson(sandbox_state *state) -> std::string;
    auto GenerateSandboxMetadataJson(sandbox_metadata *metadata) -> std::string;
    auto ParseSandboxStateFile() ->std::unique_ptr<CStructWrapper<sandbox_state>>;
    auto ParseSandboxMetadataFile() ->std::unique_ptr<CStructWrapper<sandbox_metadata>>;

    auto DoStop(uint32_t timeoutSecs, Errors &error) -> bool;
    auto IsRemovalInProcess() -> bool;
    auto IsStopped() -> bool;
    auto isValidMetadata(std::unique_ptr<CStructWrapper<sandbox_metadata>> &metadata) -> bool;

    void updateSelinuxLabels(std::string &selinuxLabels);

private:
    // Since the cri module will operate concurrently on the sandbox instance,
    // use m_mutex to ensure the correctness of the sandbox instance
    RWMutex m_mutex;
    // use m_stateMutex to ensure the correctness of m_state, m_statsInfo and m_networkSettings
    RWMutex m_stateMutex;
    SandboxState m_state;
    std::string m_id;
    std::string m_name;
    RuntimeInfo m_runtimeInfo;
    // m_rootdir = conf->rootpath + / + sandbox + / + id
    std::string m_rootdir;
    std::string m_statedir;
    std::string m_taskAddress;
    StatsInfo m_statsInfo;
    // Store network information in the sandbox, which is convenient for the cri module to obtain
    // and update the network settings of the pause container in the shim-controller.
    std::string m_netMode;
    std::string m_netNsPath;
    std::string m_networkMode;
    bool m_networkReady;
    std::string m_networkSettings;
    std::string m_image;
    // TOOD: m_sandboxConfig is a protobuf message, it can be converted to json string directly
    //       if save json string directly for sandbox recover, we need to consider hot
    //       upgrade between different CRI versions
    std::shared_ptr<runtime::v1::PodSandboxConfig> m_sandboxConfig;

    // it should select accroding to the config
    std::shared_ptr<Controller> m_controller { nullptr };

    // vsock ports
    std::mutex m_vsockPortsMutex;
    std::set<uint32_t> m_vsockPorts;
};

} // namespace sandbox

#endif // DAEMON_SANDBOX_SANDBOX_H