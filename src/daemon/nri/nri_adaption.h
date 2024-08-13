/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2024-03-15
 * Description: provide plugin manager(NRI adaption) class definition
 *********************************************************************************/

#ifndef DAEMON_NRI_PLUGIN_NRI_ADAPTION_H
#define DAEMON_NRI_PLUGIN_NRI_ADAPTION_H

// #include "read_write_lock.h"
#include <isula_libutils/nri_update_containers_request.h>
#include <isula_libutils/nri_update_containers_response.h>

#include "plugin.h"
#include "sandbox.h"
#include "v1_cri_container_manager_service.h"

const std::string PluginNameEnv = "NRI_PLUGIN_NAME";
const std::string PluginIdxEnv = "NRI_PLUGIN_IDX";
const std::string PluginSocketEnv = "NRI_PLUGIN_SOCKET";

struct nri_plugin_exec_args_t {
    const char *workdir;
    const char *cmd;
    const char *name;
    const char *index;
    const uint32_t sockFd;
};

class NRIAdaptation {
public:
    // Singleton
    static NRIAdaptation *GetInstance() noexcept;

    // initialize value
    auto Init(Errors &error) -> bool;

    auto GetSockpath(std::vector<std::string> &paths) -> bool;

    auto StopPlugins() -> bool;

    void RemoveClosedPlugins();

    auto GetPluginByIndex(const std::string &index) -> std::shared_ptr<NRIPlugin>;
    void AddPluginByIndex(const std::string &index, std::shared_ptr<NRIPlugin> plugin);
    void RemovePluginByIndex(const std::string &index);

    auto RunPodSandbox(std::shared_ptr<const sandbox::Sandbox> sandbox, Errors &error) ->bool;
    auto StopPodSandbox(std::shared_ptr<const sandbox::Sandbox> sandbox, Errors &error) ->bool;
    auto RemovePodSandbox(std::shared_ptr<const sandbox::Sandbox> sandbox, Errors &error) ->bool;
    auto CreateContainer(std::shared_ptr<const sandbox::Sandbox> sandbox, const std::string &conId,
                         const runtime::v1::ContainerConfig &containerConfig, nri_container_adjustment **adjust,
                         Errors &error) -> bool;
    auto PostCreateContainer(const std::string &conId, Errors &error) -> bool;
    auto UndoCreateContainer(std::shared_ptr<const sandbox::Sandbox> sandbox, const std::string &conId,
                             Errors &error) -> bool;
    auto StartContainer(const std::string &conId, Errors &error) -> bool;
    auto PostStartContainer(const std::string &conId, Errors &error) -> bool;
    auto UpdateContainer(const std::string &conId, Errors &error) -> bool;
    auto PostUpdateContainer(const std::string &conId, Errors &error) -> bool;
    auto StopContainer(const std::string &conId, Errors &error) -> bool;
    auto RemoveContainer(const std::string &conId, Errors &error) -> bool;
    auto StateChange(nri_state_change_event *evt, Errors &error) -> bool;
    auto updateContainers(const nri_update_containers_request *req, nri_update_containers_response **resp) -> bool;

    auto NewExternalPlugin(int fd) -> bool;

private:
    NRIAdaptation() = default;
    NRIAdaptation(const NRIAdaptation &other) = delete;
    NRIAdaptation &operator=(const NRIAdaptation &) = delete;
    virtual ~NRIAdaptation();

    auto StartPlugin() -> bool;
    auto NewLaunchedPlugin(const std::shared_ptr<NRIPlugin> &) -> bool;
    auto DiscoverPlugins(std::map<std::string, std::shared_ptr<NRIPlugin>> &map) -> bool;
    // Synchronizing NRI (plugin) with current runtime state
    auto SyncPlugin() -> bool;

    auto SortPlugins() -> bool;
    void GetClosedPlugins(std::vector<std::string> &closedPlugin);

    auto ApplyUpdates(const std::vector<nri_container_update *> &update, std::vector<nri_container_update *> &failed,
                      bool getFailed, Errors &error) -> bool;

    auto IsSupport() -> bool;

    auto NRIPodSandbox(const std::shared_ptr<const sandbox::Sandbox> &sandbox,
                       Errors &error) -> std::unique_ptr<CStructWrapper<nri_pod_sandbox>>;
    auto NRIContainerByConConfig(const std::shared_ptr<const sandbox::Sandbox> &sandbox,
                                 const runtime::v1::ContainerConfig &containerConfig, Errors &error) -> std::unique_ptr<CStructWrapper<nri_container>>;
    auto NRIContainerByID(const std::string &id, Errors &error) -> std::unique_ptr<CStructWrapper<nri_container>>;

    auto GetNRIPluginConfigPath(void) -> std::string;
    auto GetNRIPluginPath(void) -> std::string;
    auto GetNRISockPath(void) -> std::string;

    void PluginsStateChange(nri_state_change_event *evt);
    bool PluginsCreateContainer(nri_create_container_request *req, const std::string &conId, pluginResult &result);
    bool PluginsUpdateContainer(nri_update_container_request *req, const std::string &conId, pluginResult &result);

private:
    RWMutex m_mutex;
    static std::atomic<NRIAdaptation *> m_instance;
    bool m_support;
    bool m_external_support;
    std::string m_version;
    std::string m_sock_path;
    std::string m_pluginConfigPath;
    std::string m_pluginPath;
    std::vector<std::string> m_socketPathArr;
    std::string m_disableConnections;
    // id --> NRIPlugin map
    std::map<std::string, std::shared_ptr<NRIPlugin>> m_storeMap;
    // TODO:plugin monitor thread id??
    // shutdown() to clean resource
    // init to create thread
    // todo: if Singleton?
    std::unique_ptr<CRIV1::ContainerManagerService> m_containerManager;
    int64_t m_plugin_registration_timeout;
    int64_t m_plugin_requst_timeout;
};

#endif // DAEMON_NRI_PLUGIN_NRI_ADAPTION_H