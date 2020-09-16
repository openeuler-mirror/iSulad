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
 * Description: provide cni network plugin function definition
 ********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_CNI_NETWORK_PLUGIN_H
#define DAEMON_ENTRY_CRI_CNI_NETWORK_PLUGIN_H

#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "libcni_api.h"

#include "cri_runtime_service.h"
#include "errors.h"
#include "network_plugin.h"
#include "utils.h"
#include "isula_libutils/container_inspect.h"

namespace Network {
#define UNUSED(x) ((void)(x))
static const std::string CNI_PLUGIN_NAME { "cni" };
static const std::string DEFAULT_NET_DIR { "/etc/cni/net.d" };
static const std::string DEFAULT_CNI_DIR { "/opt/cni/bin" };

class CNINetwork {
public:
    CNINetwork() = delete;
    CNINetwork(const CNINetwork &) = delete;
    auto operator=(const CNINetwork &) -> CNINetwork & = delete;
    CNINetwork(const std::string &name, struct cni_network_list_conf *netList);
    ~CNINetwork();
    auto GetName() const -> const std::string &
    {
        return m_name;
    }
    void SetName(const std::string &name)
    {
        m_name = name;
    }
    void SetPaths(std::vector<std::string> &binDirs)
    {
        m_path = binDirs;
    }
    auto GetNetworkConfigJsonStr() -> std::string
    {
        return m_networkConfig->bytes != nullptr ? m_networkConfig->bytes : "";
    }
    auto GetNetworkType() const -> std::string
    {
        return m_networkConfig->first_plugin_type != nullptr ? m_networkConfig->first_plugin_type : "";
    }
    auto GetNetworkName() const -> std::string
    {
        return m_networkConfig->first_plugin_name != nullptr ? m_networkConfig->first_plugin_name : "";
    }
    auto UpdateCNIConfList(struct cni_network_list_conf *newConf) -> struct cni_network_list_conf * {
        struct cni_network_list_conf *result = m_networkConfig;
        m_networkConfig = newConf;
        return result;
    }

    auto GetPaths(Errors &err) -> char **;

private:
    std::string m_name;
    std::vector<std::string> m_path;
    struct cni_network_list_conf *m_networkConfig {
        nullptr
    };
};

class CniNetworkPlugin : public NetworkPlugin {
public:
    CniNetworkPlugin(std::vector<std::string> &binDirs, const std::string &confDir,
                     const std::string &podCidr = "");

    virtual ~CniNetworkPlugin();

    void Init(const std::string &hairpinMode, const std::string &nonMasqueradeCIDR,
              int mtu, Errors &error) override;

    void Event(const std::string &name, std::map<std::string, std::string> &details) override;

    auto Name() const -> const std::string &override;

    auto Capabilities() -> std::map<int, bool> * override;

    void SetUpPod(const std::string &ns, const std::string &name,
                  const std::string &interfaceName, const std::string &podSandboxID,
                  const std::map<std::string, std::string> &annotations,
                  const std::map<std::string, std::string> &options, Errors &error) override;

    void TearDownPod(const std::string &ns, const std::string &name,
                     const std::string &interfaceName, const std::string &podSandboxID,
                     const std::map<std::string, std::string> &annotations, Errors &error) override;

    void GetPodNetworkStatus(const std::string &ns, const std::string &name, const std::string &interfaceName,
                             const std::string &podSandboxID, PodNetworkStatus &status, Errors &error) override;

    void Status(Errors &error) override;

    virtual void SetLoNetwork(std::unique_ptr<CNINetwork> lo);

private:
    auto GetNetNS(const std::string &podSandboxID, Errors &err) -> std::string;


private:
    virtual void PlatformInit(Errors &error);
    virtual void SyncNetworkConfig();

    virtual void GetDefaultCNINetwork(const std::string &confDir, std::vector<std::string> &binDirs, Errors &error);

    virtual void CheckInitialized(Errors &error);

    virtual void AddToNetwork(CNINetwork *network, const std::string &podName,
                              const std::string &podNamespace, const std::string &interfaceName,
                              const std::string &podSandboxID, const std::string &podNetnsPath,
                              const std::map<std::string, std::string> &annotations,
                              const std::map<std::string, std::string> &options,
                              struct result **presult, Errors &error);

    virtual void DeleteFromNetwork(CNINetwork *network, const std::string &podName,
                                   const std::string &podNamespace, const std::string &interfaceName,
                                   const std::string &podSandboxID, const std::string &podNetnsPath,
                                   const std::map<std::string, std::string> &annotations,
                                   Errors &error);

    virtual void BuildCNIRuntimeConf(const std::string &podName,
                                     const std::string &podNs, const std::string &interfaceName,
                                     const std::string &podSandboxID, const std::string &podNetnsPath,
                                     const std::map<std::string, std::string> &annotations,
                                     const std::map<std::string, std::string> &options,
                                     struct runtime_conf **cni_rc, Errors &error);


    void RLockNetworkMap(Errors &error);
    void WLockNetworkMap(Errors &error);
    void UnlockNetworkMap(Errors &error);

    void UpdateMutlNetworks(std::vector<std::unique_ptr<CNINetwork>> &multNets, std::vector<std::string> &binDirs,
                            Errors &err);
    void SetDefaultNetwork(std::unique_ptr<CNINetwork> network, std::vector<std::string> &binDirs, Errors &err);
    void SetPodCidr(const std::string &podCidr);
    static auto GetCNIConfFiles(const std::string &pluginDir, std::vector<std::string> &vect_files, Errors &err) -> int;
    static auto LoadCNIConfigFileList(const std::string &elem, struct cni_network_list_conf **n_list) -> int;
    static auto InsertConfNameToAllPanes(struct cni_network_list_conf *n_list, std::set<std::string> &allPanes,
                                         Errors &err) -> int;
    void ResetCNINetwork(std::map<std::string, std::unique_ptr<CNINetwork>> &newNets, Errors &err);
    void UpdateDefaultNetwork();

    bool SetupMultNetworks(const std::string &ns, const std::string &defaultInterface, const std::string &name,
                           const std::string &netnsPath, const std::string &podSandboxID, const std::map<std::string, std::string> &annotations,
                           const std::map<std::string, std::string> &options, Errors &err);

    void TearDownMultNetworks(const std::string &ns, const std::string &defaultInterface, const std::string &name,
                              const std::string &netnsPath, const std::string &podSandboxID, const std::map<std::string, std::string> &annotations,
                              Errors &err);

    NoopNetworkPlugin m_noop;
    std::unique_ptr<CNINetwork> m_loNetwork { nullptr };
    std::unique_ptr<CNINetwork> m_defaultNetwork { nullptr };
    std::map<std::string, std::unique_ptr<CNINetwork>> m_mutlNetworks;

    std::string m_nsenterPath;
    std::string m_confDir;
    std::vector<std::string> m_binDirs;
    std::string m_podCidr;

    pthread_rwlock_t m_netsLock = PTHREAD_RWLOCK_INITIALIZER;

    std::thread m_syncThread;
    bool m_needFinish;
};

} // namespace Network

#endif
