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
 * Description: provide cni network plugin function definition
 ********************************************************************************/
#ifndef _CRI_CNI_NETWORK_PLUGIN_H_
#define _CRI_CNI_NETWORK_PLUGIN_H_

#include <memory>
#include <string>
#include <map>
#include <vector>
#include <set>
#include <clibcni/api.h>

#include "network_plugin.h"
#include "utils.h"
#include "errors.h"
#include "cri_runtime_service.h"

namespace Network {
#define UNUSED(x) ((void)(x))
static const std::string CNI_PLUGIN_NAME { "cni" };
static const std::string DEFAULT_NET_DIR { "/etc/cni/net.d" };
static const std::string DEFAULT_CNI_DIR { "/opt/cni/bin" };

class CNINetwork {
public:
    CNINetwork() = delete;
    CNINetwork(const CNINetwork &) = delete;
    CNINetwork &operator=(const CNINetwork &) = delete;
    CNINetwork(const std::string &name, struct cni_network_list_conf *netList);
    ~CNINetwork();
    const std::string &GetName() const
    {
        return m_name;
    }
    void SetName(const std::string &name)
    {
        m_name = name;
    }
    void InsertPath(const std::string &path)
    {
        m_path.push_back(path);
    }
    std::string GetNetworkConfigJsonStr()
    {
        return m_networkConfig->bytes ? m_networkConfig->bytes : "";
    }
    std::string GetNetworkType() const
    {
        return m_networkConfig->first_plugin_type ? m_networkConfig->first_plugin_type : "";
    }
    std::string GetNetworkName() const
    {
        return m_networkConfig->first_plugin_name ? m_networkConfig->first_plugin_name : "";
    }
    char **GetPaths(Errors &err);

private:
    std::string m_name;
    std::vector<std::string> m_path;
    struct cni_network_list_conf *m_networkConfig {
        nullptr
    };
};

class CniNetworkPlugin : public NetworkPlugin {
public:
    CniNetworkPlugin(const std::string &binDir, const std::string &pluginDir,
                     const std::string &vendorCNIDirPrefix = "");

    virtual ~CniNetworkPlugin();

    void Init(CRIRuntimeServiceImpl *criImpl, const std::string &hairpinMode, const std::string &nonMasqueradeCIDR,
              int mtu, Errors &error) override;

    void Event(const std::string &name, std::map<std::string, std::string> &details) override;

    const std::string &Name() const override;

    std::map<int, bool> *Capabilities() override;

    void SetUpPod(const std::string &ns, const std::string &name, const std::string &networkPlane,
                  const std::string &interfaceName, const std::string &podSandboxID,
                  const std::map<std::string, std::string> &annotations, Errors &error) override;

    void TearDownPod(const std::string &ns, const std::string &name, const std::string &networkPlane,
                     const std::string &interfaceName, const std::string &podSandboxID,
                     const std::map<std::string, std::string> &annotations, Errors &error) override;

    void GetPodNetworkStatus(const std::string &ns, const std::string &name, const std::string &interfaceName,
                             const std::string &podSandboxID, PodNetworkStatus &status, Errors &error) override;

    void Status(Errors &error) override;

    virtual void SetLoNetwork(std::unique_ptr<CNINetwork> lo);

private:
    virtual void PlatformInit(Errors &error);
    virtual void SyncNetworkConfig();

    virtual void GetCNINetwork(const std::string &pluginDir, const std::string &binDir,
                               const std::string &vendorCNIDirPrefix, Errors &error);

    virtual void CheckInitialized(Errors &error);

    virtual void AddToNetwork(CNINetwork *network, const std::string &jsonCheckpoint, const std::string &podName,
                              const std::string &podNamespace, const std::string &interfaceName,
                              const std::string &podSandboxID, const std::string &podNetnsPath, struct result **presult,
                              Errors &error);

    virtual void DeleteFromNetwork(CNINetwork *network, const std::string &jsonCheckpoint, const std::string &podName,
                                   const std::string &podNamespace, const std::string &interfaceName,
                                   const std::string &podSandboxID, const std::string &podNetnsPath, Errors &error);

    virtual void BuildCNIRuntimeConf(const std::string &podName, const std::string &jsonCheckpoint,
                                     const std::string &podNs, const std::string &interfaceName,
                                     const std::string &podSandboxID, const std::string &podNetnsPath,
                                     struct runtime_conf **cni_rc, Errors &error);

private:
    void RLockNetworkMap(Errors &error);
    void WLockNetworkMap(Errors &error);
    void UnlockNetworkMap(Errors &error);
    int GetCNIConfFiles(const std::string &pluginDir, std::vector<std::string> &vect_files, Errors &err);
    int LoadCNIConfigFileList(const std::string &elem, struct cni_network_list_conf **n_list);
    int InsertConfNameToAllPanes(struct cni_network_list_conf *n_list, std::set<std::string> &allPanes, Errors &err);
    int InsertNewNetwork(struct cni_network_list_conf *n_list,
                         std::map<std::string, std::unique_ptr<CNINetwork>> &newNets, const std::string &binDir,
                         const std::string &vendorCNIDirPrefix, Errors &err);
    void ResetCNINetwork(std::map<std::string, std::unique_ptr<CNINetwork>> &newNets, Errors &err);

    NoopNetworkPlugin m_noop;
    std::unique_ptr<CNINetwork> m_loNetwork { nullptr };
    CRIRuntimeServiceImpl *m_criImpl { nullptr };
    std::string m_nsenterPath;
    std::string m_pluginDir;
    std::string m_vendorCNIDirPrefix;
    std::string m_binDir;

    pthread_rwlock_t m_netsLock = PTHREAD_RWLOCK_INITIALIZER;
    std::map<std::string, std::unique_ptr<CNINetwork>> m_networks;
};

} // namespace Network

#endif
