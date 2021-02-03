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
 * Description: provide network plugin function definition
 **********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_NETWORK_PLUGIN_H
#define DAEMON_ENTRY_CRI_NETWORK_PLUGIN_H

#include <memory>
#include <map>
#include <vector>
#include <string>

#include "errors.h"

namespace Network {
const std::string DEFAULT_NETWORK_PLANE_NAME = "default";
const std::string DEFAULT_NETWORK_INTERFACE_NAME = "eth0";
const std::string POD_DISABLE_DEFAULT_NET_ANNOTATION_KEY = "network.alpha.kubernetes.io/disableDefaultNetwork";

class NetworkPluginConf {
public:
    /* settings for net plugin */
    NetworkPluginConf(const std::string &dockershimRootDirectory = "/var/lib/isulad/shim",
                      const std::string &pluginConfDir = "/etc/cni/net.d/",
                      const std::string &pluginBinDir = "/opt/cni/bin", const std::string &pluginName = "",
                      const std::string &hairpinMode = "hairpin-veth", const std::string &nonMasqueradeCIDR = "",
                      int32_t mtu = 1460)
        : m_dockershimRootDirectory(dockershimRootDirectory),
          m_pluginConfDir(pluginConfDir),
          m_pluginBinDir(pluginBinDir),
          m_pluginName(pluginName),
          m_hairpinMode(hairpinMode),
          m_nonMasqueradeCIDR(nonMasqueradeCIDR),
          m_mtu(mtu)
    {
    }
    ~NetworkPluginConf() = default;

    const std::string &GetDockershimRootDirectory() const;
    void SetDockershimRootDirectory(const std::string &rootDir);
    const std::string &GetPluginConfDir() const;
    void SetPluginConfDir(const std::string &confDir);
    const std::string &GetPluginBinDir() const;
    void SetPluginBinDir(const std::string &binDir);
    const std::string &GetPluginName() const;
    void SetPluginName(const std::string &name);
    const std::string &GetHairpinMode() const;
    void SetHairpinMode(const std::string &mode);
    const std::string &GetNonMasqueradeCIDR() const;
    void SetNonMasqueradeCIDR(const std::string &cidr);
    int32_t GetMTU();
    void SetMTU(int32_t mtu);

private:
    std::string m_dockershimRootDirectory;
    std::string m_pluginConfDir;
    std::string m_pluginBinDir;
    std::string m_pluginName;
    std::string m_hairpinMode;
    std::string m_nonMasqueradeCIDR;
    int32_t m_mtu;
    /* finish net plugin */
};

class PodNetworkStatus {
public:
    PodNetworkStatus() = default;
    ~PodNetworkStatus() = default;
    const std::string &GetKind() const;
    void SetKind(const std::string &kind);
    const std::string &GetAPIVersion() const;
    void SetAPIVersion(const std::string &version);
    const std::vector<std::string> &GetIPs() const;
    void SetIPs(std::vector<std::string> &ips);

private:
    std::string m_kind;
    std::string m_apiVersion;
    std::vector<std::string> m_ips;
};

class NetworkPlugin {
public:
    virtual void Init(const std::string &hairpinMode,
                      const std::string &nonMasqueradeCIDR, int mtu, Errors &error) = 0;

    virtual void Event(const std::string &name, std::map<std::string, std::string> &details) = 0;

    virtual const std::string &Name() const = 0;

    virtual std::map<int, bool> *Capabilities() = 0;

    virtual void SetUpPod(const std::string &ns, const std::string &name,
                          const std::string &interfaceName, const std::string &podSandboxID,
                          const std::map<std::string, std::string> &annotations,
                          const std::map<std::string, std::string> &options, std::string &network_settings_json, Errors &error) = 0;

    virtual void TearDownPod(const std::string &ns, const std::string &name, const std::string &networkPlane,
                             const std::string &podSandboxID,
                             const std::map<std::string, std::string> &annotations, Errors &error) = 0;

    virtual void GetPodNetworkStatus(const std::string &ns, const std::string &name, const std::string &interfaceName,
                                     const std::string &podSandboxID, PodNetworkStatus &status, Errors &error) = 0;

    virtual void Status(Errors &error) = 0;
};

class NoopNetworkPlugin : public NetworkPlugin {
public:
    NoopNetworkPlugin() = default;

    virtual ~NoopNetworkPlugin() = default;

    void Init(const std::string &hairpinMode, const std::string &nonMasqueradeCIDR,
              int mtu, Errors &error) override;

    void Event(const std::string &name, std::map<std::string, std::string> &details) override;

    const std::string &Name() const override;

    std::map<int, bool> *Capabilities() override;

    void SetUpPod(const std::string &ns, const std::string &name,
                  const std::string &interfaceName, const std::string &podSandboxID,
                  const std::map<std::string, std::string> &annotations,
                  const std::map<std::string, std::string> &options, std::string &network_settings_json, Errors &error) override;

    void TearDownPod(const std::string &ns, const std::string &name, const std::string &networkPlane,
                     const std::string &podSandboxID,
                     const std::map<std::string, std::string> &annotations, Errors &error) override;

    void GetPodNetworkStatus(const std::string &ns, const std::string &name, const std::string &interfaceName,
                             const std::string &podSandboxID, PodNetworkStatus &status, Errors &error) override;

    void Status(Errors &error) override;

private:
    std::string SYSCTL_BRIDGE_CALL_IPTABLES = "net/bridge/bridge-nf-call-iptables";
    std::string SYSCTL_BRIDGE_CALL_IP6TABLES = "net/bridge/bridge-nf-call-ip6tables";
    std::string DEFAULT_PLUGIN_NAME = "kubernetes.io/no-op";
};

class PodLock {
public:
    PodLock() = default;
    ~PodLock() = default;
    uint32_t GetRefcount()
    {
        return m_refcount;
    }
    void Increase()
    {
        m_refcount++;
    }
    void Decrease()
    {
        m_refcount--;
    }
    void Lock(Errors &error)
    {
        int ret = pthread_mutex_lock(&m_mu);
        if (ret != 0) {
            error.Errorf("mutex lock failed: %d", ret);
        }
    }
    void Unlock(Errors &error)
    {
        int ret = pthread_mutex_unlock(&m_mu);
        if (ret != 0) {
            error.Errorf("mutex unlock failed: %d", ret);
        }
    }

private:
    // Count of in-flight operations for this pod; when this reaches zero the lock can be removed from the pod map
    uint32_t m_refcount = 0;

    // Lock to synchronize operations for this specific pod
    pthread_mutex_t m_mu = PTHREAD_MUTEX_INITIALIZER;
};

class PluginManager {
public:
    explicit PluginManager(std::shared_ptr<NetworkPlugin> plugin)
        : m_plugin(plugin)
    {
    }
    ~PluginManager() = default;
    std::string PluginName();
    void Event(const std::string &name, std::map<std::string, std::string> &details);
    void Status(Errors &error);
    void GetPodNetworkStatus(const std::string &ns, const std::string &name, const std::string &interfaceName,
                             const std::string &podSandboxID, PodNetworkStatus &status, Errors &error);
    void SetUpPod(const std::string &ns, const std::string &name,
                  const std::string &interfaceName, const std::string &podSandboxID,
                  std::map<std::string, std::string> &annotations,
                  const std::map<std::string, std::string> &options, std::string &network_settings_json, Errors &error);
    void TearDownPod(const std::string &ns, const std::string &name, const std::string &networkPlane,
                     const std::string &podSandboxID,
                     std::map<std::string, std::string> &annotations, Errors &error);

private:
    void Lock(const std::string &fullPodName, Errors &error);
    void Unlock(const std::string &fullPodName, Errors &error);

    pthread_mutex_t m_podsLock = PTHREAD_MUTEX_INITIALIZER;
    std::map<std::string, std::unique_ptr<Network::PodLock>> m_pods;
    std::shared_ptr<NetworkPlugin> m_plugin = nullptr;
};

void InitNetworkPlugin(std::vector<std::shared_ptr<NetworkPlugin>> *plugins, std::string networkPluginName,
                       std::string hairpinMode, std::string nonMasqueradeCIDR, int mtu,
                       std::shared_ptr<NetworkPlugin> *result, Errors &error);

void ProbeNetworkPlugins(const std::string &pluginDir, const std::string &binDir,
                         std::vector<std::shared_ptr<NetworkPlugin>> *plugins);

void GetPodIP(const std::string &nsenterPath, const std::string &netnsPath, const std::string &interfaceName,
              std::vector<std::string> &getIPs, Errors &error);

const std::string &GetInterfaceName();
} // namespace Network

#endif
