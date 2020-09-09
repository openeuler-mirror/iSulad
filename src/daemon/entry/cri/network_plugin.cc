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
 * Description: provide net plugin functions
 *********************************************************************************/

#include "network_plugin.h"
#include <memory>
#include <utility>
#include <vector>
#include <map>
#include <unistd.h>

#include "cni/types.h"
#include "utils.h"
#include "isula_libutils/log.h"
#include "sysctl_tools.h"
#include "cri_runtime_service.h"

namespace Network {
static void run_modprobe(void *args)
{
    execlp("modprobe", "modprobe", "br-netfilter", nullptr);
}

static void runGetIP(void *cmdArgs)
{
    constexpr size_t ARGS_NUM { 14 };
    constexpr size_t CMD_ARGS_NUM { 4 };
    char *args[ARGS_NUM];
    char **tmpArgs = reinterpret_cast<char **>(cmdArgs);

    if (util_array_len((const char **)tmpArgs) != CMD_ARGS_NUM) {
        COMMAND_ERROR("need four args");
        exit(1);
    }

    if (asprintf(&(args[1]), "--net=%s", tmpArgs[1]) < 0) {
        COMMAND_ERROR("Out of memory");
        exit(1);
    }

    args[0] = util_strdup_s(tmpArgs[0]);
    args[2] = util_strdup_s("-F");
    args[3] = util_strdup_s("--");
    args[4] = util_strdup_s("ip");
    args[5] = util_strdup_s("-o");
    args[6] = util_strdup_s(tmpArgs[3]);
    args[7] = util_strdup_s("addr");
    args[8] = util_strdup_s("show");
    args[9] = util_strdup_s("dev");
    args[10] = util_strdup_s(tmpArgs[2]);
    args[11] = util_strdup_s("scope");
    args[12] = util_strdup_s("global");
    args[13] = nullptr;
    execvp(tmpArgs[0], args);
}

static std::string ParseIPFromLine(const char *line, const char *stdout_str)
{
    char *cIP { nullptr };
    char **fields { nullptr };
    char *strErr { nullptr };
    struct ipnet *ipnet_val {
        nullptr
    };
    std::string ret;

    fields = util_string_split(line, ' ');
    if (fields == nullptr) {
        ERROR("Out of memory");
        goto out;
    }
    if (util_array_len((const char **)fields) < 4) {
        ERROR("Unexpected address output %s ", line);
        goto out;
    }

    if (parse_cidr(fields[3], &ipnet_val, &strErr) != 0) {
        ERROR("CNI failed to parse ip from output %s due to %s", stdout_str, strErr);
        goto out;
    }
    cIP = ip_to_string(ipnet_val->ip, ipnet_val->ip_len);
    if (cIP == nullptr) {
        ERROR("Out of memory");
        goto out;
    }

    ret = cIP;
out:
    free(cIP);
    free(strErr);
    free_ipnet_type(ipnet_val);
    util_free_array(fields);
    return ret;
}

static void GetOnePodIP(std::string nsenterPath, std::string netnsPath, std::string interfaceName,
                        std::string addrType, std::vector<std::string> &ips, Errors &error)
{
    char *stderr_str { nullptr };
    char *stdout_str { nullptr };
    char **lines { nullptr };
    char **args { nullptr };
    size_t i;

    args = (char **)util_common_calloc_s(sizeof(char *) * 5);
    if (args == nullptr) {
        error.SetError("Out of memory");
        return;
    }

    args[0] = util_strdup_s(nsenterPath.c_str());
    args[1] = util_strdup_s(netnsPath.c_str());
    args[2] = util_strdup_s(interfaceName.c_str());
    args[3] = util_strdup_s(addrType.c_str());
    if (!util_exec_cmd(runGetIP, args, nullptr, &stdout_str, &stderr_str)) {
        error.Errorf("Unexpected command output %s with error: %s", stdout_str, stderr_str);
        goto free_out;
    }

    DEBUG("get ip : %s", stdout_str);
    /* get ip from stdout str */
    lines = util_string_split(stdout_str, '\n');
    if (lines == nullptr) {
        error.SetError("Out of memory");
        goto free_out;
    }

    if (util_array_len((const char **)lines) == 0) {
        error.Errorf("Unexpected command output %s", stdout_str);
        goto free_out;
    }

    for (i = 0; i < util_array_len((const char **)lines); i++) {
        // ip string min length must bigger than 4
        if (lines[i] == nullptr || strlen(lines[i]) < 4) {
            continue;
        }
        std::string tIP = ParseIPFromLine(lines[i], stdout_str);
        if (tIP.empty()) {
            error.Errorf("parse %s to ip failed", lines[i]);
            break;
        }
        ips.push_back(tIP);
    }

free_out:
    free(stdout_str);
    free(stderr_str);
    util_free_array(args);
    util_free_array(lines);
}

void GetPodIP(const std::string &nsenterPath, const std::string &netnsPath, const std::string &interfaceName,
              std::vector<std::string> &getIPs, Errors &error)
{
    Errors tmpErr;

    GetOnePodIP(nsenterPath, netnsPath, interfaceName, "-4", getIPs, tmpErr);
    if (tmpErr.NotEmpty()) {
        WARN("Get ipv4 failed: %s", tmpErr.GetCMessage());
    }

    GetOnePodIP(nsenterPath, netnsPath, interfaceName, "-6", getIPs, error);
    if (error.NotEmpty()) {
        WARN("Get ipv6 failed: %s", tmpErr.GetCMessage());
    }

    if (getIPs.size() > 0) {
        error.Clear();
        return;
    }

    if (tmpErr.NotEmpty()) {
        error.AppendError(tmpErr.GetMessage());
    }
}

void InitNetworkPlugin(std::vector<std::shared_ptr<NetworkPlugin>> *plugins, std::string networkPluginName,
                       std::string hairpinMode, std::string nonMasqueradeCIDR, int mtu,
                       std::shared_ptr<NetworkPlugin> *result, Errors &err)
{
    std::string allErr { "" };

    if (networkPluginName.empty()) {
        DEBUG("network plugin name empty");
        *result = std::shared_ptr<NetworkPlugin>(new (std::nothrow) NoopNetworkPlugin);
        if (*result == nullptr) {
            ERROR("Out of memory");
            return;
        }
        (*result)->Init(hairpinMode, nonMasqueradeCIDR, mtu, err);
        return;
    }

    std::map<std::string, std::shared_ptr<NetworkPlugin>> pluginMap;

    for (auto it = plugins->begin(); it != plugins->end(); ++it) {
        std::string tmpName = (*it)->Name();
        // qualify plugin name
        if (pluginMap.find(tmpName) != pluginMap.end()) {
            allErr += ("network plugin " + tmpName + "was registered more than once");
            continue;
        }

        pluginMap[tmpName] = *it;
    }

    if (pluginMap.find(networkPluginName) == pluginMap.end()) {
        allErr += ("Network plugin " + networkPluginName + "not found.");
        err.SetError(allErr);
        pluginMap.clear();
        return;
    }
    *result = pluginMap.find(networkPluginName)->second;

    (*result)->Init(hairpinMode, nonMasqueradeCIDR, mtu, err);
    if (err.NotEmpty()) {
        allErr += ("Network plugin " + networkPluginName + " failed init: " + err.GetMessage());
        err.SetError(allErr);
    } else {
        INFO("Loaded network plugin %s", networkPluginName.c_str());
    }

    pluginMap.clear();
    return;
}

const std::string &NetworkPluginConf::GetDockershimRootDirectory() const
{
    return m_dockershimRootDirectory;
}

void NetworkPluginConf::SetDockershimRootDirectory(const std::string &rootDir)
{
    m_dockershimRootDirectory = rootDir;
}

const std::string &NetworkPluginConf::GetPluginConfDir() const
{
    return m_pluginConfDir;
}

void NetworkPluginConf::SetPluginConfDir(const std::string &confDir)
{
    m_pluginConfDir = confDir;
}

const std::string &NetworkPluginConf::GetPluginBinDir() const
{
    return m_pluginBinDir;
}

void NetworkPluginConf::SetPluginBinDir(const std::string &binDir)
{
    m_pluginBinDir = binDir;
}

const std::string &NetworkPluginConf::GetPluginName() const
{
    return m_pluginName;
}

void NetworkPluginConf::SetPluginName(const std::string &name)
{
    m_pluginName = name;
}

const std::string &NetworkPluginConf::GetHairpinMode() const
{
    return m_hairpinMode;
}

void NetworkPluginConf::SetHairpinMode(const std::string &mode)
{
    m_hairpinMode = mode;
}

const std::string &NetworkPluginConf::GetNonMasqueradeCIDR() const
{
    return m_nonMasqueradeCIDR;
}

void NetworkPluginConf::SetNonMasqueradeCIDR(const std::string &cidr)
{
    m_nonMasqueradeCIDR = cidr;
}

int NetworkPluginConf::GetMTU()
{
    return m_mtu;
}

void NetworkPluginConf::SetMTU(int mtu)
{
    m_mtu = mtu;
}

const std::string &PodNetworkStatus::GetKind() const
{
    return m_kind;
}

void PodNetworkStatus::SetKind(const std::string &kind)
{
    m_kind = kind;
}

const std::string &PodNetworkStatus::GetAPIVersion() const
{
    return m_apiVersion;
}

void PodNetworkStatus::SetAPIVersion(const std::string &version)
{
    m_apiVersion = version;
}

const std::vector<std::string> &PodNetworkStatus::GetIPs() const
{
    return m_ips;
}

void PodNetworkStatus::SetIPs(std::vector<std::string> &ips)
{
    m_ips = ips;
}

void PluginManager::Lock(const std::string &fullPodName, Errors &error)
{
    if (pthread_mutex_lock(&m_podsLock) != 0) {
        error.SetError("plugin manager lock failed");
        return;
    }
    auto iter = m_pods.find(fullPodName);
    PodLock *lock { nullptr };
    if (iter == m_pods.end()) {
        auto tmpLock = std::unique_ptr<PodLock>(new (std::nothrow) PodLock());
        if (tmpLock == nullptr) {
            error.SetError("Out of memory");
            return;
        }
        lock = tmpLock.get();
        m_pods[fullPodName] = std::move(tmpLock);
    } else {
        lock = iter->second.get();
    }
    lock->Increase();

    if (pthread_mutex_unlock(&m_podsLock) != 0) {
        error.SetError("plugin manager unlock failed");
    }

    lock->Lock(error);
}

void PluginManager::Unlock(const std::string &fullPodName, Errors &error)
{
    if (pthread_mutex_lock(&m_podsLock) != 0) {
        error.SetError("plugin manager lock failed");
        return;
    }

    auto iter = m_pods.find(fullPodName);
    PodLock *lock { nullptr };
    if (iter == m_pods.end()) {
        WARN("Unbalanced pod lock unref for %s", fullPodName.c_str());
        goto unlock;
    }
    lock = iter->second.get();
    if (lock->GetRefcount() == 0) {
        m_pods.erase(iter);
        WARN("Pod lock for %s still in map with zero refcount", fullPodName.c_str());
        goto unlock;
    }
    lock->Decrease();
    lock->Unlock(error);
    if (lock->GetRefcount() == 0) {
        m_pods.erase(iter);
    }
unlock:
    if (pthread_mutex_unlock(&m_podsLock) != 0) {
        error.SetError("plugin manager unlock failed");
    }
}

std::string PluginManager::PluginName()
{
    if (m_plugin != nullptr) {
        return m_plugin->Name();
    }
    return "";
}

void PluginManager::Event(const std::string &name, std::map<std::string, std::string> &details)
{
    if (m_plugin != nullptr) {
        m_plugin->Event(name, details);
    }
}

void PluginManager::Status(Errors &error)
{
    if (m_plugin != nullptr) {
        m_plugin->Status(error);
    }
}

void PluginManager::GetPodNetworkStatus(const std::string &ns, const std::string &name,
                                        const std::string &interfaceName, const std::string &podSandboxID,
                                        PodNetworkStatus &status, Errors &error)
{
    std::string fullName = name + "_" + ns;

    Lock(fullName, error);
    if (error.NotEmpty()) {
        return;
    }
    if (m_plugin != nullptr) {
        Errors tmpErr;
        m_plugin->GetPodNetworkStatus(ns, name, interfaceName, podSandboxID, status, tmpErr);
        if (tmpErr.NotEmpty()) {
            error.Errorf("NetworkPlugin %s failed on the status hook for pod %s: %s", m_plugin->Name().c_str(),
                         fullName.c_str(), tmpErr.GetCMessage());
        }
    }
    Unlock(fullName, error);
}

void PluginManager::SetUpPod(const std::string &ns, const std::string &name, const std::string &interfaceName,
                             const std::string &podSandboxID, std::map<std::string, std::string> &annotations,
                             const std::map<std::string, std::string> &options, Errors &error)
{
    if (m_plugin == nullptr) {
        return;
    }

    std::string fullName = name + "_" + ns;
    Lock(fullName, error);
    if (error.NotEmpty()) {
        return;
    }
    INFO("Calling network plugin %s to set up pod %s", m_plugin->Name().c_str(), fullName.c_str());

    Errors tmpErr;
    m_plugin->SetUpPod(ns, name, interfaceName, podSandboxID, annotations, options, tmpErr);
    if (tmpErr.NotEmpty()) {
        error.Errorf("NetworkPlugin %s failed to set up pod %s network: %s", m_plugin->Name().c_str(), fullName.c_str(),
                     tmpErr.GetCMessage());
    }
    Unlock(fullName, error);
}

void PluginManager::TearDownPod(const std::string &ns, const std::string &name, const std::string &interfaceName,
                                const std::string &podSandboxID, std::map<std::string, std::string> &annotations,
                                Errors &error)
{
    Errors tmpErr;
    std::string fullName = name + "_" + ns;
    Lock(fullName, error);
    if (error.NotEmpty()) {
        return;
    }
    if (m_plugin == nullptr) {
        goto unlock;
    }

    INFO("Calling network plugin %s to tear down pod %s", m_plugin->Name().c_str(), fullName.c_str());
    m_plugin->TearDownPod(ns, name, Network::DEFAULT_NETWORK_INTERFACE_NAME, podSandboxID, annotations, tmpErr);
    if (tmpErr.NotEmpty()) {
        error.Errorf("NetworkPlugin %s failed to teardown pod %s network: %s", m_plugin->Name().c_str(),
                     fullName.c_str(), tmpErr.GetCMessage());
    }
unlock:
    Unlock(fullName, error);
}

void NoopNetworkPlugin::Init(const std::string &hairpinMode,
                             const std::string &nonMasqueradeCIDR, int mtu, Errors &error)
{
    char *stderr_str { nullptr };
    char *stdout_str { nullptr };
    int ret;
    char *err { nullptr };

    if (!util_exec_cmd(run_modprobe, nullptr, nullptr, &stdout_str, &stderr_str)) {
        WARN("exec failed: [%s], [%s]", stdout_str, stderr_str);
    }

    ret = set_sysctl(SYSCTL_BRIDGE_CALL_IPTABLES.c_str(), 1, &err);
    if (ret != 0) {
        WARN("can't set sysctl %s: 1, err: %s", SYSCTL_BRIDGE_CALL_IPTABLES.c_str(), err);
        free(err);
        err = nullptr;
    }

    ret = get_sysctl(SYSCTL_BRIDGE_CALL_IP6TABLES.c_str(), &err);
    if (ret != 1) {
        free(err);
        err = nullptr;
        ret = set_sysctl(SYSCTL_BRIDGE_CALL_IP6TABLES.c_str(), 1, &err);
        if (ret != 0) {
            WARN("can't set sysctl %s: 1, err: %s", SYSCTL_BRIDGE_CALL_IP6TABLES.c_str(), err);
        }
    }

    free(err);
    free(stderr_str);
    free(stdout_str);
}

void NoopNetworkPlugin::Event(const std::string &name, std::map<std::string, std::string> &details)
{
    return;
}

const std::string &NoopNetworkPlugin::Name() const
{
    return DEFAULT_PLUGIN_NAME;
}

std::map<int, bool> *NoopNetworkPlugin::Capabilities()
{
    std::map<int, bool> *ret { new (std::nothrow) std::map<int, bool> };
    return ret;
}

void NoopNetworkPlugin::SetUpPod(const std::string &ns, const std::string &name, const std::string &interfaceName,
                                 const std::string &podSandboxID, const std::map<std::string, std::string> &annotations,
                                 const std::map<std::string, std::string> &options, Errors &error)
{
    return;
}

void NoopNetworkPlugin::TearDownPod(const std::string &ns, const std::string &name, const std::string &interfaceName,
                                    const std::string &podSandboxID,
                                    const std::map<std::string, std::string> &annotations, Errors &error)
{
    return;
}

void NoopNetworkPlugin::GetPodNetworkStatus(const std::string &ns, const std::string &name,
                                            const std::string &interfaceName, const std::string &podSandboxID,
                                            PodNetworkStatus &status, Errors &error)
{
    return;
}

void NoopNetworkPlugin::Status(Errors &error)
{
    return;
}

const std::string &GetInterfaceName()
{
    return DEFAULT_NETWORK_INTERFACE_NAME;
}
} // namespace Network
