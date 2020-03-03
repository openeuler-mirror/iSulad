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
 **********************************************************************************/
#include "cni_network_plugin.h"
#include <iostream>
#include <memory>
#include <algorithm>
#include <vector>
#include <utility>
#include <set>

#include "log.h"
#include "utils.h"
#include "cri_helpers.h"

namespace Network {
static std::string VendorCNIDir(const std::string &prefix, const std::string &pluginType)
{
    return prefix + "/opt/" + pluginType + "/bin";
}

static std::unique_ptr<CNINetwork> GetLoNetwork(const std::string &binDir, const std::string &vendorDirPrefix)
{
    const std::string loNetConfListJson { "{\"cniVersion\": \"0.3.0\", \"name\": \"cni-loopback\","
        "\"plugins\":[{\"type\": \"loopback\" }]}" };

    char *cerr { nullptr };
    struct cni_network_list_conf *loConf {
        nullptr
    };
    if (cni_conflist_from_bytes(loNetConfListJson.c_str(), &loConf, &cerr) != 0) {
        if (cerr != nullptr) {
            ERROR("invalid lo config: %s", cerr);
            free(cerr);
        }
        char **traces = get_backtrace();
        if (traces != nullptr) {
            ERROR("show backtrace: ");
            for (char **sym = traces; sym && *sym; sym++) {
                ERROR("%s", *sym);
            }
            util_free_array(traces);
        }
        sync();
        exit(1);
    }

    auto result = std::unique_ptr<CNINetwork>(new (std::nothrow) CNINetwork("lo", loConf));
    if (result == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }

    result->InsertPath(VendorCNIDir(vendorDirPrefix, "loopback"));
    result->InsertPath(binDir);

    return result;
}

CNINetwork::CNINetwork(const std::string &name, struct cni_network_list_conf *list)
    : m_name(name)
    , m_networkConfig(list)
{
}

CNINetwork::~CNINetwork()
{
    free_cni_network_list_conf(m_networkConfig);
}

char **CNINetwork::GetPaths(Errors &err)
{
    char **paths = CRIHelpers::StringVectorToCharArray(m_path);
    if (paths == nullptr) {
        err.SetError("Get char ** path failed");
    }
    return paths;
}

void ProbeNetworkPlugins(const std::string &pluginDir, const std::string &binDir,
                         std::vector<std::shared_ptr<NetworkPlugin>> *plugins)
{
    const std::string useBinDir = binDir.empty() ? DEFAULT_CNI_DIR : binDir;
    auto plugin = std::make_shared<CniNetworkPlugin>(useBinDir, pluginDir);
    plugin->SetLoNetwork(GetLoNetwork(useBinDir, ""));
    plugins->push_back(plugin);
}

void CniNetworkPlugin::SetLoNetwork(std::unique_ptr<CNINetwork> lo)
{
    if (lo != nullptr) {
        m_loNetwork = std::move(lo);
    }
}

CniNetworkPlugin::CniNetworkPlugin(const std::string &binDir, const std::string &pluginDir,
                                   const std::string &vendorCNIDirPrefix)
    : m_pluginDir(pluginDir)
    , m_vendorCNIDirPrefix(vendorCNIDirPrefix)
    , m_binDir(binDir)
{
}

CniNetworkPlugin::~CniNetworkPlugin()
{
    m_networks.clear();
}

void CniNetworkPlugin::PlatformInit(Errors &error)
{
    char *tpath { nullptr };
    char *serr { nullptr };
    tpath = look_path(const_cast<char *>("nsenter"), &serr);
    if (tpath == nullptr) {
        error.SetError(serr);
        return;
    }
    m_nsenterPath = tpath;
    free(tpath);
    return;
}

int CniNetworkPlugin::GetCNIConfFiles(const std::string &pluginDir, std::vector<std::string> &vect_files, Errors &err)
{
    int ret { 0 };
    std::string usePluginDir { pluginDir };
    const char *exts[] { ".conf", ".conflist", ".json" };
    char **files { nullptr };
    char *serr { nullptr };

    if (usePluginDir.empty()) {
        usePluginDir = DEFAULT_NET_DIR;
    }

    ret = cni_conf_files(usePluginDir.c_str(), exts, sizeof(exts) / sizeof(char *), &files, &serr);
    if (ret != 0) {
        err.Errorf("get conf files: %s", serr);
        ret = -1;
        goto out;
    }

    if (util_array_len((const char **)files) == 0) {
        err.Errorf("No networks found in %s", usePluginDir.c_str());
        ret = -1;
        goto out;
    }

    vect_files = std::vector<std::string>(files, files + util_array_len((const char **)files));

out:
    free(serr);
    util_free_array(files);
    return ret;
}

int CniNetworkPlugin::LoadCNIConfigFileList(const std::string &elem, struct cni_network_list_conf **n_list)
{
    int ret { 0 };
    std::size_t found = elem.rfind(".conflist");
    char *serr { nullptr };
    struct cni_network_conf *n_conf {
        nullptr
    };

    if (found != std::string::npos && found + strlen(".conflist") == elem.length()) {
        if (cni_conflist_from_file(elem.c_str(), n_list, &serr) != 0) {
            WARN("Error loading CNI config list file %s: %s", elem.c_str(), serr);
            ret = -1;
            goto out;
        }
    } else {
        if (cni_conf_from_file(elem.c_str(), &n_conf, &serr) != 0) {
            WARN("Error loading CNI config file %s: %s", elem.c_str(), serr);
            ret = -1;
            goto out;
        }
        if (n_conf->type == nullptr || strcmp(n_conf->type, "") == 0) {
            WARN("Error loading CNI config file %s: no 'type'; perhaps this is a .conflist?", elem.c_str());
            ret = -1;
            goto out;
        }
        if (cni_conflist_from_conf(n_conf, n_list, &serr) != 0) {
            WARN("Error converting CNI config file %s to list: %s", elem.c_str(), serr);
            ret = -1;
            goto out;
        }
    }
out:
    if (n_conf != nullptr) {
        free_cni_network_conf(n_conf);
    }
    free(serr);
    return ret;
}

int CniNetworkPlugin::InsertConfNameToAllPanes(struct cni_network_list_conf *n_list, std::set<std::string> &allPanes,
                                               Errors &err)
{
    int ret { 0 };
    std::string confName { "" };

    if (n_list == nullptr) {
        err.Errorf("Invalid arguments");
        return -1;
    }
    if (n_list->first_plugin_name != nullptr) {
        confName = n_list->first_plugin_name;
    }

    if (confName.empty() || allPanes.find(confName) != allPanes.end()) {
        free_cni_network_list_conf(n_list);
        n_list = nullptr;
        ret = -1;
        ERROR("Invalid cni network name: %s, it may be duplicated or empty.", confName.c_str());
        err.Errorf("Invalid cni network name: %s, it may be duplicated or empty.", confName.c_str());
        goto out;
    }
    allPanes.insert(confName);

out:
    return ret;
}

int CniNetworkPlugin::InsertNewNetwork(struct cni_network_list_conf *n_list,
                                       std::map<std::string, std::unique_ptr<CNINetwork>> &newNets,
                                       const std::string &binDir, const std::string &vendorCNIDirPrefix, Errors &err)
{
    std::string confType { "" };

    if (n_list == nullptr) {
        err.Errorf("Invalid arguments");
        return -1;
    }
    if (n_list->first_plugin_type != nullptr) {
        confType = n_list->first_plugin_type;
    }

    std::string tpath = VendorCNIDir(vendorCNIDirPrefix, confType);
    if (tpath.empty()) {
        free_cni_network_list_conf(n_list);
        err.SetError("Out of memory");
        return -1;
    }
    std::unique_ptr<CNINetwork> network(new (std::nothrow) CNINetwork(n_list->name, n_list));
    if (network == nullptr) {
        free_cni_network_list_conf(n_list);
        err.SetError("Out of memory");
        return -1;
    }
    network->InsertPath(tpath);
    network->InsertPath(binDir);

    std::string n_key(network->GetName());
    newNets.insert(std::pair<std::string, std::unique_ptr<CNINetwork>>(n_key, std::move(network)));
    DEBUG("---parse cni network: %s finish ----", n_key.c_str());

    return 0;
}

void CniNetworkPlugin::ResetCNINetwork(std::map<std::string, std::unique_ptr<CNINetwork>> &newNets, Errors &err)
{
    std::string pluginNames { "map[" };

    m_networks.clear();
    for (auto iter = newNets.begin(); iter != newNets.end(); iter++) {
        m_networks[iter->first] = std::move(iter->second);
        pluginNames += (iter->first + " ");
    }
    INFO("Loaded cni plugins successfully, all plugins: %s]", pluginNames.substr(0, pluginNames.length() - 1).c_str());
}

void CniNetworkPlugin::GetCNINetwork(const std::string &pluginDir, const std::string &binDir,
                                     const std::string &vendorCNIDirPrefix, Errors &err)
{
    std::vector<std::string> files;
    std::set<std::string> allPanes;
    std::map<std::string, std::unique_ptr<CNINetwork>> newNets;

    if (GetCNIConfFiles(pluginDir, files, err) != 0) {
        goto free_out;
    }

    for (auto elem : files) {
        struct cni_network_list_conf *n_list = nullptr;

        if (LoadCNIConfigFileList(elem, &n_list) != 0) {
            continue;
        }

        if (n_list == nullptr || n_list->plugin_len == 0) {
            WARN("CNI config list %s has no networks, skipping", elem.c_str());
            free_cni_network_list_conf(n_list);
            n_list = nullptr;
            continue;
        }

        if (InsertConfNameToAllPanes(n_list, allPanes, err) != 0) {
            goto free_out;
        }

        if (InsertNewNetwork(n_list, newNets, binDir, vendorCNIDirPrefix, err) != 0) {
            goto free_out;
        }
    }

    if (newNets.size() == 0) {
        err.Errorf("No valid networks found in %s", pluginDir.c_str());
        goto free_out;
    }
    ResetCNINetwork(newNets, err);

free_out:
    newNets.clear();
    return;
}

void CniNetworkPlugin::CheckInitialized(Errors &err)
{
    RLockNetworkMap(err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetCMessage());
        return;
    }
    size_t len = m_networks.size();
    UnlockNetworkMap(err);
    if (len == 0) {
        err.AppendError("cni config uninitialized");
    }
}

void CniNetworkPlugin::SyncNetworkConfig()
{
    Errors err;
    WLockNetworkMap(err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetCMessage());
        return;
    }
    GetCNINetwork(m_pluginDir, m_binDir, m_vendorCNIDirPrefix, err);
    if (err.NotEmpty()) {
        WARN("Unable to update cni config: %s", err.GetCMessage());
    }
    UnlockNetworkMap(err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetCMessage());
    }
}

void CniNetworkPlugin::Init(CRIRuntimeServiceImpl *criImpl, const std::string &hairpinMode,
                            const std::string &nonMasqueradeCIDR, int mtu, Errors &error)
{
    UNUSED(hairpinMode);
    UNUSED(nonMasqueradeCIDR);
    UNUSED(mtu);

    if (criImpl == nullptr) {
        error.Errorf("Empty runtime service");
        return;
    }
    PlatformInit(error);
    if (error.NotEmpty()) {
        return;
    }
    m_criImpl = criImpl;
    SyncNetworkConfig();

    return;
}

const std::string &CniNetworkPlugin::Name() const
{
    return CNI_PLUGIN_NAME;
}

void CniNetworkPlugin::Status(Errors &err)
{
    SyncNetworkConfig();

    CheckInitialized(err);
}

void CniNetworkPlugin::SetUpPod(const std::string &ns, const std::string &name, const std::string &networkPlane,
                                const std::string &interfaceName, const std::string &id,
                                const std::map<std::string, std::string> &annotations, Errors &err)
{
    CheckInitialized(err);
    if (err.NotEmpty()) {
        return;
    }
    std::string netnsPath = m_criImpl->GetNetNS(id, err);
    if (err.NotEmpty()) {
        ERROR("CNI failed to retrieve network namespace path: %s", err.GetCMessage());
        return;
    }
    auto iter = annotations.find(CRIHelpers::Constants::POD_CHECKPOINT_KEY);
    std::string jsonCheckpoint { "" };
    if (iter != annotations.end()) {
        jsonCheckpoint = iter->second;
    }
    DEBUG("add checkpoint: ", jsonCheckpoint.c_str());

    struct result *preResult = nullptr;
    if (m_loNetwork != nullptr) {
        AddToNetwork(m_loNetwork.get(), jsonCheckpoint, name, ns, interfaceName, id, netnsPath, &preResult, err);
        free_result(preResult);
        preResult = nullptr;
        if (err.NotEmpty()) {
            ERROR("Error while adding to cni lo network: %s", err.GetCMessage());
            return;
        }
    }

    RLockNetworkMap(err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetCMessage());
        return;
    }
    auto netIter = m_networks.find(networkPlane);
    if (netIter == m_networks.end()) {
        ERROR("Can't find cni plugin for network plane %s.", networkPlane.c_str());
        err.Errorf("Can't find cni plugin for network plane %s.", networkPlane.c_str());
        goto unlock_out;
    }

    AddToNetwork((netIter->second).get(), jsonCheckpoint, name, ns, interfaceName, id, netnsPath, &preResult, err);
    free_result(preResult);
    preResult = nullptr;
    if (err.NotEmpty()) {
        ERROR("Error while adding to cni network: %s", err.GetCMessage());
    }

unlock_out:
    UnlockNetworkMap(err);
}

void CniNetworkPlugin::TearDownPod(const std::string &ns, const std::string &name, const std::string &networkPlane,
                                   const std::string &interfaceName, const std::string &id,
                                   const std::map<std::string, std::string> &annotations, Errors &err)
{
    CheckInitialized(err);
    if (err.NotEmpty()) {
        return;
    }

    std::string netnsPath = m_criImpl->GetNetNS(id, err);
    if (err.NotEmpty()) {
        WARN("CNI failed to retrieve network namespace path: %s", err.GetCMessage());
        err.Clear();
    }

    auto iter = annotations.find(CRIHelpers::Constants::POD_CHECKPOINT_KEY);
    std::string jsonCheckpoint = "";
    if (iter != annotations.end()) {
        jsonCheckpoint = iter->second;
    }
    DEBUG("delete checkpoint: ", jsonCheckpoint.c_str());
    RLockNetworkMap(err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetCMessage());
        return;
    }
    auto netIter = m_networks.find(networkPlane);
    if (netIter == m_networks.end()) {
        ERROR("Can't find cni plugin for network plane %s.", networkPlane.c_str());
        err.Errorf("Can't find cni plugin for network plane %s.", networkPlane.c_str());
        goto unlock_out;
    }

    DeleteFromNetwork((netIter->second).get(), jsonCheckpoint, name, ns, interfaceName, id, netnsPath, err);

unlock_out:
    UnlockNetworkMap(err);
}

std::map<int, bool> *CniNetworkPlugin::Capabilities()
{
    return m_noop.Capabilities();
}

void CniNetworkPlugin::Event(const std::string &name, std::map<std::string, std::string> &details)
{
    m_noop.Event(name, details);
}

void CniNetworkPlugin::GetPodNetworkStatus(const std::string &ns, const std::string &name,
                                           const std::string &interfaceName, const std::string &podSandboxID,
                                           PodNetworkStatus &status, Errors &err)
{
    std::string netnsPath, ip;
    Errors tmpErr;

    if (podSandboxID.empty()) {
        err.SetError("Empty podsandbox ID");
        goto out;
    }

    netnsPath = m_criImpl->GetNetNS(podSandboxID, tmpErr);
    if (tmpErr.NotEmpty()) {
        err.Errorf("CNI failed to retrieve network namespace path: %s", tmpErr.GetCMessage());
        goto out;
    }
    if (netnsPath.empty()) {
        err.Errorf("Cannot find the network namespace, skipping pod network status for container %s",
                   podSandboxID.c_str());
        goto out;
    }
    ip = GetPodIP(m_nsenterPath, netnsPath, interfaceName, err);
    if (err.NotEmpty()) {
        ERROR("GetPodIP failed: %s", err.GetCMessage());
        goto out;
    }
    status.SetIP(ip);

out:
    INFO("get_pod_network_status: %s", podSandboxID.c_str());
}

void CniNetworkPlugin::AddToNetwork(CNINetwork *snetwork, const std::string &jsonCheckpoint, const std::string &podName,
                                    const std::string &podNamespace, const std::string &interfaceName,
                                    const std::string &podSandboxID, const std::string &podNetnsPath,
                                    struct result **presult, Errors &err)
{
    struct runtime_conf *rc {
        nullptr
    };

    if (snetwork == nullptr || presult == nullptr) {
        err.Errorf("Invalid arguments");
        ERROR("Invalid arguments");
        return;
    }
    BuildCNIRuntimeConf(podName, jsonCheckpoint, podNamespace, interfaceName, podSandboxID, podNetnsPath, &rc, err);
    if (err.NotEmpty()) {
        ERROR("Error adding network when building cni runtime conf: %s", err.GetCMessage());
        return;
    }

    INFO("About to add CNI network %s (type=%s)", snetwork->GetName().c_str(), snetwork->GetNetworkType().c_str());

    char **paths = snetwork->GetPaths(err);
    if (paths == nullptr) {
        ERROR("Empty cni bin path");
        free_runtime_conf(rc);
        return;
    }
    char *serr = nullptr;
    int nret = cni_add_network_list(snetwork->GetNetworkConfigJsonStr().c_str(), rc, paths, presult, &serr);
    if (nret != 0) {
        ERROR("Error adding network: %s", serr);
        err.SetError(serr);
    }

    util_free_array(paths);
    free_runtime_conf(rc);
    free(serr);
}

void CniNetworkPlugin::DeleteFromNetwork(CNINetwork *network, const std::string &jsonCheckpoint,
                                         const std::string &podName, const std::string &podNamespace,
                                         const std::string &interfaceName, const std::string &podSandboxID,
                                         const std::string &podNetnsPath, Errors &err)
{
    struct runtime_conf *rc {
        nullptr
    };

    if (network == nullptr) {
        err.Errorf("Invalid arguments");
        ERROR("Invalid arguments");
        return;
    }
    BuildCNIRuntimeConf(podName, jsonCheckpoint, podNamespace, interfaceName, podSandboxID, podNetnsPath, &rc, err);
    if (err.NotEmpty()) {
        ERROR("Error deleting network when building cni runtime conf: %s", err.GetCMessage());
        return;
    }

    INFO("About to del CNI network %s (type=%s)", network->GetName().c_str(), network->GetNetworkType().c_str());

    char **paths = network->GetPaths(err);
    if (paths == nullptr) {
        free_runtime_conf(rc);
        ERROR("Empty cni bin path");
        return;
    }
    char *serr = nullptr;
    int nret = cni_del_network_list(network->GetNetworkConfigJsonStr().c_str(), rc, paths, &serr);
    if (nret != 0) {
        ERROR("Error deleting network: %s", serr);
        err.Errorf("Error deleting network: %s", serr);
    }

    util_free_array(paths);
    free_runtime_conf(rc);
    free(serr);
}

void CniNetworkPlugin::BuildCNIRuntimeConf(const std::string &podName, const std::string &jsonCheckpoint,
                                           const std::string &podNs, const std::string &interfaceName,
                                           const std::string &podSandboxID, const std::string &podNetnsPath,
                                           struct runtime_conf **cni_rc, Errors &err)
{
    std::vector<cri::PortMapping> portMappings;
    INFO("Got netns path %s", podNetnsPath.c_str());
    INFO("Using podns path %s", podNs.c_str());

    if (cni_rc == nullptr) {
        err.Errorf("Invalid arguments");
        ERROR("Invalid arguments");
        return;
    }
    struct runtime_conf *rt = (struct runtime_conf *)util_common_calloc_s(sizeof(struct runtime_conf));
    if (rt == nullptr) {
        ERROR("Out of memory");
        err.SetError("Out of memory");
        return;
    }

    rt->container_id = util_strdup_s(podSandboxID.c_str());
    rt->netns = util_strdup_s(podNetnsPath.c_str());
    rt->ifname = util_strdup_s(interfaceName.c_str());

    rt->args = (char *(*)[2])util_common_calloc_s(sizeof(char *) * 2 * 4);
    if (rt->args == nullptr) {
        ERROR("Out of memory");
        err.SetError("Out of memory");
        goto free_out;
    }
    rt->args_len = 4;
    rt->args[0][0] = util_strdup_s("IgnoreUnknown");
    rt->args[0][1] = util_strdup_s("1");
    rt->args[1][0] = util_strdup_s("K8S_POD_NAMESPACE");
    rt->args[1][1] = util_strdup_s(podNs.c_str());
    rt->args[2][0] = util_strdup_s("K8S_POD_NAME");
    rt->args[2][1] = util_strdup_s(podName.c_str());
    rt->args[3][0] = util_strdup_s("K8S_POD_INFRA_CONTAINER_ID");
    rt->args[3][1] = util_strdup_s(podSandboxID.c_str());

    if (!jsonCheckpoint.empty()) {
        cri::PodSandboxCheckpoint checkpoint;
        CRIHelpers::GetCheckpoint(jsonCheckpoint, checkpoint, err);
        if (err.NotEmpty() || checkpoint.GetData() == nullptr) {
            err.Errorf("could not retrieve port mappings: %s", err.GetCMessage());
            goto free_out;
        }
        std::copy(checkpoint.GetData()->GetPortMappings().begin(), checkpoint.GetData()->GetPortMappings().end(),
                  std::back_inserter(portMappings));
    }

    if (portMappings.size() > 0) {
        if (portMappings.size() > SIZE_MAX / sizeof(struct cni_port_mapping *)) {
            err.SetError("Invalid cni port mapping size");
            goto free_out;
        }
        rt->p_mapping = (struct cni_port_mapping **)util_common_calloc_s(sizeof(struct cni_port_mapping *) *
                                                                         portMappings.size());
        if (rt->p_mapping == nullptr) {
            err.SetError("Out of memory");
            goto free_out;
        }
        for (auto iter = portMappings.cbegin(); iter != portMappings.cend(); iter++) {
            if (iter->GetHostPort() && *(iter->GetHostPort()) <= 0) {
                continue;
            }
            rt->p_mapping[rt->p_mapping_len] =
                (struct cni_port_mapping *)util_common_calloc_s(sizeof(struct cni_port_mapping));
            if (rt->p_mapping[rt->p_mapping_len] == nullptr) {
                err.SetError("Out of memory");
                goto free_out;
            }
            if (iter->GetHostPort()) {
                rt->p_mapping[rt->p_mapping_len]->host_port = *(iter->GetHostPort());
            }
            if (iter->GetContainerPort()) {
                rt->p_mapping[rt->p_mapping_len]->container_port = *(iter->GetContainerPort());
            }
            if (iter->GetProtocol()) {
                rt->p_mapping[rt->p_mapping_len]->protocol = strings_to_lower(iter->GetProtocol()->c_str());
            }
            // ignore hostip, because GetPodPortMappings() don't set
            (rt->p_mapping_len)++;
        }
    }

    *cni_rc = rt;
    return;
free_out:
    free_runtime_conf(rt);
}

void CniNetworkPlugin::RLockNetworkMap(Errors &error)
{
    int ret = pthread_rwlock_rdlock(&m_netsLock);
    if (ret != 0) {
        error.Errorf("Get read lock failed: %s", strerror(ret));
    }
}

void CniNetworkPlugin::WLockNetworkMap(Errors &error)
{
    int ret = pthread_rwlock_wrlock(&m_netsLock);
    if (ret != 0) {
        error.Errorf("Get write lock failed: %s", strerror(ret));
    }
}

void CniNetworkPlugin::UnlockNetworkMap(Errors &error)
{
    int ret = pthread_rwlock_unlock(&m_netsLock);
    if (ret != 0) {
        error.Errorf("Unlock failed: %s", strerror(ret));
    }
}

} // namespace Network
