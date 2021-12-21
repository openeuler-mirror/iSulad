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
 **********************************************************************************/
#include "cni_network_plugin.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <utility>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "cri_helpers.h"
#include "cxxutils.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "errors.h"
#include "service_container_api.h"
#include "network_namespace_api.h"

namespace Network {
static auto GetLoNetwork(std::vector<std::string> binDirs) -> std::unique_ptr<CNINetwork>
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
        char **traces = util_get_backtrace();
        if (traces != nullptr) {
            ERROR("show backtrace: ");
            for (char **sym = traces; (sym != nullptr) && (*sym != nullptr); sym++) {
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

    result->SetPaths(binDirs);

    return result;
}

CNINetwork::CNINetwork(const std::string &name, struct cni_network_list_conf *list)
    : m_name(name), m_networkConfig(list)
{
}

CNINetwork::~CNINetwork()
{
    free_cni_network_list_conf(m_networkConfig);
}

auto CNINetwork::GetPaths(Errors &err) -> char **
{
    char **paths = CRIHelpers::StringVectorToCharArray(m_path);
    if (paths == nullptr) {
        err.SetError("Get cni network paths failed");
    }
    return paths;
}

void ProbeNetworkPlugins(const std::string &pluginDir, const std::string &binDir,
                         std::vector<std::shared_ptr<NetworkPlugin>> *plugins)
{
    const std::string useBinDir = binDir.empty() ? DEFAULT_CNI_DIR : binDir;
    std::vector<std::string> binDirs = CXXUtils::Split(useBinDir, ',');
    auto plugin = std::make_shared<CniNetworkPlugin>(binDirs, pluginDir);
    plugin->SetLoNetwork(GetLoNetwork(binDirs));
    plugins->push_back(plugin);
}

void CniNetworkPlugin::SetLoNetwork(std::unique_ptr<CNINetwork> lo)
{
    if (lo != nullptr) {
        m_loNetwork = std::move(lo);
    }
}

void CniNetworkPlugin::SetDefaultNetwork(std::unique_ptr<CNINetwork> network, std::vector<std::string> &binDirs,
                                         Errors &err)
{
    if (network == nullptr) {
        return;
    }
    WLockNetworkMap(err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetCMessage());
        return;
    }
    m_defaultNetwork = std::move(network);
    m_defaultNetwork->SetPaths(binDirs);

    DEBUG("Update new cni network: \"%s\"", m_defaultNetwork->GetName().c_str());

    UnlockNetworkMap(err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetCMessage());
    }
}

void CniNetworkPlugin::UpdateMutlNetworks(std::vector<std::unique_ptr<CNINetwork>> &multNets,
                                          std::vector<std::string> &binDirs, Errors &err)
{
    if (multNets.size() == 0) {
        return;
    }
    WLockNetworkMap(err);
    if (err.NotEmpty()) {
        return;
    }

    m_mutlNetworks.clear();
    for (auto iter = multNets.begin(); iter != multNets.end(); ++iter) {
        (*iter)->SetPaths(binDirs);
        m_mutlNetworks[(*iter)->GetName()] = std::move(*iter);
    }

    UnlockNetworkMap(err);
}

CniNetworkPlugin::CniNetworkPlugin(std::vector<std::string> &binDirs, const std::string &confDir,
                                   const std::string &podCidr)
    : m_confDir(confDir), m_binDirs(binDirs), m_podCidr(podCidr), m_needFinish(false)
{
}

CniNetworkPlugin::~CniNetworkPlugin()
{
    m_needFinish = true;
    if (m_syncThread.joinable()) {
        m_syncThread.join();
    }
    m_mutlNetworks.clear();
}

void CniNetworkPlugin::PlatformInit(Errors &error)
{
    char *tpath { nullptr };
    char *serr { nullptr };
    tpath = look_path(std::string("nsenter").c_str(), &serr);
    if (tpath == nullptr) {
        error.SetError(serr);
        free(serr);
        return;
    }
    m_nsenterPath = tpath;
    free(tpath);
}

auto CniNetworkPlugin::GetCNIConfFiles(const std::string &pluginDir, std::vector<std::string> &vect_files, Errors &err)
-> int
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

auto CniNetworkPlugin::LoadCNIConfigFileList(const std::string &elem, struct cni_network_list_conf **n_list) -> int
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

auto CniNetworkPlugin::InsertConfNameToAllPanes(struct cni_network_list_conf *n_list, std::set<std::string> &allPanes,
                                                Errors &err) -> int
{
    int ret { 0 };
    std::string confName;

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

void CniNetworkPlugin::GetDefaultCNINetwork(const std::string &confDir, std::vector<std::string> &binDirs, Errors &err)
{
    std::vector<std::string> files;
    std::vector<std::unique_ptr<CNINetwork>> mutlNets;
    char *default_net_name = nullptr;
    std::string message = { "" };

    if (GetCNIConfFiles(confDir, files, err) != 0) {
        goto free_out;
    }

    sort(files.begin(), files.end());
    for (const auto &elem : files) {
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
        DEBUG("parse cni network: %s", n_list->name);

        if (default_net_name == nullptr) {
            SetDefaultNetwork(std::unique_ptr<CNINetwork>(new (std::nothrow) CNINetwork(n_list->name, n_list)), binDirs, err);
            default_net_name = util_strdup_s(n_list->name);
            message += default_net_name;
            continue;
        }
        if (strcmp(default_net_name, n_list->name) == 0) {
            WARN("Use same name of default net: %s", default_net_name);
            free_cni_network_list_conf(n_list);
            n_list = nullptr;
            continue;
        }
        mutlNets.push_back(std::unique_ptr<CNINetwork>(new (std::nothrow) CNINetwork(n_list->name, n_list)));
        message += ", " + std::string(n_list->name);
    }
    if (default_net_name == nullptr) {
        err.Errorf("No valid networks found in %s", confDir.c_str());
        goto free_out;
    }
    UpdateMutlNetworks(mutlNets, binDirs, err);
    if (err.NotEmpty()) {
        goto free_out;
    }
    INFO("Loaded cni plugins successfully, [ %s ]", message.c_str());

free_out:
    free(default_net_name);
    return;
}

void CniNetworkPlugin::CheckInitialized(Errors &err)
{
    RLockNetworkMap(err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetCMessage());
        return;
    }
    bool inited = (m_defaultNetwork != nullptr);
    UnlockNetworkMap(err);
    if (!inited) {
        err.AppendError("cni config uninitialized");
    }
}

void CniNetworkPlugin::SyncNetworkConfig()
{
    Errors err;
    GetDefaultCNINetwork(m_confDir, m_binDirs, err);
    if (err.NotEmpty()) {
        WARN("Unable to update cni config: %s", err.GetCMessage());
    }
}

void CniNetworkPlugin::Init(const std::string &hairpinMode,
                            const std::string &nonMasqueradeCIDR, int mtu, Errors &error)
{
    UNUSED(hairpinMode);
    UNUSED(nonMasqueradeCIDR);
    UNUSED(mtu);

    PlatformInit(error);
    if (error.NotEmpty()) {
        return;
    }
    SyncNetworkConfig();

    // start a thread to sync network config from confDir periodically to detect network config updates in every 5 seconds
    m_syncThread = std::thread([&]() {
        UpdateDefaultNetwork();
    });
}

auto CniNetworkPlugin::Name() const -> const std::string &
{
    return CNI_PLUGIN_NAME;
}

void CniNetworkPlugin::Status(Errors &err)
{
    CheckInitialized(err);
}

// return: represent need rollback
bool CniNetworkPlugin::SetupMultNetworks(const std::string &ns, const std::string &defaultInterface,
                                         const std::string &name,
                                         const std::string &netnsPath, const std::string &podSandboxID,
                                         const std::map<std::string, std::string> &annotations,
                                         const std::map<std::string, std::string> &options, Errors &err)
{
    int defaultIdx = -1;
    size_t len = 0;
    struct result *preResult = nullptr;
    CNINetwork *useDefaultNet = nullptr;
    bool ret = true;
    cri_pod_network_element **networks = CRIHelpers::GetNetworkPlaneFromPodAnno(annotations, &len, err);
    if (err.NotEmpty()) {
        ERROR("Couldn't get network plane from pod annotations: %s", err.GetCMessage());
        err.Errorf("Couldn't get network plane from pod annotations: %s", err.GetCMessage());
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        if (networks[i] == nullptr || networks[i]->name == nullptr || networks[i]->interface == nullptr) {
            continue;
        }
        auto netIter = m_mutlNetworks.find(networks[i]->name);
        if (netIter == m_mutlNetworks.end()) {
            err.Errorf("Cannot found user defined net: %s", networks[i]->name);
            goto cleanup;
        }
        if (defaultInterface == networks[i]->interface) {
            defaultIdx = i;
            continue;
        }
        AddToNetwork((netIter->second).get(), name, ns, networks[i]->interface, podSandboxID, netnsPath, annotations, options,
                     &preResult, err);
        free_result(preResult);
        preResult = nullptr;
        if (err.NotEmpty()) {
            ERROR("Do setup user defined net: %s, failed: %s", networks[i]->name, err.GetCMessage());
            goto cleanup;
        }
        INFO("Setup user defined net: %s success", networks[i]->name);
    }

    useDefaultNet = m_defaultNetwork.get();
    // mask default network pod, if user defined net use same interface
    if (defaultIdx >= 0) {
        auto netIter = m_mutlNetworks.find(networks[defaultIdx]->name);
        if (netIter == m_mutlNetworks.end()) {
            err.Errorf("Cannot default net: %s", networks[defaultIdx]->name);
            goto cleanup;
        }
        useDefaultNet = (netIter->second).get();
    }
    AddToNetwork(useDefaultNet, name, ns, defaultInterface, podSandboxID, netnsPath, annotations, options, &preResult, err);
    free_result(preResult);
    if (err.NotEmpty()) {
        ERROR("Setup default net failed: %s", err.GetCMessage());
        goto cleanup;
    }
    INFO("Setup default net: %s success", useDefaultNet->GetName().c_str());
    ret = false;
cleanup:
    free_cri_pod_network(networks, len);
    return ret;
}

auto CniNetworkPlugin::GetNetNS(const std::string &podSandboxID, Errors &err) -> std::string
{
    int ret = 0;
    char fullpath[PATH_MAX] { 0 };
    std::string result;
    const std::string NetNSFmt { "/proc/%d/ns/net" };

    container_inspect *inspect_data = CRIHelpers::InspectContainer(podSandboxID, err, false);
    if (inspect_data == nullptr) {
        goto cleanup;
    }
    if (inspect_data->state->pid == 0) {
        err.Errorf("cannot find network namespace for the terminated container %s", podSandboxID.c_str());
        goto cleanup;
    }
    ret = snprintf(fullpath, sizeof(fullpath), NetNSFmt.c_str(), inspect_data->state->pid);
    if ((size_t)ret >= sizeof(fullpath) || ret < 0) {
        err.SetError("Sprint nspath failed");
        goto cleanup;
    }
    result = fullpath;

cleanup:
    free_container_inspect(inspect_data);
    return result;
}


void CniNetworkPlugin::SetUpPod(const std::string &ns, const std::string &name, const std::string &interfaceName,
                                const std::string &id, const std::map<std::string, std::string> &annotations,
                                const std::map<std::string, std::string> &options, Errors &err)
{
    CheckInitialized(err);
    if (err.NotEmpty()) {
        return;
    }

    auto iter = annotations.find(CRIHelpers::Constants::POD_SANDBOX_KEY);
    if (iter == annotations.end()) {
        ERROR("Failed to find sandbox key from annotations");
        return;
    }
    const std::string netnsPath = iter->second;
    if (netnsPath.length() == 0) {
        ERROR("Failed to get network namespace path");
        return;
    }

    if (m_loNetwork != nullptr) {
        struct result *preResult = nullptr;
        AddToNetwork(m_loNetwork.get(), name, ns, interfaceName, id, netnsPath, annotations, options, &preResult, err);
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

    bool needRollback = SetupMultNetworks(ns, interfaceName, name, netnsPath, id, annotations, options, err);
    if (needRollback && err.NotEmpty()) {
        Errors tmpErr;
        TearDownMultNetworks(ns, interfaceName, name, netnsPath, id, annotations, tmpErr);
        if (tmpErr.NotEmpty()) {
            err.AppendError(tmpErr.GetMessage());
        }
    }
    UnlockNetworkMap(err);
}

void CniNetworkPlugin::TearDownMultNetworks(const std::string &ns, const std::string &defaultInterface,
                                            const std::string &name,
                                            const std::string &netnsPath, const std::string &podSandboxID, const std::map<std::string, std::string> &annotations,
                                            Errors &err)
{
    int defaultIdx = -1;
    size_t len = 0;
    CNINetwork *useDefaultNet = nullptr;
    Errors tmpErr;
    cri_pod_network_element **networks = CRIHelpers::GetNetworkPlaneFromPodAnno(annotations, &len, err);
    if (err.NotEmpty()) {
        ERROR("Couldn't get network plane from pod annotations: %s", err.GetCMessage());
        err.Errorf("Couldn't get network plane from pod annotations: %s", err.GetCMessage());
        return;
    }

    for (size_t i = 0; i < len; i++) {
        if (networks[i] == nullptr || networks[i]->name == nullptr || networks[i]->interface == nullptr) {
            continue;
        }
        auto netIter = m_mutlNetworks.find(networks[i]->name);
        if (netIter == m_mutlNetworks.end()) {
            WARN("Cannot found user defined net: %s", networks[i]->name);
            continue;
        }
        if (defaultInterface == networks[i]->interface) {
            defaultIdx = i;
            continue;
        }
        DeleteFromNetwork((netIter->second).get(), name, ns, networks[i]->interface, podSandboxID, netnsPath, annotations,
                          tmpErr);
        if (tmpErr.NotEmpty()) {
            ERROR("Do teardown user defined net: %s, failed: %s", networks[i]->name, tmpErr.GetCMessage());
            err.AppendError(tmpErr.GetMessage());
            tmpErr.Clear();
            continue;
        }
        INFO("Teardown user defained net: %s success", networks[i]->name);
    }

    useDefaultNet = m_defaultNetwork.get();
    // mask default network pod, if user defined net use same interface
    if (defaultIdx >= 0) {
        auto netIter = m_mutlNetworks.find(networks[defaultIdx]->name);
        if (netIter == m_mutlNetworks.end()) {
            err.Errorf("Cannot found user defined net: %s", networks[defaultIdx]->name);
            goto cleanup;
        }
        useDefaultNet = (netIter->second).get();
    }
    DeleteFromNetwork(useDefaultNet, name, ns, defaultInterface, podSandboxID, netnsPath, annotations, tmpErr);
    if (tmpErr.NotEmpty()) {
        ERROR("Teardown default net: %s, failed: %s", useDefaultNet->GetName().c_str(), tmpErr.GetCMessage());
        err.AppendError(tmpErr.GetMessage());
        goto cleanup;
    }
    INFO("Teardown default net: %s success", useDefaultNet->GetName().c_str());

cleanup:
    free_cri_pod_network(networks, len);
}

void CniNetworkPlugin::TearDownPod(const std::string &ns, const std::string &name, const std::string &interfaceName,
                                   const std::string &id, const std::map<std::string, std::string> &annotations,
                                   Errors &err)
{
    CheckInitialized(err);
    if (err.NotEmpty()) {
        return;
    }
    Errors tmpErr;

    auto iter = annotations.find(CRIHelpers::Constants::POD_SANDBOX_KEY);
    if (iter == annotations.end()) {
        ERROR("Failed to find sandbox key from annotations");
        return;
    }
    std::string netnsPath = iter->second;
    if (netnsPath.length() == 0) {
        ERROR("Failed to get network namespace path");
        return;
    }

    // When netns file does not exist, netnsPath is assigned to an
    // empty string so that lxc can handle the path properly
    if (!util_file_exists(netnsPath.c_str())) {
        netnsPath = "";
    }

    RLockNetworkMap(err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetCMessage());
        return;
    }

    TearDownMultNetworks(ns, interfaceName, name, netnsPath, id, annotations, err);
    if (err.NotEmpty()) {
        WARN("Teardown user defined networks failed: %s", err.GetCMessage());
    }

    UnlockNetworkMap(err);
}

auto CniNetworkPlugin::Capabilities() -> std::map<int, bool> *
{
    return m_noop.Capabilities();
}

void CniNetworkPlugin::SetPodCidr(const std::string &podCidr)
{
    Errors err;

    WLockNetworkMap(err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetCMessage());
        return;
    }

    if (!m_podCidr.empty()) {
        WARN("Ignoring subsequent pod CIDR update to %s", podCidr.c_str());
        goto unlock_out;
    }

    m_podCidr = podCidr;

unlock_out:
    UnlockNetworkMap(err);
}

void CniNetworkPlugin::Event(const std::string &name, std::map<std::string, std::string> &details)
{
    if (name != CRIHelpers::Constants::NET_PLUGIN_EVENT_POD_CIDR_CHANGE) {
        return;
    }

    auto iter = details.find(CRIHelpers::Constants::NET_PLUGIN_EVENT_POD_CIDR_CHANGE_DETAIL_CIDR);
    if (iter == details.end()) {
        WARN("%s event didn't contain pod CIDR", CRIHelpers::Constants::NET_PLUGIN_EVENT_POD_CIDR_CHANGE.c_str());
        return;
    }

    SetPodCidr(iter->second);
}

void CniNetworkPlugin::GetPodNetworkStatus(const std::string & /*ns*/, const std::string & /*name*/,
                                           const std::string &interfaceName, const std::string &podSandboxID,
                                           PodNetworkStatus &status, Errors &err)
{
    std::string netnsPath;
    std::vector<std::string> ips;
    Errors tmpErr;

    if (podSandboxID.empty()) {
        err.SetError("Empty podsandbox ID");
        goto out;
    }

    netnsPath = GetNetNS(podSandboxID, tmpErr);
    if (tmpErr.NotEmpty()) {
        err.Errorf("CNI failed to retrieve network namespace path: %s", tmpErr.GetCMessage());
        goto out;
    }
    if (netnsPath.empty()) {
        err.Errorf("Cannot find the network namespace, skipping pod network status for container %s",
                   podSandboxID.c_str());
        goto out;
    }
    GetPodIP(m_nsenterPath, netnsPath, interfaceName, ips, err);
    if (err.NotEmpty()) {
        ERROR("GetPodIP failed: %s", err.GetCMessage());
        goto out;
    }
    status.SetIPs(ips);

out:
    INFO("Get pod: %s network status success", podSandboxID.c_str());
}

void CniNetworkPlugin::AddToNetwork(CNINetwork *snetwork, const std::string &podName, const std::string &podNamespace,
                                    const std::string &interfaceName, const std::string &podSandboxID,
                                    const std::string &podNetnsPath,
                                    const std::map<std::string, std::string> &annotations,
                                    const std::map<std::string, std::string> &options, struct result **presult,
                                    Errors &err)
{
    struct runtime_conf *rc {
        nullptr
    };

    if (snetwork == nullptr || presult == nullptr) {
        err.Errorf("Invalid arguments");
        ERROR("Invalid arguments");
        return;
    }

    BuildCNIRuntimeConf(podName, podNamespace, interfaceName, podSandboxID, podNetnsPath, annotations, options, &rc,
                        err);
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

void CniNetworkPlugin::DeleteFromNetwork(CNINetwork *network, const std::string &podName,
                                         const std::string &podNamespace, const std::string &interfaceName,
                                         const std::string &podSandboxID, const std::string &podNetnsPath,
                                         const std::map<std::string, std::string> &annotations, Errors &err)
{
    struct runtime_conf *rc {
        nullptr
    };

    if (network == nullptr) {
        err.Errorf("Invalid arguments");
        ERROR("Invalid arguments");
        return;
    }
    std::map<std::string, std::string> options;
    BuildCNIRuntimeConf(podName, podNamespace, interfaceName, podSandboxID, podNetnsPath, annotations, options, &rc,
                        err);
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

static bool CheckCNIArgValue(const std::string &val)
{
    if (val.find(';') != std::string::npos) {
        return false;
    }
    if (std::count(val.begin(), val.end(), '=') != 1) {
        return false;
    }
    return true;
}

static void GetExtensionCNIArgs(const std::map<std::string, std::string> &annotations,
                                std::map<std::string, std::string> &args)
{
    // get cni multinetwork extension
    auto iter = annotations.find(CRIHelpers::Constants::CNI_MUTL_NET_EXTENSION_KEY);
    if (iter != annotations.end()) {
        // args value must do not have ';'
        if (iter->second.find(';') != std::string::npos) {
            WARN("Ignore: invalid multinetwork cni args: %s", iter->second.c_str());
        } else {
            args[CRIHelpers::Constants::CNI_MUTL_NET_EXTENSION_ARGS_KEY] = iter->second;
        }
    }

    for (const auto &work : annotations) {
        if (work.first.find(CRIHelpers::Constants::CNI_ARGS_EXTENSION_PREFIX_KEY) != 0) {
            continue;
        }
        if (!CheckCNIArgValue(work.second)) {
            WARN("Ignore: invalid extension cni args: %s", work.second.c_str());
            continue;
        }
        auto strs = CXXUtils::Split(work.second, '=');
        iter = args.find(strs[0]);
        if (iter != args.end()) {
            WARN("Ignore: Same key cni args: %s", work.second.c_str());
            continue;
        }
        args[strs[0]] = strs[1];
    }
}

static void PrepareRuntimeConf(const std::string &podName, const std::string &podNs, const std::string &interfaceName,
                               const std::string &podSandboxID, const std::string &podNetnsPath,
                               const std::map<std::string, std::string> &annotations,
                               const std::map<std::string, std::string> &options, struct runtime_conf **cni_rc,
                               Errors &err)
{
    size_t workLen = 5;
    std::map<std::string, std::string> cniArgs;

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

    auto iter = options.find("UID");
    std::string podUID;
    if (iter != options.end()) {
        podUID = iter->second;
    }

    cniArgs["K8S_POD_UID"] = podUID;
    cniArgs["IgnoreUnknown"] = "1";
    cniArgs["K8S_POD_NAMESPACE"] = podNs;
    cniArgs["K8S_POD_NAME"] = podName;
    cniArgs["K8S_POD_INFRA_CONTAINER_ID"] = podSandboxID;

    GetExtensionCNIArgs(annotations, cniArgs);
    workLen = cniArgs.size();

    rt->args = (char *(*)[2])util_common_calloc_s(sizeof(char *) * 2 * workLen);
    if (rt->args == nullptr) {
        ERROR("Out of memory");
        err.SetError("Out of memory");
        free_runtime_conf(rt);
        return;
    }
    rt->args_len = workLen;

    workLen = 0;
    for (const auto &work : cniArgs) {
        rt->args[workLen][0] = util_strdup_s(work.first.c_str());
        rt->args[workLen][1] = util_strdup_s(work.second.c_str());
        workLen++;
    }

    *cni_rc = rt;
}

void CniNetworkPlugin::BuildCNIRuntimeConf(const std::string &podName, const std::string &podNs,
                                           const std::string &interfaceName, const std::string &podSandboxID,
                                           const std::string &podNetnsPath,
                                           const std::map<std::string, std::string> &annotations,
                                           const std::map<std::string, std::string> &options,
                                           struct runtime_conf **cni_rc, Errors &err)
{
    PrepareRuntimeConf(podName, podNs, interfaceName, podSandboxID, podNetnsPath, annotations, options, cni_rc, err);
    if (err.NotEmpty()) {
        return;
    }
    struct runtime_conf *rt = *cni_rc;
    *cni_rc = nullptr;

    auto iter = annotations.find(CRIHelpers::Constants::POD_CHECKPOINT_KEY);
    std::string jsonCheckpoint;
    if (iter != annotations.end()) {
        jsonCheckpoint = iter->second;
    }
    DEBUG("add checkpoint: %s", jsonCheckpoint.c_str());

    std::vector<CRI::PortMapping> portMappings;
    INFO("Got netns path %s", podNetnsPath.c_str());
    INFO("Using podns path %s", podNs.c_str());

    if (!jsonCheckpoint.empty()) {
        CRI::PodSandboxCheckpoint checkpoint;
        CRIHelpers::GetCheckpoint(jsonCheckpoint, checkpoint, err);
        if (err.NotEmpty() || checkpoint.GetData() == nullptr) {
            err.Errorf("could not retrieve port mappings: %s", err.GetCMessage());
            goto free_out;
        }
        std::copy(checkpoint.GetData()->GetPortMappings().begin(), checkpoint.GetData()->GetPortMappings().end(),
                  std::back_inserter(portMappings));
    }

    if (!portMappings.empty()) {
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
        for (const auto &portMapping : portMappings) {
            if ((portMapping.GetHostPort() != nullptr) && *(portMapping.GetHostPort()) <= 0) {
                continue;
            }
            rt->p_mapping[rt->p_mapping_len] =
                (struct cni_port_mapping *)util_common_calloc_s(sizeof(struct cni_port_mapping));
            if (rt->p_mapping[rt->p_mapping_len] == nullptr) {
                err.SetError("Out of memory");
                goto free_out;
            }
            if (portMapping.GetHostPort() != nullptr) {
                rt->p_mapping[rt->p_mapping_len]->host_port = *(portMapping.GetHostPort());
            }
            if (portMapping.GetContainerPort() != nullptr) {
                rt->p_mapping[rt->p_mapping_len]->container_port = *(portMapping.GetContainerPort());
            }
            if (portMapping.GetProtocol() != nullptr) {
                rt->p_mapping[rt->p_mapping_len]->protocol = util_strings_to_lower(portMapping.GetProtocol()->c_str());
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
        error.Errorf("Failed to get read lock");
        ERROR("Get read lock failed: %s", strerror(ret));
    }
}

void CniNetworkPlugin::WLockNetworkMap(Errors &error)
{
    int ret = pthread_rwlock_wrlock(&m_netsLock);
    if (ret != 0) {
        error.Errorf("Failed to get write lock");
        ERROR("Get write lock failed: %s", strerror(ret));
    }
}

void CniNetworkPlugin::UnlockNetworkMap(Errors &error)
{
    int ret = pthread_rwlock_unlock(&m_netsLock);
    if (ret != 0) {
        error.Errorf("Failed to unlock");
        ERROR("Unlock failed: %s", strerror(ret));
    }
}

void CniNetworkPlugin::UpdateDefaultNetwork()
{
    const int defaultSyncConfigCnt = 5;
    const int defaultSyncConfigPeriod = 1000;

    pthread_setname_np(pthread_self(), "CNIUpdater");

    while (true) {
        for (int i = 0; i < defaultSyncConfigCnt; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(defaultSyncConfigPeriod));
            if (m_needFinish) {
                return;
            }
        }
        SyncNetworkConfig();
    }
}

} // namespace Network
