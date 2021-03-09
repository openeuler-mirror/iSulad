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

#include <isula_libutils/log.h>
#include <isula_libutils/cni_anno_port_mappings.h>
#include <isula_libutils/cni_ip_ranges_array.h>
#include <isula_libutils/cni_bandwidth_entry.h>
#include "cri_helpers.h"
#include "cxxutils.h"
#include "utils.h"
#include "errors.h"
#include "service_container_api.h"
#include "service_network_api.h"
#include "network_namespace_api.h"
#include "network_api.h"
#include "err_msg.h"

namespace Network {

void ProbeNetworkPlugins(const std::string &pluginDir, const std::string &binDir,
                         std::vector<std::shared_ptr<NetworkPlugin>> *plugins)
{
    const std::string useBinDir = binDir.empty() ? DEFAULT_CNI_DIR : binDir;
    std::vector<std::string> binDirs = CXXUtils::Split(useBinDir, ',');
    auto plugin = std::make_shared<CniNetworkPlugin>(binDirs, pluginDir);
    plugins->push_back(plugin);
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
}

void CniNetworkPlugin::SyncNetworkConfig()
{
    Errors err;
    WLockNetworkMap(err);
    if (err.NotEmpty()) {
        return;
    }

    if (network_module_update(NETWOKR_API_TYPE_CRI) != 0) {
        err.SetError("update cni conf list failed");
    }

    UnlockNetworkMap(err);
    if (err.NotEmpty()) {
        WARN("Unable to update cni config: %s", err.GetCMessage());
    }
}

void CniNetworkPlugin::Init(const std::string &hairpinMode, const std::string &nonMasqueradeCIDR, int mtu,
                            Errors &error)
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

void CniNetworkPlugin::CheckInitialized(Errors &err)
{
    RLockNetworkMap(err);
    if (err.NotEmpty()) {
        return;
    }

    if (!network_module_ready(NETWOKR_API_TYPE_CRI)) {
        err.SetError("cni config uninitialized");
    }

    UnlockNetworkMap(err);
    if (err.NotEmpty()) {
        WARN("Unable to update cni config: %s", err.GetCMessage());
    }
}

void CniNetworkPlugin::Status(Errors &err)
{
    CheckInitialized(err);
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
        if (!CheckCNIArgValue(iter->second)) {
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
        iter = annotations.find(work.first);
        if (iter != annotations.end()) {
            WARN("Ignore: Same key cni args: %s", work.first.c_str());
            continue;
        }
        args[strs[0]] = strs[1];
    }
}

static void PrepareAdaptorArgs(const std::string &podName, const std::string &podNs, const std::string &podSandboxID,
                               const std::map<std::string, std::string> &annotations, const std::map<std::string, std::string> &options,
                               network_api_conf *config, Errors &err)
{
    size_t workLen;
    std::map<std::string, std::string> cniArgs;

    auto iter = options.find("UID");
    std::string podUID { "" };
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

    config->args = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if (config->args == nullptr) {
        ERROR("Out of memory");
        goto err_out;
    }
    config->args->keys = (char **)util_smart_calloc_s(sizeof(char *), workLen);
    if (config->args->keys == nullptr) {
        ERROR("Out of memory");
        goto err_out;
    }
    config->args->values = (char **)util_smart_calloc_s(sizeof(char *), workLen);
    if (config->args->values == nullptr) {
        ERROR("Out of memory");
        goto err_out;
    }

    workLen = 0;
    for (const auto &work : cniArgs) {
        config->args->keys[workLen] = util_strdup_s(work.first.c_str());
        config->args->values[workLen] = util_strdup_s(work.second.c_str());
        config->args->len += 1;
        workLen++;
    }
    return;
err_out:
    err.SetError("prepare network api config failed");
}

static void PrepareAdaptorAttachNetworks(const std::map<std::string, std::string> &annotations,
                                         network_api_conf *config, Errors &err)
{
    cri_pod_network_container *networks = CRIHelpers::GetNetworkPlaneFromPodAnno(annotations, err);
    if (err.NotEmpty()) {
        ERROR("Couldn't get network plane from pod annotations: %s", err.GetCMessage());
        err.SetError("Prepare Adaptor Attach Networks failed");
        goto free_out;
    }
    if (networks == nullptr) {
        goto free_out;
    }
    config->extral_nets = (struct attach_net_conf **)util_smart_calloc_s(sizeof(struct attach_net_conf *), networks->len);
    if (config->extral_nets == nullptr) {
        ERROR("Out of memory");
        err.SetError("Prepare Adaptor Attach Networks failed");
        goto free_out;
    }

    for (size_t i = 0; i < networks->len; i++) {
        if (networks->items[i] == nullptr || networks->items[i]->name == nullptr || networks->items[i]->interface == nullptr) {
            continue;
        }
        config->extral_nets[i] = (struct attach_net_conf *)util_common_calloc_s(sizeof(struct attach_net_conf));
        if (config->extral_nets[i] == nullptr) {
            ERROR("Out of memory");
            err.SetError("Prepare Adaptor Attach Networks failed");
            goto free_out;
        }
        config->extral_nets[i]->name = util_strdup_s(networks->items[i]->name);
        config->extral_nets[i]->interface = util_strdup_s(networks->items[i]->interface);
        config->extral_nets_len += 1;
    }

free_out:
    free_cri_pod_network_container(networks);
}

static void InsertPortmappingIntoAdaptorAnnotations(const std::map<std::string, std::string> &annos,
                                                    network_api_conf *config, Errors &err)
{
    auto iter = annos.find(CRIHelpers::Constants::POD_CHECKPOINT_KEY);
    std::string jsonCheckpoint;

    if (iter != annos.end()) {
        jsonCheckpoint = iter->second;
    }
    if (jsonCheckpoint.empty()) {
        return;
    }
    DEBUG("add checkpoint: %s", jsonCheckpoint.c_str());

    CRI::PodSandboxCheckpoint checkpoint;
    CRIHelpers::GetCheckpoint(jsonCheckpoint, checkpoint, err);
    if (err.NotEmpty() || checkpoint.GetData() == nullptr) {
        err.Errorf("could not retrieve port mappings: %s", err.GetCMessage());
        return;
    }
    if (checkpoint.GetData()->GetPortMappings().size() == 0) {
        return;
    }

    parser_error jerr = nullptr;
    char *tmpVal = nullptr;
    size_t i = 0;
    cni_anno_port_mappings_container *cni_pms = (cni_anno_port_mappings_container *)util_common_calloc_s(sizeof(
                                                                                                             cni_anno_port_mappings_container));
    if (cni_pms == nullptr) {
        ERROR("Out of memory");
        err.SetError("Out of memory");
        goto free_out;
    }
    cni_pms->items = (cni_anno_port_mappings_element **)util_smart_calloc_s(sizeof(cni_anno_port_mappings_element *),
                                                                            checkpoint.GetData()->GetPortMappings().size());

    for (const auto &pm : checkpoint.GetData()->GetPortMappings()) {
        cni_anno_port_mappings_element *elem = (cni_anno_port_mappings_element *)util_common_calloc_s(sizeof(
                                                                                                          cni_anno_port_mappings_element));
        if (elem == nullptr) {
            ERROR("Out of memory");
            err.SetError("Out of memory");
            goto free_out;
        }
        if (pm.GetHostPort() != nullptr && *pm.GetHostPort() > 0) {
            elem->host_port = *pm.GetHostPort();
        }
        if (pm.GetContainerPort() != nullptr) {
            elem->container_port = *pm.GetContainerPort();
        }
        if (pm.GetProtocol() != nullptr) {
            elem->protocol = util_strdup_s(pm.GetProtocol()->c_str());
        }
        cni_pms->items[i++] = elem;
        cni_pms->len += 1;
    }
    tmpVal = cni_anno_port_mappings_container_generate_json(cni_pms, nullptr, &jerr);
    if (network_module_insert_portmapping(tmpVal, config) != 0) {
        err.SetError("add portmappings failed");
    }
    free(tmpVal);

free_out:
    free(jerr);
    free_cni_anno_port_mappings_container(cni_pms);
}

static void InsertBandWidthIntoAdaptorAnnotations(const std::map<std::string, std::string> &annos,
                                                  network_api_conf *config, Errors &err)
{
    cni_bandwidth_entry bandwidth { 0 };

    auto iter = annos.find(CRIHelpers::Constants::CNI_CAPABILITIES_BANDWIDTH_INGRESS_KEY);
    if (iter != annos.end()) {
        bandwidth.ingress_rate = CRIHelpers::ParseQuantity(iter->second, err);
        if (err.NotEmpty()) {
            ERROR("failed to get pod bandwidth from annotations: %s", err.GetCMessage());
            return;
        }
        bandwidth.ingress_burst = INT32_MAX;
    }
    iter = annos.find(CRIHelpers::Constants::CNI_CAPABILITIES_BANDWIDTH_ENGRESS_KEY);
    if (iter != annos.end()) {
        bandwidth.egress_rate = CRIHelpers::ParseQuantity(iter->second, err);
        if (err.NotEmpty()) {
            ERROR("failed to get pod bandwidth from annotations: %s", err.GetCMessage());
            return;
        }
        bandwidth.egress_burst = INT32_MAX;
    }
    parser_error jerr = nullptr;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY | OPT_GEN_KEY_VALUE, 0 };
    char *bandwidth_str = cni_bandwidth_entry_generate_json(&bandwidth, &ctx, &jerr);
    if (bandwidth_str == NULL) {
        ERROR("generate bandwidth json failed: %s", jerr);
        err.SetError("generate bandwidth json failed");
        goto out;
    }

    if (network_module_insert_bandwith(bandwidth_str, config) != 0) {
        err.SetError("set bandwidth for network config failed");
        goto out;
    }

out:
    free(jerr);
    free(bandwidth_str);
}

static void PrepareAdaptorAnnotations(const std::map<std::string, std::string> &annos, network_api_conf *config,
                                      Errors &err)
{
    if (config->annotations == nullptr) {
        config->annotations = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    }
    if (config->annotations == nullptr) {
        err.SetError("Out of memory");
        ERROR("Out of memory");
        return;
    }

    InsertPortmappingIntoAdaptorAnnotations(annos, config, err);
    if (err.NotEmpty()) {
        ERROR("Set port mapping failed");
        return;
    }

    InsertBandWidthIntoAdaptorAnnotations(annos, config, err);
    if (err.NotEmpty()) {
        ERROR("Set bandwidth failed");
    }
}

static void InsertIPRangesIntoAdaptorAnnotations(const std::string &podCidr, network_api_conf *config, Errors &err)
{
    cni_ip_ranges_array_container *ip_ranges = nullptr;

    if (podCidr.empty()) {
        return;
    }
    ip_ranges = static_cast<cni_ip_ranges_array_container *>(util_common_calloc_s(sizeof(cni_ip_ranges_array_container)));
    if (ip_ranges == nullptr) {
        ERROR("Out of memory");
        err.SetError("Out of memory");
        return;
    }
    parser_error jerr = nullptr;
    char *tmpVal = nullptr;

    ip_ranges->items = static_cast<cni_ip_ranges ***>(util_smart_calloc_s(sizeof(cni_ip_ranges **), 1));
    if (ip_ranges->items == nullptr) {
        ERROR("Out of memory");
        err.SetError("Out of memory");
        goto out;
    }
    ip_ranges->subitem_lens = static_cast<size_t *>(util_smart_calloc_s(sizeof(size_t), 1));
    if (ip_ranges->subitem_lens == nullptr) {
        ERROR("Out of memory");
        err.SetError("Out of memory");
        goto out;
    }
    ip_ranges->items[0] = static_cast<cni_ip_ranges **>(util_smart_calloc_s(sizeof(cni_ip_ranges *), 1));
    if (ip_ranges->items[0] == nullptr) {
        ERROR("Out of memory");
        err.SetError("Out of memory");
        goto out;
    }
    ip_ranges->items[0][0] = static_cast<cni_ip_ranges *>(util_common_calloc_s(sizeof(cni_ip_ranges)));
    if (ip_ranges->items[0][0] == nullptr) {
        ERROR("Out of memory");
        err.SetError("Out of memory");
        goto out;
    }
    ip_ranges->items[0][0]->subnet = util_strdup_s(podCidr.c_str());
    tmpVal = cni_ip_ranges_array_container_generate_json(ip_ranges, NULL, &jerr);
    if (tmpVal == nullptr) {
        ERROR("generate ip range failed: %s", jerr);
        err.SetError("generate ip range failed");
        goto out;
    }
    if (network_module_insert_iprange(tmpVal, config) != 0) {
        err.SetError("add ip ranges failed");
    }

out:
    free_cni_ip_ranges_array_container(ip_ranges);
    free(jerr);
    free(tmpVal);
}

void BuildAdaptorCNIConfig(const std::string &ns, const std::string &defaultInterface, const std::string &name,
                           const std::string &netnsPath, const std::string &podSandboxID, const std::string &podCidr,
                           const std::map<std::string, std::string> &annotations,
                           const std::map<std::string, std::string> &options, network_api_conf **api_conf, Errors &err)
{
    network_api_conf *config = nullptr;

    config = static_cast<network_api_conf *>(util_common_calloc_s(sizeof(network_api_conf)));
    if (config == nullptr) {
        ERROR("Out of memory");
        err.SetError("Out of memory");
        return;
    }

    // fill attach network names for pod
    PrepareAdaptorAttachNetworks(annotations, config, err);
    if (err.NotEmpty()) {
        goto err_out;
    }

    // fill args for cni plugin
    PrepareAdaptorArgs(name, ns, podSandboxID, annotations, options, config, err);
    if (err.NotEmpty()) {
        goto err_out;
    }

    // fill annotations for cni runtime config
    // 1. parse annotations configs(portmapping and bandwith etc..) into config;
    PrepareAdaptorAnnotations(annotations, config, err);
    // 2. parse other configs into config;
    InsertIPRangesIntoAdaptorAnnotations(podCidr, config, err);

    if (!name.empty()) {
        config->name = util_strdup_s(name.c_str());
    }
    config->ns = util_strdup_s(ns.c_str());
    config->pod_id = util_strdup_s(podSandboxID.c_str());
    config->netns_path = util_strdup_s(netnsPath.c_str());
    if (!defaultInterface.empty()) {
        config->default_interface = util_strdup_s(defaultInterface.c_str());
    }

    *api_conf = config;
    config = nullptr;
    return;
err_out:
    err.AppendError("BuildAdaptorCNIConfig failed");
    free_network_api_conf(config);
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

auto CniNetworkPlugin::GetNetworkSettingsJson(const std::string &podSandboxID, const std::string netnsPath,
                                              network_api_result_list *result, Errors &err) -> std::string
{
    std::string json;
    parser_error jerr { nullptr };
    std::unique_ptr<char> setting_json;

    if (result == nullptr) {
        ERROR("Invalid input param, no network result to set");
        return json;
    }

    container_network_settings *network_settings = static_cast<container_network_settings *>(util_common_calloc_s(sizeof(
                                                                                                                      container_network_settings)));
    if (network_settings == nullptr) {
        err.SetError("Out of memory");
        goto out;
    }

    network_settings->networks = static_cast<defs_map_string_object_networks *>(util_common_calloc_s(sizeof(
                                                                                                         defs_map_string_object_networks)));
    if (network_settings->networks == nullptr) {
        err.SetError("Out of memory");
        goto out;
    }

    if (cni_update_container_networks_info(result, podSandboxID.c_str(), netnsPath.c_str(), network_settings) != 0) {
        err.SetError("Failed to update network setting");
        goto out;
    }

    setting_json = std::unique_ptr<char>(container_network_settings_generate_json(network_settings, nullptr, &jerr));
    if (setting_json == nullptr) {
        err.Errorf("Get network settings json err:%s", jerr);
        goto out;
    }

    json = setting_json.get();

out:
    free(jerr);
    free_container_network_settings(network_settings);
    return json;
}

void CniNetworkPlugin::SetUpPod(const std::string &ns, const std::string &name, const std::string &interfaceName,
                                const std::string &id, const std::map<std::string, std::string> &annotations,
                                const std::map<std::string, std::string> &options, std::string &network_settings_json, Errors &err)
{
    DAEMON_CLEAR_ERRMSG();
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

    network_api_conf *config = nullptr;
    BuildAdaptorCNIConfig(ns, interfaceName, name, netnsPath, id, m_podCidr, annotations, options, &config, err);
    if (err.NotEmpty()) {
        ERROR("build network api config failed");
        return;
    }

    RLockNetworkMap(err);
    if (err.NotEmpty()) {
        ERROR("%s", err.GetCMessage());
        return;
    }

    // TODO: parse result of attach
    network_api_result_list *result = nullptr;
    if (network_module_attach(config, NETWOKR_API_TYPE_CRI, &result) != 0) {
        if (g_isulad_errmsg != nullptr) {
            err.SetError(g_isulad_errmsg);
        } else {
            err.Errorf("setup cni for container: %s failed", id.c_str());
        }
    }

    network_settings_json = GetNetworkSettingsJson(id, netnsPath, result, err);

    UnlockNetworkMap(err);
    free_network_api_result_list(result);
    free_network_api_conf(config);
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

    std::map<std::string, std::string> tmpOpts;
    network_api_conf *config = nullptr;
    BuildAdaptorCNIConfig(ns, interfaceName, name, netnsPath, id, m_podCidr, annotations, tmpOpts, &config, err);
    if (err.NotEmpty()) {
        ERROR("build network api config failed");
        return;
    }

    RLockNetworkMap(err);
    if (err.NotEmpty()) {
        ERROR("get lock failed: %s", err.GetCMessage());
        return;
    }

    if (network_module_detach(config, NETWOKR_API_TYPE_CRI) != 0) {
        err.Errorf("teardown cni for container: %s failed", id.c_str());
    }

    UnlockNetworkMap(err);
    free_network_api_conf(config);
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

void CheckNetworkStatus(const std::string &ns, const std::string &name, const std::string &podCidr,
                        const std::string &interfaceName, const std::string &netnsPath, const std::string &podSandboxID,
                        std::vector<std::string> &ips, Errors &err)
{
    // int network_module_check(const network_api_conf *conf, const char *type, network_api_result_list **result);
    network_api_conf *config = nullptr;
    std::map<std::string, std::string> fakeMap;
    BuildAdaptorCNIConfig(ns, interfaceName, name, netnsPath, podSandboxID, podCidr, fakeMap, fakeMap, &config, err);
    if (err.NotEmpty()) {
        ERROR("build network api config failed");
        return;
    }

    network_api_result_list *result = nullptr;
    if (err.NotEmpty()) {
        ERROR("%s", err.GetCMessage());
        goto out;
    }

    if (network_module_check(config, NETWOKR_API_TYPE_CRI, &result) != 0) {
        if (g_isulad_errmsg != nullptr) {
            err.SetError(g_isulad_errmsg);
        } else {
            err.Errorf("setup cni for container: %s failed", podSandboxID.c_str());
        }
        goto out;
    }
    for (size_t i = 0; i < result->len; i++) {
        if (result->items[i]->interface == NULL) {
            continue;
        }
        if (interfaceName != result->items[i]->interface) {
            continue;
        }
        for (size_t j = 0; j < result->items[i]->ips_len; j++) {
            ips.push_back(result->items[i]->ips[j]);
        }
        break;
    }

out:
    free_network_api_result_list(result);
    free_network_api_conf(config);
}

void CniNetworkPlugin::GetPodNetworkStatus(const std::string &ns, const std::string &name,
                                           const std::string &interfaceName, const std::string &podSandboxID,
                                           PodNetworkStatus &status, Errors &err)
{
    DAEMON_CLEAR_ERRMSG();
    std::string netnsPath;
    Errors tmpErr;

    if (podSandboxID.empty()) {
        err.SetError("Empty podsandbox ID");
        return;
    }

    // TODO: save netns path in container_t
    netnsPath = GetNetNS(podSandboxID, tmpErr);
    if (tmpErr.NotEmpty()) {
        err.Errorf("CNI failed to retrieve network namespace path: %s", tmpErr.GetCMessage());
        return;
    }
    if (netnsPath.empty()) {
        err.Errorf("Cannot find the network namespace, skipping pod network status for container %s",
                   podSandboxID.c_str());
        return;
    }
    std::vector<std::string> ips;


    RLockNetworkMap(err);
    CheckNetworkStatus(ns, name, m_podCidr, interfaceName, netnsPath, podSandboxID, ips, err);
    UnlockNetworkMap(err);

    if (err.Empty()) {
        goto out;
    }
    WARN("Get network status by check failed: %s", err.GetCMessage());
    err.Clear();

    GetPodIP(m_nsenterPath, netnsPath, interfaceName, ips, err);
    if (!err.Empty()) {
        ERROR("Get ip from plugin failed: %s", err.GetCMessage());
        return;
    }
out:
    INFO("Get pod: %s network status success", podSandboxID.c_str());
    status.SetIPs(ips);
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
