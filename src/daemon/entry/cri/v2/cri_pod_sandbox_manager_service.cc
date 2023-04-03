/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-01-28
 * Description: provide cri pod sandbox manager service implementation
 *********************************************************************************/
#include "cri_pod_sandbox_manager_service.h"
#include <google/protobuf/util/json_util.h>
#include <sys/mount.h>
#include "isula_libutils/log.h"
#include "isula_libutils/host_config.h"
#include "isula_libutils/container_config.h"
#include "isula_libutils/sandbox_config.h"
#include "checkpoint_handler.h"
#include "utils.h"
#include "cri_helpers.h"
#include "cri_security_context.h"
#include "cri_constants.h"
#include "naming.h"
#include "service_container_api.h"
#include "cxxutils.h"
#include "network_namespace.h"
#include "cri_image_manager_service_impl.h"
#include "namespace.h"
#include "callback.h"

namespace CRI {
void PodSandboxManagerService::ApplySandboxResources(const runtime::v1alpha2::LinuxPodSandboxConfig * /*lc*/,
                                                     host_config *hc, Errors & /*error*/)
{
    hc->oom_score_adj = CRI::Constants::PodInfraOOMAdj;
    hc->memory_swap = CRI::Constants::DefaultMemorySwap;
    hc->cpu_shares = CRI::Constants::DefaultSandboxCPUshares;
}
 
void PodSandboxManagerService::SetHostConfigDefaultValue(host_config *hc)
{
    free(hc->network_mode);
    hc->network_mode = util_strdup_s(CRI::Constants::namespaceModeCNI.c_str());
}

auto PodSandboxManagerService::ParseCheckpointProtocol(runtime::v1alpha2::Protocol protocol) -> std::string
{
    switch (protocol) {
        case runtime::v1alpha2::UDP:
            return "udp";
        case runtime::v1alpha2::TCP:
        default:
            return "tcp";
    }
}

void PodSandboxManagerService::ConstructPodSandboxCheckpoint(const runtime::v1alpha2::PodSandboxConfig &config,
                                                             CRI::PodSandboxCheckpoint &checkpoint)
{
    checkpoint.SetName(config.metadata().name());
    checkpoint.SetNamespace(config.metadata().namespace_());
    checkpoint.SetData(new CRI::CheckpointData);

    int len = config.port_mappings_size();
    for (int i = 0; i < len; i++) {
        CRI::PortMapping item;

        const runtime::v1alpha2::PortMapping &iter = config.port_mappings(i);
        item.SetProtocol(ParseCheckpointProtocol(iter.protocol()));
        item.SetContainerPort(iter.container_port());
        item.SetHostPort(iter.host_port());
        (checkpoint.GetData())->InsertPortMapping(item);
    }
    if (config.linux().security_context().namespace_options().network() == runtime::v1alpha2::NamespaceMode::NODE) {
        (checkpoint.GetData())->SetHostNetwork(true);
    }
}

void PodSandboxManagerService::SetNetworkReady(const std::string &podSandboxID, bool ready, Errors &error)
{
    std::lock_guard<std::mutex> lockGuard(m_networkReadyLock);

    m_networkReady[podSandboxID] = ready;
}

auto PodSandboxManagerService::GetNetworkReady(const std::string &podSandboxID, Errors &error) -> bool
{
    std::lock_guard<std::mutex> lockGuard(m_networkReadyLock);

    bool ready { false };
    auto iter = m_networkReady.find(podSandboxID);
    if (iter != m_networkReady.end()) {
        ready = iter->second;
    } else {
        error.Errorf("Do not find network: %s", podSandboxID.c_str());
    }

    return ready;
}

void PodSandboxManagerService::ClearNetworkReady(const std::string &podSandboxID)
{
    std::lock_guard<std::mutex> lockGuard(m_networkReadyLock);

    auto iter = m_networkReady.find(podSandboxID);
    if (iter != m_networkReady.end()) {
        m_networkReady.erase(iter);
    }
}

void PodSandboxManagerService::AddPodSandboxCheckpoint(const runtime::v1alpha2::PodSandboxConfig &config,
                                                       sandbox_config *sandboxconf, Errors &error)
{
    CRI::PodSandboxCheckpoint checkpoint;
    std::string jsonCheckpoint;

    ConstructPodSandboxCheckpoint(config, checkpoint);
    jsonCheckpoint = CRIHelpers::CreateCheckpoint(checkpoint, error);
    if (error.NotEmpty()) {
        return;
    }

    sandboxconf->checkpoint = util_strdup_s(jsonCheckpoint.c_str());
}

void PodSandboxManagerService::ApplySandboxLinuxOptions(const runtime::v1alpha2::PodSandboxConfig &config,
                                                        host_config *hostconf, sandbox_config *sandboxconf, Errors &error)
{
    const runtime::v1alpha2::LinuxPodSandboxConfig &lc = config.linux();
    CRISecurity::ApplySandboxSecurityContext(lc, sandboxconf, hostconf, error);
    if (error.NotEmpty()) {
        return;
    }

    if (!lc.cgroup_parent().empty()) {
        hostconf->cgroup_parent = util_strdup_s(lc.cgroup_parent().c_str());
    }
    int len = lc.sysctls_size();
    if (len <= 0) {
        return;
    }

    if (len > LIST_SIZE_MAX) {
        error.Errorf("Too many sysctls, the limit is %d", LIST_SIZE_MAX);
        return;
    }
    hostconf->sysctls = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if (hostconf->sysctls == nullptr) {
        error.SetError("Out of memory");
        return;
    }

    auto iter = lc.sysctls().begin();
    while (iter != lc.sysctls().end()) {
        if (append_json_map_string_string(hostconf->sysctls, iter->first.c_str(), iter->second.c_str()) != 0) {
            error.SetError("Failed to append sysctl");
            return;
        }
        ++iter;
    }
}

void PodSandboxManagerService::MakeIsuladSandboxConfig(const runtime::v1alpha2::PodSandboxConfig &config,
                                                       const std::string &runtimeHandler,
                                                       const std::string &sandboxId, host_config **hostconfig,
                                                       sandbox_config **custom_config, Errors &error)
{
    host_config *hostconf = nullptr;
    sandbox_config *sandboxconf = nullptr;
    CRI::PodSandboxCheckpoint checkpoint;
    // TODO: Need to add checkpoint here as well

    hostconf = (host_config *)util_common_calloc_s(sizeof(host_config));
    if (hostconf == nullptr) {
        error.SetError("Out of memory");
        goto error_out;
    }

    sandboxconf = (sandbox_config *)util_common_calloc_s(sizeof(sandbox_config));
    if (sandboxconf == nullptr) {
        error.SetError("Out of memory");
        goto error_out;
    }

    sandboxconf->id = util_strdup_s(sandboxId.c_str());

    sandboxconf->labels = CRIHelpers::MakeLabels(config.labels(), error);
    if (error.NotEmpty()) {
        goto error_out;
    }

    sandboxconf->annotations = CRIHelpers::MakeAnnotations(config.annotations(), error);
    if (error.NotEmpty()) {
        goto error_out;
    }

    if (config.has_metadata()) {
        sandboxconf->metadata_namespace = util_strdup_s(config.metadata().namespace_().c_str());
        sandboxconf->metadata_name = util_strdup_s(config.metadata().name().c_str());
        sandboxconf->metadata_uid = util_strdup_s(config.metadata().uid().c_str());
        sandboxconf->metadata_attempt = config.metadata().attempt();
    }

    if (!config.hostname().empty()) {
        sandboxconf->hostname = util_strdup_s(config.hostname().c_str());
    }

    // TODO: Set correct network namespace by config
    SetHostConfigDefaultValue(hostconf);

    // Currently only default value
    ApplySandboxResources(config.has_linux() ? &config.linux() : nullptr, hostconf, error);
    if (error.NotEmpty()) {
        return;
    }

    if (config.has_linux()) {
        ApplySandboxLinuxOptions(config, hostconf, sandboxconf, error);
        if (error.NotEmpty()) {
            goto error_out;
        }
    }

    AddPodSandboxCheckpoint(config, sandboxconf, error);
    if (error.NotEmpty()) {
        goto error_out;
    }

    hostconf->runtime = util_strdup_s(runtimeHandler.c_str());

    *hostconfig = hostconf;
    *custom_config = sandboxconf;
    return;

error_out:
    free_host_config(hostconf);
    free_sandbox_config(sandboxconf);
}

auto PodSandboxManagerService::NewSandboxNetNS(std::string &sandbox_netns) -> int
{
    std::string netns_str;
    int nret = 0;
    char random[NETNS_LEN + 1] = { 0x00 };
    char netns[PATH_MAX] = { 0x00 };
    const char *netns_fmt = RUNPATH"/netns/isulacni-%s";

    nret = util_generate_random_str(random, NETNS_LEN);
    if (nret != 0) {
        ERROR("Failed to generate random netns");
        return -1;
    }

    nret = snprintf(netns, sizeof(netns), netns_fmt, random);
    if (nret < 0 || (size_t)nret >= sizeof(netns)) {
        ERROR("snprintf netns failed");
        return -1;
    }

    sandbox_netns = std::string(netns);

    return 0;
}

auto PodSandboxManagerService::CreateNetworkNamespace(std::string &netns) -> int
{
    int ret = NewSandboxNetNS(netns);
    if (ret != 0) {
        ERROR("Failed to generate sandbox key");
        return -1;
    }

    if (create_network_namespace_file(netns.c_str()) != 0) {
        ERROR("Failed to create network namespace");
        return -1;
    }

    return 0;
}

void PodSandboxManagerService::SetupPodSandboxCNINetwork(const runtime::v1alpha2::PodSandboxConfig &config,
                                                         const std::string &sandbox_id, sandbox_config *sandboxconfig,
                                                         std::string &netns, std::map<std::string, std::string> &stdAnnos,
                                                         Errors &error)
{
    std::map<std::string, std::string> networkOptions;
    std::string network_settings_json;

    CRIHelpers::ProtobufAnnoMapToStd(config.annotations(), stdAnnos);
    stdAnnos[CRIHelpers::Constants::POD_CHECKPOINT_KEY] = std::string(sandboxconfig->checkpoint);
    stdAnnos.insert(std::pair<std::string, std::string>(CRIHelpers::Constants::POD_SANDBOX_KEY, netns));
    networkOptions["UID"] = std::string(sandboxconfig->metadata_uid);

    if (prepare_network_namespace(netns.c_str(), false, 0) != 0) {
        error.Errorf("Failed to prepare network namespace: %s", netns.c_str());
        ERROR("Failed to prepare network namespace: %s", netns.c_str());
        return;
    }

    // Setup networking for the sandbox.
    m_pluginManager->SetUpPod(config.metadata().namespace_(), config.metadata().name(),
                              Network::DEFAULT_NETWORK_INTERFACE_NAME, sandbox_id, stdAnnos, networkOptions,
                              network_settings_json, error);
    if (error.NotEmpty()) {
        ERROR("SetupPod failed: %s", error.GetCMessage());
        return;
    }

    sandboxconfig->network_settings = util_strdup_s(network_settings_json.c_str());
}

void PodSandboxManagerService::SetupPodSandboxNetwork(const runtime::v1alpha2::PodSandboxConfig &config,
                                                      const std::string &sandbox_id, host_config *hostconfig,
                                                      sandbox_config *sandboxconfig, std::map<std::string, std::string> &stdAnnos,
                                                      Errors &error)
{
    std::string netns;
    std::string network_mode(hostconfig->network_mode);

    if (network_mode == CRI::Constants::namespaceModeCNI) {
        int ret = CreateNetworkNamespace(netns);
        if (ret != 0) {
            error.Errorf("Failed to create network namesapce");
            return;
        }
        SetupPodSandboxCNINetwork(config, sandbox_id, sandboxconfig, netns, stdAnnos, error);
        sandboxconfig->netns_path = util_strdup_s(netns.c_str());
    } else if (network_mode != CRI::Constants::namespaceModeHost){
        error.Errorf("Network mode is neither host nor cni");
        ERROR("Network mode is neither host nor cni");
    }
}

void PodSandboxManagerService::ClearPodSandboxNetwork(const host_config *hostconf, const sandbox_config *sandboxconf,
                                                      const std::string &sandbox_id, std::vector<std::string> &errlist)
{
    Errors networkErr;
    std::string network_mode(hostconf->network_mode);
    bool ready = GetNetworkReady(sandbox_id, networkErr);
    parser_error perr = NULL;
    // TODO: Make network_settings generic
    container_network_settings *network_settings = NULL;
    std::map<std::string, std::string> stdAnnos;

    if (network_mode != CRI::Constants::namespaceModeHost && (ready || networkErr.NotEmpty())) {
        Errors pluginErr;
        if (sandboxconf != NULL && sandboxconf->network_settings != NULL) {
            network_settings = container_network_settings_parse_data(sandboxconf->network_settings, NULL, &perr);
        }
        if (network_settings == NULL) {
            ERROR("Parse network settings failed: %s", perr);
            goto out;
        }
        std::string netnsPath = std::string(network_settings->sandbox_key);
        for (size_t i = 0; i < sandboxconf->annotations->len; i++) {
            stdAnnos.insert(std::pair<std::string, std::string>(sandboxconf->annotations->keys[i],
                                                                sandboxconf->annotations->values[i]));
        }
        stdAnnos.insert(std::pair<std::string, std::string>(CRIHelpers::Constants::POD_SANDBOX_KEY, netnsPath));
        m_pluginManager->TearDownPod(netnsPath, sandboxconf->metadata_name, Network::DEFAULT_NETWORK_INTERFACE_NAME,
                                     sandbox_id, stdAnnos, pluginErr);
        if (pluginErr.NotEmpty()) {
            WARN("TearDownPod cni network failed: %s", pluginErr.GetCMessage());
            errlist.push_back(pluginErr.GetMessage());
        } else {
            INFO("TearDownPod cni network: success");
            SetNetworkReady(sandbox_id, false, pluginErr);
            if (pluginErr.NotEmpty()) {
                WARN("set network ready: %s", pluginErr.GetCMessage());
            }
            // umount netns when cni removed network successfully
            if (remove_network_namespace(netnsPath.c_str()) != 0) {
                ERROR("Failed to umount directory %s:%s", netnsPath.c_str(), strerror(errno));
            }
        }
    }
out:
    free(perr);
    free_container_network_settings(network_settings);
}

auto PodSandboxManagerService::GenerateSandboxIdentity(const runtime::v1alpha2::PodSandboxConfig &config, std::string &name,
                                                       std::string &sandboxId, Errors &error) -> int
{
    int ret = 0;
    sandbox_allocate_id_response *response = nullptr;
    sandbox_allocate_id_request *request = (sandbox_allocate_id_request *)util_common_calloc_s(sizeof(*request));
    if (request == nullptr) {
        error.Errorf("Out of memory");
        return -1;
    }

    std::string sandboxName = CRINaming::MakeSandboxName(config.metadata());
    request->name = util_strdup_s(sandboxName.c_str());
    if (m_cb->sandbox.allocate_id(request, &response) != 0) {
        if (response != nullptr && (response->errmsg != nullptr)) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to generate identity for sandbox");
        }
        ret = -1;
        goto error_out;
    }
    name = std::move(sandboxName);
    sandboxId = response->id;

error_out:
    free_sandbox_allocate_id_request(request);
    free_sandbox_allocate_id_response(response);
    return ret;
}

sandbox_create_request *
PodSandboxManagerService::GenerateSandboxCreateRequest(const runtime::v1alpha2::PodSandboxConfig &config,
                                                       const std::string &runtimeHandler,
                                                       const std::string &sandboxName, const std::string &sandboxId,
                                                       const host_config *hostconfig, const sandbox_config *custom_config,
                                                       Errors &error)
{
    std::string configStr;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error perror = nullptr;
    sandbox_create_request *create_request = (sandbox_create_request *)util_common_calloc_s(sizeof(*create_request));
    if (create_request == nullptr) {
        error.Errorf("Out of memory");
        return nullptr;
    }

    create_request->name = util_strdup_s(sandboxName.c_str());
    create_request->id = util_strdup_s(sandboxId.c_str());
    // TODO: analyze what to do for "untrusted workload", reference to what containerd does
    if (!runtimeHandler.empty()) {
        create_request->runtime = util_strdup_s(runtimeHandler.c_str());
    }
    // TODO: Figure out how to convert message to json string
    google::protobuf::util::MessageToJsonString(config, &configStr);
    create_request->pod_config_option = util_strdup_s(configStr.c_str());

    create_request->isulad_host_config = host_config_generate_json(hostconfig, &ctx, &perror);
    if (create_request->isulad_host_config == nullptr) {
        error.Errorf("Failed to generate host config json: %s", perror);
        goto error_out;
    }
    create_request->isulad_sandbox_config = sandbox_config_generate_json(custom_config, &ctx, &perror);
    if (create_request->isulad_sandbox_config == nullptr) {
        error.Errorf("Failed to generate custom config json: %s", perror);
        goto error_out;
    }

    return create_request;

error_out:
    free_sandbox_create_request(create_request);
    return nullptr;
}

void PodSandboxManagerService::CreateSandbox(const runtime::v1alpha2::PodSandboxConfig &config,
                                             const std::string &runtimeHandler, const std::string& sandboxName,
                                             const std::string &sandboxId, Errors &error)
{
    host_config *hostconfig = nullptr;
    sandbox_config *custom_config = nullptr;
    std::map<std::string, std::string> stdAnnos;
    sandbox_create_request *create_request = nullptr;
    sandbox_create_response *create_response = nullptr;
    std::vector<std::string> errlist;

    MakeIsuladSandboxConfig(config, runtimeHandler, sandboxId, &hostconfig, &custom_config, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    SetupPodSandboxNetwork(config, sandboxId, hostconfig, custom_config, stdAnnos, error);
    if (error.NotEmpty()) {
        // TODO: Is it necessary to clear sandbox after creation?
        goto cleanup_network;
    }

    create_request = GenerateSandboxCreateRequest(config, runtimeHandler, sandboxName, sandboxId,
                                                  hostconfig, custom_config, error);
    if (create_request == nullptr) {
        if (error.Empty()) {
            error.SetError("Failed to generate sandbox create request");
        }
        goto cleanup_network;
    }

    if (m_cb->sandbox.create(create_request, &create_response) != 0) {
        if (create_response != nullptr && (create_response->errmsg != nullptr)) {
            error.SetError(create_response->errmsg);
        } else {
            error.SetError("Failed to call create sandbox callback");
        }
        goto cleanup_network;
    }
    goto cleanup;

cleanup_network:
    ClearPodSandboxNetwork(hostconfig, custom_config, sandboxId, errlist);
cleanup:
    free_host_config(hostconfig);
    free_sandbox_config(custom_config);
    free_sandbox_create_request(create_request);
    free_sandbox_create_response(create_response);
}

void PodSandboxManagerService::StartSandbox(const std::string &sandbox_id, Errors &error)
{
    sandbox_start_response *start_response = nullptr;
    sandbox_start_request *start_request = (sandbox_start_request *)util_common_calloc_s(sizeof(*start_request));
    if (start_request == nullptr) {
        error.Errorf("Out of memory");
        return;
    }
    start_request->id = util_strdup_s(sandbox_id.c_str());
    if (m_cb->sandbox.start(start_request, &start_response) != 0) {
        if (start_response != nullptr && (start_response->errmsg != nullptr)) {
            error.SetError(start_response->errmsg);
        } else {
            error.SetError("Failed to call run sandbox callback");
        }
    }

    free_sandbox_start_request(start_request);
    free_sandbox_start_response(start_response);
}

auto PodSandboxManagerService::RunPodSandbox(const runtime::v1alpha2::PodSandboxConfig &config,
                                             const std::string &runtimeHandler, Errors &error) -> std::string
{
    std::string sandboxName;
    std::string sandboxId;

    if (m_cb == nullptr || m_cb->sandbox.allocate_id == nullptr || 
        m_cb->sandbox.create == nullptr || m_cb->sandbox.start == nullptr) {
        error.SetError("Unimplemented callback");
        return sandboxId;
    }

    // 1. Generate sandbox name and id
    if (GenerateSandboxIdentity(config, sandboxName, sandboxId, error) != 0) {
        // Error has been set
        goto cleanup;
    }

    // 2. Disable network
    SetNetworkReady(sandboxId, false, error);
    if (error.NotEmpty()) {
        WARN("disable network: %s", error.GetCMessage());
        error.Clear();
    }

    // 3. Create sandbox
    CreateSandbox(config, runtimeHandler, sandboxName, sandboxId, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    // 4. Start sandbox
    StartSandbox(sandboxId, error);
    // TODO: Is it necessary to clear sandbox after creation?

cleanup:
    if (error.Empty()) {
        SetNetworkReady(sandboxId, true, error);
        DEBUG("set %s ready", sandboxId.c_str());
        error.Clear();
    }
    return sandboxId;
}

sandbox_stop_request *PodSandboxManagerService::GenerateSandboxStopRequest(const std::string &realPodSandboxID, Errors &error){
    sandbox_stop_request *stop_request = (sandbox_stop_request *)util_common_calloc_s(sizeof(*stop_request));
    if (stop_request == nullptr) {
        error.Errorf("Out of memory");
        return nullptr;
    }
    stop_request->id = util_strdup_s(realPodSandboxID.c_str());    
    return stop_request;
}

int PodSandboxManagerService::StopAllContainersInSandbox(const std::string &realSandboxID, Errors &error)
{
    int ret = 0;
    container_list_request *list_request = nullptr;
    container_list_response *list_response = nullptr;

    if (m_cb==nullptr || m_cb->container.list == nullptr) {
        error.SetError("Unimplemented callback");
        return -1;
    }

    // list all containers to stop
    list_request = (container_list_request *)util_common_calloc_s(sizeof(container_list_request));
    if (list_request == nullptr) {
        error.SetError("Out of memory");
        return -1;
    }
    list_request->all = true;

    list_request->filters = (defs_filters *)util_common_calloc_s(sizeof(defs_filters));
    if (list_request->filters == nullptr) {
        error.SetError("Out of memory");
        ret = -1;
        goto cleanup;
    }

    // Add sandbox label
    if (CRIHelpers::FiltersAddLabel(list_request->filters, CRIHelpers::Constants::SANDBOX_ID_LABEL_KEY,
                                    realSandboxID) != 0) {
        error.SetError("Failed to add label");
        ret = -1;
        goto cleanup;
    }

    ret = m_cb->container.list(list_request, &list_response);
    if (ret != 0) {
        if (list_response != nullptr && list_response->errmsg != nullptr) {
            error.SetError(list_response->errmsg);
        } else {
            error.SetError("Failed to call list container callback");
        }
        ret = -1;
        goto cleanup;
    }
    // Remove all containers in the sandbox.
    for (size_t i = 0; i < list_response->containers_len; i++) {
        Errors stopError;
        CRIHelpers::StopContainer(m_cb, list_response->containers[i]->id, 0, stopError);
        if (stopError.NotEmpty() && !CRIHelpers::IsContainerNotFoundError(stopError.GetMessage())) {
            ERROR("Error stop container: %s: %s", list_response->containers[i]->id, stopError.GetCMessage());
            error.SetError(stopError.GetMessage());
            ret = -1;
            goto cleanup;
        }
    }
cleanup:
    free_container_list_request(list_request);
    free_container_list_response(list_response);
    return ret;
}

sandbox_inspect_request *PodSandboxManagerService::GenerateSandboxInspectRequest(const std::string &podSandboxID, Errors &error){
    sandbox_inspect_request *inspect_request = (sandbox_inspect_request *)util_common_calloc_s(sizeof(*inspect_request));
    if (inspect_request == nullptr) {
        error.Errorf("Out of memory");
        return nullptr;
    }
    inspect_request->id_or_name = util_strdup_s(podSandboxID.c_str());
    return inspect_request;
}

sandbox_inspect_response *PodSandboxManagerService::InspectSandbox(const std::string &realPodSandboxID, Errors &error)
{
    sandbox_inspect_request *inspect_request = { nullptr };
    sandbox_inspect_response *inspect_response = { nullptr };

    inspect_request = PodSandboxManagerService::GenerateSandboxInspectRequest(realPodSandboxID, error);
    if (inspect_request == nullptr || error.NotEmpty()){
        ERROR("Failed to make an inspect request for sandbox %s", realPodSandboxID.c_str());
        goto clean;
    }
    if (m_cb->sandbox.inspect(inspect_request, &inspect_response) != 0){
        if (inspect_response != nullptr || inspect_response->errmsg != nullptr) {
            ERROR("Unable to inspect Sandbox, %s", inspect_response->errmsg);
            error.Errorf("Unable to inspect Sandbox, %s", inspect_response->errmsg);
        } else {
            ERROR("Unable to inspect Sandbox");
            error.Errorf("Unable to inspect Sandbox");
        }
        free_sandbox_inspect_response(inspect_response);
        inspect_response = nullptr;
        goto clean;
    }
clean:
    free_sandbox_inspect_request(inspect_request);
    return inspect_response;
}

void PodSandboxManagerService::StopPodSandbox(const std::string &podSandboxID, Errors &error)
{   
    std::vector<std::string> errlist;
    sandbox_inspect_response *inspect_response = nullptr;
    sandbox_stop_response *stop_response = nullptr;
    sandbox_stop_request *stop_request = nullptr; 
    
    std::string realPodSandboxID = CRIHelpers::GetRealSandboxID(m_cb, podSandboxID, error);
    if (error.NotEmpty()) {
        ERROR("Failed to find sandbox id %s: %s", podSandboxID.c_str(), error.GetCMessage());
        goto clean;
    }

    stop_request = GenerateSandboxStopRequest(realPodSandboxID, error);
    if (error.NotEmpty()){
        ERROR("Failed to make a SandboxStop requiest sandbox id %s: %s", podSandboxID.c_str(), error.GetCMessage());
        goto clean;
    }

    INFO("Stop sandbox %s", podSandboxID.c_str());
    
    if (PodSandboxManagerService::StopAllContainersInSandbox(realPodSandboxID, error) != 0){
        ERROR("Failed to stop containers in sandbox %s", podSandboxID.c_str());
        goto clean;
    }

    inspect_response = PodSandboxManagerService::InspectSandbox(realPodSandboxID, error);
    if (inspect_response == nullptr) {
        goto clean;
    }

    PodSandboxManagerService::ClearPodSandboxNetwork(inspect_response->isulad_host_config, inspect_response->isulad_sandbox_config, realPodSandboxID, errlist);
    if (!errlist.empty()){
        ERROR("Unable to clear PodSandboxNetwork");
        error.SetAggregate(errlist);
        // TODO: Should isulad continue to stop sandbox even if clear network failed?
        goto clean;
    }
    
    if (m_cb->sandbox.stop(stop_request, &stop_response) != 0) {
        if (stop_response != NULL && stop_response->errmsg != NULL) {
            ERROR("Failed to stop sandbox %s: %s", podSandboxID.c_str(), stop_response->errmsg);
            error.Errorf("Failed to stop sandbox %s: %s", podSandboxID.c_str(), stop_response->errmsg);
        } else {
            ERROR("Failed to stop sandbox %s", podSandboxID.c_str());
            error.Errorf("Failed to stop sandbox %s", podSandboxID.c_str());
        }
        goto clean;
    }
    INFO("Sandbox %s was successefully stopped", podSandboxID.c_str());
clean:
    free_sandbox_inspect_response(inspect_response);
    free_sandbox_stop_request(stop_request);
    free_sandbox_stop_response(stop_response);
}


auto PodSandboxManagerService::RemoveAllContainersInSandbox(const std::string &realSandboxID,
                                                            std::vector<std::string> &errors) -> int
{
    int ret = 0;
    container_list_request *list_request { nullptr };
    container_list_response *list_response { nullptr };

    if (m_cb == nullptr || m_cb->container.list == nullptr) {
        errors.push_back("Unimplemented callback");
        return -1;
    }

    // list all containers to stop
    list_request = (container_list_request *)util_common_calloc_s(sizeof(container_list_request));
    if (list_request == nullptr) {
        errors.push_back("Out of memory");
        return -1;
    }
    list_request->all = true;

    list_request->filters = (defs_filters *)util_common_calloc_s(sizeof(defs_filters));
    if (list_request->filters == nullptr) {
        errors.push_back("Out of memory");
        ret = -1;
        goto cleanup;
    }

    // Add sandbox label
    if (CRIHelpers::FiltersAddLabel(list_request->filters, CRIHelpers::Constants::SANDBOX_ID_LABEL_KEY,
                                    realSandboxID) != 0) {
        errors.push_back("Faild to add label");
        ret = -1;
        goto cleanup;
    }

    ret = m_cb->container.list(list_request, &list_response);
    if (ret != 0) {
        if (list_response != nullptr && list_response->errmsg != nullptr) {
            errors.push_back(list_response->errmsg);
        } else {
            errors.push_back("Failed to call list container callback");
        }
    }

    // Remove all containers in the sandbox.
    for (size_t i = 0; list_response != nullptr && i < list_response->containers_len; i++) {
        Errors rmError;
        CRIHelpers::RemoveContainer(m_cb, list_response->containers[i]->id, rmError);
        if (rmError.NotEmpty() && !CRIHelpers::IsContainerNotFoundError(rmError.GetMessage())) {
            ERROR("Error remove container: %s: %s", list_response->containers[i]->id, rmError.GetCMessage());
            errors.push_back(rmError.GetMessage());
        }
    }
cleanup:
    free_container_list_request(list_request);
    free_container_list_response(list_response);
    return ret;
}

int PodSandboxManagerService::DoRemovePodSandbox(const std::string &realSandboxID, std::vector<std::string> &errors)
{
    int ret = 0;
    sandbox_remove_request *remove_request { nullptr };
    sandbox_remove_response *remove_response { nullptr };

    if (m_cb == nullptr || m_cb->sandbox.remove == nullptr) {
        errors.push_back("Unimplemented callback");
        return -1;
    }

    remove_request = (sandbox_remove_request *)util_common_calloc_s(sizeof(sandbox_remove_request));
    if (remove_request == nullptr) {
        errors.push_back("Out of memory");
        return -1;
    }
    remove_request->id = util_strdup_s(realSandboxID.c_str());
    remove_request->force = true;

    ret = m_cb->sandbox.remove(remove_request, &remove_response);
    if (ret == 0) {
        // Only clear network ready when the sandbox has actually been
        // removed from docker or doesn't exist
        ClearNetworkReady(realSandboxID);
    } else {
        if (remove_response != nullptr && (remove_response->errmsg != nullptr)) {
            errors.push_back(remove_response->errmsg);
        } else {
            errors.push_back("Failed to call remove container callback");
        }
        ret = -1;
    }
    free_sandbox_remove_request(remove_request);
    free_sandbox_remove_response(remove_response);
    return ret;
}


void PodSandboxManagerService::RemovePodSandbox(const std::string &podSandboxID, Errors &error)
{
    std::vector<std::string> errors;

    std::string realPodSandboxID;
    if (podSandboxID.empty()) {
        errors.push_back("Invalid empty sandbox id.");
        goto cleanup;
    }
    // TODO: Check sandbox status first
    realPodSandboxID = CRIHelpers::GetRealSandboxID(m_cb, podSandboxID, error);
    if (error.NotEmpty()) {
        ERROR("Failed to find sandbox id %s", podSandboxID.c_str());
        goto cleanup;
    }

    // TODO: What if sandbox is still running?
    if (RemoveAllContainersInSandbox(realPodSandboxID, errors) != 0) {
        goto cleanup;
    }

    if (DoRemovePodSandbox(realPodSandboxID, errors) != 0) {
        goto cleanup;
    }

cleanup:
    error.SetAggregate(errors);
}

sandbox_status_request *PodSandboxManagerService::GenerateSandboxStatusRequest(const std::string &podSandboxID, bool verbose, Errors &error)
{
    sandbox_status_request *status_request = (sandbox_status_request *)util_common_calloc_s(sizeof(*status_request));
    if (status_request == nullptr) {
        error.Errorf("Out of memory");
        return nullptr;
    }
    status_request->id = util_strdup_s(podSandboxID.c_str());   
    status_request->verbose = verbose;
    return status_request;
}

auto PodSandboxManagerService::SharesHostPid(const sandbox_inspect_response *inspect) -> runtime::v1alpha2::NamespaceMode
{
    if (inspect != nullptr && inspect->isulad_host_config != nullptr && (inspect->isulad_host_config->pid_mode != nullptr) &&
        std::string(inspect->isulad_host_config->pid_mode) == CRI::Constants::namespaceModeHost) {
        return runtime::v1alpha2::NamespaceMode::NODE;
    }
    // TODO investigate Namespace type correctnes
    return runtime::v1alpha2::NamespaceMode::POD;
}

auto PodSandboxManagerService::SharesHostIpc(const sandbox_inspect_response *inspect) -> runtime::v1alpha2::NamespaceMode
{
    if (inspect != nullptr && inspect->isulad_host_config != nullptr && (inspect->isulad_host_config->ipc_mode != nullptr) &&
        std::string(inspect->isulad_host_config->ipc_mode) == CRI::Constants::namespaceModeHost) {
        return runtime::v1alpha2::NamespaceMode::NODE;
    }
    // TODO investigate Namespace type correctnes
    return runtime::v1alpha2::NamespaceMode::POD;
}

auto PodSandboxManagerService::SharesHostNetwork(const sandbox_inspect_response *inspect) -> runtime::v1alpha2::NamespaceMode
{
    if (inspect != nullptr && inspect->isulad_host_config != nullptr && (inspect->isulad_host_config->network_mode != nullptr) &&
        std::string(inspect->isulad_host_config->network_mode) == CRI::Constants::namespaceModeHost) {
        return runtime::v1alpha2::NamespaceMode::NODE;
    }
    // TODO investigate Namespace type correctnes
    return runtime::v1alpha2::NamespaceMode::POD;
}

void PodSandboxManagerService::SetSandboxMetadata(runtime::v1alpha2::PodSandboxMetadata* podMetadata,
                                                  sandbox_config *config)
{
    podMetadata->set_name(config->metadata_name);
    podMetadata->set_uid(config->metadata_uid);
    podMetadata->set_attempt(config->metadata_attempt);
    podMetadata->set_namespace_(config->metadata_namespace);
}

void PodSandboxManagerService::GetIPs(const std::string &podSandboxID, const sandbox_inspect_response *inspect_response, std::vector<std::string> &ips, Errors &error)
{
    // TODO need refactoring
    if (inspect_response == nullptr) {
        return;
    }

    bool ready = GetNetworkReady(podSandboxID, error);
    if (error.Empty() && !ready) {
        WARN("Network %s is not ready", podSandboxID.c_str());
        return;
    }

    if (inspect_response->isulad_sandbox_config->network_settings == NULL ) {
        WARN("inspect network is empty");
        return;
    }
    // TODO fix IP problems later.
}

void PodSandboxManagerService::SetSandboxStatusNetwork(const sandbox_inspect_response *inspect_response,
                                                       const std::string &podSandboxID,
                                                       std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> &podStatus,
                                                       Errors &error)
{
    std::vector<std::string> ips;
    GetIPs(podSandboxID, inspect_response, ips, error);
    if (ips.size() == 0) {
        return;
    }
    podStatus->mutable_network()->set_ip(ips[0]);
    for (size_t i = 1; i < ips.size(); i++) {
        auto tPoint = podStatus->mutable_network()->add_additional_ips();
        tPoint->set_ip(ips[i]);
    }
}

auto PodSandboxManagerService::PodSandboxStatus(const std::string &podSandboxID, Errors &error) 
                -> std::unique_ptr<runtime::v1alpha2::PodSandboxStatus>
{
    bool verbose = true;
    std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> podStatus(new runtime::v1alpha2::PodSandboxStatus);
    runtime::v1alpha2::NamespaceOption *options { nullptr };
    sandbox_inspect_response *inspect_response { nullptr };
    sandbox_status_request *status_request { nullptr };
    sandbox_status_response *status_response { nullptr };

    std::string realPodSandboxID = CRIHelpers::GetRealSandboxID(m_cb, podSandboxID, error);
    if (error.NotEmpty()) {
        ERROR("Failed to inspect Sandbox %s", realPodSandboxID.c_str());
        goto clean;
    }
    // TODO: Is it possible to inspect without GetRealSandboxID.
    //       The inspect function should be able to sandbox id at same time
    // Why?
    inspect_response = PodSandboxManagerService::InspectSandbox(realPodSandboxID, error);
    if (error.NotEmpty() || inspect_response == nullptr) {
        ERROR("Failed to inspect Sandbox %s", realPodSandboxID.c_str());
        goto clean;
    }

    status_request = GenerateSandboxStatusRequest(realPodSandboxID, verbose, error);
    if (error.NotEmpty() || status_request == nullptr) {
        ERROR("Failed to make status request for Sandbox %s", realPodSandboxID.c_str());
        goto clean;
    }

    if (m_cb->sandbox.status(status_request, &status_response) != 0) {
        ERROR("Failed get status of sandbox  %s", podSandboxID.c_str());
        error.Errorf("Failed get status of sandbox  %s", podSandboxID.c_str());
        goto clean;
    }

    podStatus->set_id(status_response->status->id);
    options = podStatus->mutable_linux()->mutable_namespaces()->mutable_options();
    options->set_pid(SharesHostPid(inspect_response));
    options->set_ipc(SharesHostIpc(inspect_response));
    options->set_network(SharesHostNetwork(inspect_response));
    if (strcmp(status_response->status->state,"READY") != 0){
        podStatus->set_state(runtime::v1alpha2::SANDBOX_NOTREADY);
    } else {
        podStatus->set_state(runtime::v1alpha2::SANDBOX_READY);
    }
    SetSandboxMetadata(podStatus->mutable_metadata(), inspect_response->isulad_sandbox_config);
    podStatus->set_created_at(status_response->status->created_at);
    podStatus->set_runtime_handler(inspect_response->isulad_host_config->runtime);
    CRIHelpers::ExtractLabels(inspect_response->isulad_sandbox_config->labels, *podStatus->mutable_labels());
    CRIHelpers::ExtractAnnotations(inspect_response->isulad_sandbox_config->annotations, *podStatus->mutable_annotations());
    SetSandboxStatusNetwork(inspect_response, realPodSandboxID, podStatus, error);
    if (error.NotEmpty()) {
        ERROR("Set network status failed: %s", error.GetCMessage());
    }
clean:
    free_sandbox_status_request(status_request);
    free_sandbox_status_response(status_response);
    free_sandbox_inspect_response(inspect_response);
    return podStatus;
}

void PodSandboxManagerService::ListPodSandboxToGRPC(sandbox_list_response *response,
                                                    std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods,
                                                    Errors &error)
{
    for (size_t i = 0; i < response->sandboxes_len; i++) {
        if (response->sandboxes[i] == nullptr) {
            continue;
        }
        std::unique_ptr<runtime::v1alpha2::PodSandbox> pod(new runtime::v1alpha2::PodSandbox);

        if (response->sandboxes[i]->id != nullptr) {
            pod->set_id(response->sandboxes[i]->id);
        }
        if (response->sandboxes[i]->ready) {
            pod->set_state(runtime::v1alpha2::SANDBOX_READY);
        } else {
            pod->set_state(runtime::v1alpha2::SANDBOX_NOTREADY);
        }
        pod->set_created_at(response->sandboxes[i]->created_at);

        CRIHelpers::ExtractLabels(response->sandboxes[i]->labels, *pod->mutable_labels());

        CRIHelpers::ExtractAnnotations(response->sandboxes[i]->annotations, *pod->mutable_annotations());

        runtime::v1alpha2::PodSandboxMetadata *metadata = pod->mutable_metadata();
        metadata->set_name(response->sandboxes[i]->metadata_name);
        metadata->set_namespace_(response->sandboxes[i]->metadata_namespace);
        metadata->set_uid(response->sandboxes[i]->metadata_uid);
        metadata->set_attempt(response->sandboxes[i]->metadata_attempt);

        pods->push_back(std::move(pod));
    }
}

// TODO: filter is ignored at the moment
void PodSandboxManagerService::ListPodSandbox(const runtime::v1alpha2::PodSandboxFilter *filter,
                    std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods, Errors &error)
{
    int ret = 0;
    sandbox_list_request *request { nullptr };
    sandbox_list_response *response { nullptr };

    if (m_cb == nullptr || m_cb->sandbox.list == nullptr) {
        error.SetError("Unimplemented callback");
        return;
    }

    request = (sandbox_list_request *)util_common_calloc_s(sizeof(sandbox_list_request));
    if (request == nullptr) {
        error.SetError("Out of memory");
        return;

    }

    ret = m_cb->sandbox.list(request, &response);
    if (ret != 0) {
        if (response != nullptr && (response->errmsg != nullptr)) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call start container callback");
        }
        goto cleanup;
    }

    ListPodSandboxToGRPC(response, pods, error);
cleanup:
    free_sandbox_list_request(request);
    free_sandbox_list_response(response);
}

void PodSandboxManagerService::PortForward(const runtime::v1alpha2::PortForwardRequest &req,
                                           runtime::v1alpha2::PortForwardResponse *resp,
                                           Errors &error)
{
    error.Errorf("PortForward unimplemented");
}

} // namespace CRI
