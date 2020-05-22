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
 * Description: provide cri sandbox functions
 *********************************************************************************/
#include "cri_sandbox.h"
#include "cri_runtime_service.h"

#include <vector>
#include <utility>
#include <map>
#include <sstream>
#include <iostream>
#include <memory>
#include <string>

#include <unistd.h>
#include <grpc++/grpc++.h>

#include "cxxutils.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "errors.h"
#include "naming.h"
#include "isula_libutils/host_config.h"
#include "cri_helpers.h"
#include "checkpoint_handler.h"
#include "cri_security_context.h"

runtime::v1alpha2::NamespaceMode CRIRuntimeServiceImpl::SharesHostNetwork(container_inspect *inspect)
{
    if (inspect != nullptr && inspect->host_config != nullptr && inspect->host_config->network_mode &&
        std::string(inspect->host_config->network_mode) == CRIRuntimeService::Constants::namespaceModeHost) {
        return runtime::v1alpha2::NamespaceMode::NODE;
    }
    return runtime::v1alpha2::NamespaceMode::POD;
}

runtime::v1alpha2::NamespaceMode CRIRuntimeServiceImpl::SharesHostPid(container_inspect *inspect)
{
    if (inspect != nullptr && inspect->host_config != nullptr && inspect->host_config->pid_mode &&
        std::string(inspect->host_config->pid_mode) == CRIRuntimeService::Constants::namespaceModeHost) {
        return runtime::v1alpha2::NamespaceMode::NODE;
    }
    return runtime::v1alpha2::NamespaceMode::CONTAINER;
}

runtime::v1alpha2::NamespaceMode CRIRuntimeServiceImpl::SharesHostIpc(container_inspect *inspect)
{
    if (inspect != nullptr && inspect->host_config != nullptr && inspect->host_config->ipc_mode &&
        std::string(inspect->host_config->ipc_mode) == CRIRuntimeService::Constants::namespaceModeHost) {
        return runtime::v1alpha2::NamespaceMode::NODE;
    }
    return runtime::v1alpha2::NamespaceMode::POD;
}

bool CRIRuntimeServiceImpl::EnsureSandboxImageExists(const std::string &image, Errors &error)
{
    runtime::v1alpha2::ImageSpec imageRef;
    runtime::v1alpha2::AuthConfig auth;
    runtime::v1alpha2::ImageSpec imageSpec;
    Errors err;

    imageSpec.set_image(image);
    std::unique_ptr<runtime::v1alpha2::Image> imageStatus = rImageService.ImageStatus(imageSpec, err);
    if (err.Empty()) {
        return true;
    }
    imageStatus.reset();

    imageRef.set_image(image);
    std::string outRef = rImageService.PullImage(imageRef, auth, error);
    if (!error.Empty() || outRef.empty()) {
        return false;
    }

    return true;
}

std::string CRIRuntimeServiceImpl::ParseCheckpointProtocol(runtime::v1alpha2::Protocol protocol)
{
    switch (protocol) {
        case runtime::v1alpha2::UDP:
            return "udp";
        case runtime::v1alpha2::TCP:
        default:
            return "tcp";
    }
}

void CRIRuntimeServiceImpl::ConstructPodSandboxCheckpoint(const runtime::v1alpha2::PodSandboxConfig &config,
                                                          cri::PodSandboxCheckpoint &checkpoint)
{
    checkpoint.SetName(config.metadata().name());
    checkpoint.SetNamespace(config.metadata().namespace_());
    checkpoint.SetData(new cri::CheckpointData);

    int len = config.port_mappings_size();
    for (int i = 0; i < len; i++) {
        cri::PortMapping item;

        runtime::v1alpha2::PortMapping iter = config.port_mappings(i);
        item.SetProtocol(ParseCheckpointProtocol(iter.protocol()));
        item.SetContainerPort(iter.container_port());
        item.SetHostPort(iter.host_port());
        (checkpoint.GetData())->InsertPortMapping(item);
    }
    if (config.linux().security_context().namespace_options().network() == runtime::v1alpha2::NamespaceMode::NODE) {
        (checkpoint.GetData())->SetHostNetwork(true);
    }
}

void CRIRuntimeServiceImpl::ApplySandboxResources(const runtime::v1alpha2::LinuxPodSandboxConfig *lc, host_config *hc,
                                                  Errors &error)
{
    hc->memory_swap = CRIRuntimeService::Constants::DefaultMemorySwap;
    hc->cpu_shares = CRIRuntimeService::Constants::DefaultSandboxCPUshares;
}

void CRIRuntimeServiceImpl::ApplySandboxLinuxOptions(const runtime::v1alpha2::LinuxPodSandboxConfig &lc,
                                                     host_config *hc, container_config *custom_config,
                                                     Errors &error)
{
    CRISecurity::ApplySandboxSecurityContext(lc, custom_config, hc, error);
    if (error.NotEmpty()) {
        return;
    }

    if (!lc.cgroup_parent().empty()) {
        hc->cgroup_parent = util_strdup_s(lc.cgroup_parent().c_str());
    }
    int len = lc.sysctls_size();
    if (len <= 0) {
        return;
    }

    if (len > LIST_SIZE_MAX) {
        error.Errorf("Too many sysctls, the limit is %d", LIST_SIZE_MAX);
        return;
    }
    hc->sysctls = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if (hc->sysctls == nullptr) {
        error.SetError("Out of memory");
        return;
    }

    auto iter = lc.sysctls().begin();
    while (iter != lc.sysctls().end()) {
        if (append_json_map_string_string(hc->sysctls, iter->first.c_str(), iter->second.c_str()) != 0) {
            error.SetError("Failed to append sysctl");
            return;
        }
        ++iter;
    }
}

void CRIRuntimeServiceImpl::MergeSecurityContextToHostConfig(const runtime::v1alpha2::PodSandboxConfig &c,
                                                             host_config *hc, Errors &error)
{
    // Security Opts
    if (!c.linux().has_security_context()) {
        return;
    }

    const char securityOptSep = '=';
    std::vector<std::string> securityOpts =
        CRIHelpers::GetSecurityOpts(c.linux().security_context().seccomp_profile_path(), securityOptSep, error);
    if (error.NotEmpty()) {
        error.Errorf("failed to generate security options for sandbox %s", c.metadata().name().c_str());
        return;
    }
    if (securityOpts.size() > 0) {
        char **tmp_security_opt = nullptr;

        if (securityOpts.size() > (SIZE_MAX / sizeof(char *)) - hc->security_opt_len) {
            error.Errorf("Out of memory");
            return;
        }
        size_t newSize = (hc->security_opt_len + securityOpts.size()) * sizeof(char *);
        size_t oldSize = hc->security_opt_len * sizeof(char *);
        int ret = mem_realloc((void **)(&tmp_security_opt), newSize, (void *)hc->security_opt, oldSize);
        if (ret != 0) {
            error.Errorf("Out of memory");
            return;
        }
        hc->security_opt = tmp_security_opt;
        for (size_t i = 0; i < securityOpts.size(); i++) {
            hc->security_opt[hc->security_opt_len] = util_strdup_s(securityOpts[i].c_str());
            hc->security_opt_len++;
        }
    }
}

void CRIRuntimeServiceImpl::MakeSandboxIsuladConfig(const runtime::v1alpha2::PodSandboxConfig &c, host_config *hc,
                                                    container_config *custom_config, Errors &error)
{
    custom_config->labels = CRIHelpers::MakeLabels(c.labels(), error);
    if (error.NotEmpty()) {
        return;
    }
    if (append_json_map_string_string(custom_config->labels, CRIHelpers::Constants::CONTAINER_TYPE_LABEL_KEY.c_str(),
                                      CRIHelpers::Constants::CONTAINER_TYPE_LABEL_SANDBOX.c_str()) != 0) {
        error.SetError("Append container type into labels failed");
        return;
    }

    custom_config->annotations = CRIHelpers::MakeAnnotations(c.annotations(), error);
    if (error.NotEmpty()) {
        return;
    }
    if (append_json_map_string_string(custom_config->annotations,
                                      CRIHelpers::Constants::CONTAINER_TYPE_ANNOTATION_KEY.c_str(),
                                      CRIHelpers::Constants::CONTAINER_TYPE_ANNOTATION_SANDBOX.c_str()) != 0) {
        error.SetError("Append container type into annotation failed");
        return;
    }

    if (!c.hostname().empty()) {
        custom_config->hostname = util_strdup_s(c.hostname().c_str());
    }

    if (c.has_linux()) {
        ApplySandboxLinuxOptions(c.linux(), hc, custom_config, error);
        if (error.NotEmpty()) {
            return;
        }
    }

    hc->oom_score_adj = CRIRuntimeService::Constants::PodInfraOOMAdj;

    ApplySandboxResources(c.has_linux() ? &c.linux() : nullptr, hc, error);
    if (error.NotEmpty()) {
        return;
    }

    const char securityOptSep = '=';

    // Security Opts
    if (c.linux().has_security_context()) {
        std::vector<std::string> securityOpts =
            CRIHelpers::GetSecurityOpts(c.linux().security_context().seccomp_profile_path(), securityOptSep, error);
        if (error.NotEmpty()) {
            error.Errorf("failed to generate security options for sandbox %s", c.metadata().name().c_str());
            return;
        }
        if (securityOpts.size() > 0) {
            char **tmp_security_opt = nullptr;

            if (securityOpts.size() > (SIZE_MAX / sizeof(char *)) - hc->security_opt_len) {
                error.Errorf("Out of memory");
                return;
            }
            size_t newSize = (hc->security_opt_len + securityOpts.size()) * sizeof(char *);
            size_t oldSize = hc->security_opt_len * sizeof(char *);
            int ret = mem_realloc((void **)(&tmp_security_opt), newSize, (void *)hc->security_opt, oldSize);
            if (ret != 0) {
                error.Errorf("Out of memory");
                return;
            }
            hc->security_opt = tmp_security_opt;
            for (size_t i = 0; i < securityOpts.size(); i++) {
                hc->security_opt[hc->security_opt_len] = util_strdup_s(securityOpts[i].c_str());
                hc->security_opt_len++;
            }
        }
    }
}

void CRIRuntimeServiceImpl::SetupSandboxFiles(const std::string &resolvPath,
                                              const runtime::v1alpha2::PodSandboxConfig &config, Errors &error)
{
    if (resolvPath.empty()) {
        return;
    }
    std::vector<std::string> resolvContentStrs;

    /* set DNS options */
    int len = config.dns_config().searches_size();
    if (len > CRIRuntimeService::Constants::MAX_DNS_SEARCHES) {
        error.SetError("DNSOption.Searches has more than 6 domains");
        return;
    }

    std::vector<std::string> servers(config.dns_config().servers().begin(), config.dns_config().servers().end());
    if (!servers.empty()) {
        resolvContentStrs.push_back("nameserver " + CXXUtils::StringsJoin(servers, "\nnameserver "));
    }

    std::vector<std::string> searchs(config.dns_config().searches().begin(), config.dns_config().searches().end());
    if (!searchs.empty()) {
        resolvContentStrs.push_back("search " + CXXUtils::StringsJoin(searchs, " "));
    }

    std::vector<std::string> options(config.dns_config().options().begin(), config.dns_config().options().end());
    if (!options.empty()) {
        resolvContentStrs.push_back("options " + CXXUtils::StringsJoin(options, " "));
    }

    if (!resolvContentStrs.empty()) {
        std::string resolvContent = CXXUtils::StringsJoin(resolvContentStrs, "\n") + "\n";
        if (util_write_file(resolvPath.c_str(), resolvContent.c_str(), resolvContent.size(), DEFAULT_SECURE_FILE_MODE) != 0) {
            error.SetError("Failed to write resolv content");
        }
    }
}

container_create_request *CRIRuntimeServiceImpl::PackCreateContainerRequest(
    const runtime::v1alpha2::PodSandboxConfig &config,
    const std::string &image, host_config *hostconfig,
    container_config *custom_config,
    const std::string &runtimeHandler, Errors &error)
{
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error perror = nullptr;
    container_create_request *create_request =
        (container_create_request *)util_common_calloc_s(sizeof(*create_request));
    if (create_request == nullptr) {
        error.Errorf("Out of memory");
        return nullptr;
    }

    std::string sandboxName = CRINaming::MakeSandboxName(config.metadata());
    create_request->id = util_strdup_s(sandboxName.c_str());

    if (!runtimeHandler.empty()) {
        create_request->runtime = util_strdup_s(runtimeHandler.c_str());
    }

    create_request->image = util_strdup_s(image.c_str());

    create_request->hostconfig = host_config_generate_json(hostconfig, &ctx, &perror);
    if (create_request->hostconfig == nullptr) {
        error.Errorf("Failed to generate host config json: %s", perror);
        goto error_out;
    }
    create_request->customconfig = container_config_generate_json(custom_config, &ctx, &perror);
    if (create_request->customconfig == nullptr) {
        error.Errorf("Failed to generate custom config json: %s", perror);
        goto error_out;
    }

    free(perror);
    return create_request;
error_out:
    free_container_create_request(create_request);
    free(perror);
    return nullptr;
}

container_create_request *CRIRuntimeServiceImpl::GenerateSandboxCreateContainerRequest(
    const runtime::v1alpha2::PodSandboxConfig &config,
    const std::string &image, std::string &jsonCheckpoint,
    const std::string &runtimeHandler,
    Errors &error)
{
    container_create_request *create_request = nullptr;
    host_config *hostconfig = nullptr;
    container_config *custom_config = nullptr;
    cri::PodSandboxCheckpoint checkpoint;

    hostconfig = (host_config *)util_common_calloc_s(sizeof(host_config));
    if (hostconfig == nullptr) {
        error.SetError("Out of memory");
        goto error_out;
    }

    custom_config = (container_config *)util_common_calloc_s(sizeof(container_config));
    if (custom_config == nullptr) {
        error.SetError("Out of memory");
        goto error_out;
    }

    MakeSandboxIsuladConfig(config, hostconfig, custom_config, error);
    if (error.NotEmpty()) {
        ERROR("Failed to make sandbox config for pod %s: %s", config.metadata().name().c_str(), error.GetCMessage());
        error.Errorf("Failed to make sandbox config for pod %s: %s", config.metadata().name().c_str(),
                     error.GetCMessage());
        goto error_out;
    }

    // add checkpoint into annotations
    ConstructPodSandboxCheckpoint(config, checkpoint);
    jsonCheckpoint = CRIHelpers::CreateCheckpoint(checkpoint, error);
    if (error.NotEmpty()) {
        goto error_out;
    }

    if (append_json_map_string_string(custom_config->annotations, CRIHelpers::Constants::POD_CHECKPOINT_KEY.c_str(),
                                      jsonCheckpoint.c_str()) != 0) {
        error.SetError("Append checkpoint into annotations failed");
        goto error_out;
    }

    create_request = PackCreateContainerRequest(config, image, hostconfig, custom_config, runtimeHandler, error);
    if (create_request == nullptr) {
        error.SetError("Failed to pack create container request");
        goto error_out;
    }

    goto cleanup;
error_out:
    free_container_create_request(create_request);
    create_request = nullptr;
cleanup:
    free_host_config(hostconfig);
    free_container_config(custom_config);
    return create_request;
}

std::string CRIRuntimeServiceImpl::CreateSandboxContainer(const runtime::v1alpha2::PodSandboxConfig &config,
                                                          const std::string &image, std::string &jsonCheckpoint,
                                                          const std::string &runtimeHandler,
                                                          Errors &error)
{
    std::string response_id { "" };
    container_create_request *create_request =
        GenerateSandboxCreateContainerRequest(config, image, jsonCheckpoint, runtimeHandler, error);
    if (error.NotEmpty()) {
        return response_id;
    }

    container_create_response *create_response = nullptr;
    if (m_cb->container.create(create_request, &create_response) != 0) {
        if (create_response != nullptr && create_response->errmsg) {
            error.SetError(create_response->errmsg);
        } else {
            error.SetError("Failed to call create container callback");
        }
        goto cleanup;
    }
    response_id = create_response->id;
cleanup:
    free_container_create_request(create_request);
    free_container_create_response(create_response);
    return response_id;
}

void CRIRuntimeServiceImpl::StartSandboxContainer(const std::string &response_id, Errors &error)
{
    container_start_request *start_request =
        (container_start_request *)util_common_calloc_s(sizeof(container_start_request));
    if (start_request == nullptr) {
        error.SetError("Out of memory");
        return;
    }
    start_request->id = util_strdup_s(response_id.c_str());
    container_start_response *start_response = nullptr;
    int ret = m_cb->container.start(start_request, &start_response, -1, nullptr, nullptr);
    if (ret != 0) {
        if (start_response != nullptr && start_response->errmsg) {
            error.SetError(start_response->errmsg);
        } else {
            error.SetError("Failed to call start container callback");
        }
    }
    free_container_start_request(start_request);
    free_container_start_response(start_response);
}

void CRIRuntimeServiceImpl::SetupUserDefinedNetworkPlane(const runtime::v1alpha2::PodSandboxConfig &config,
                                                         const std::string &response_id,
                                                         container_inspect *inspect_data,
                                                         std::map<std::string, std::string> &stdAnnos,
                                                         std::map<std::string, std::string> &options, Errors &error)
{
    google::protobuf::Map<std::string, std::string> annotations;
    CRIHelpers::ExtractAnnotations(inspect_data->config->annotations, annotations);

    size_t len = 0;
    cri_pod_network_element **networks = CRIHelpers::GetNetworkPlaneFromPodAnno(annotations, &len, error);
    if (error.NotEmpty()) {
        ERROR("Couldn't get network plane from pod annotations: %s", error.GetCMessage());
        error.Errorf("Couldn't get network plane from pod annotations: %s", error.GetCMessage());
        goto cleanup;
    }
    for (size_t i = 0; i < len; i++) {
        if (networks[i] && networks[i]->name && networks[i]->interface &&
            strcmp(networks[i]->name, Network::DEFAULT_NETWORK_PLANE_NAME.c_str()) != 0) {
            INFO("SetupPod net: %s", networks[i]->name);
            m_pluginManager->SetUpPod(config.metadata().namespace_(), config.metadata().name(), networks[i]->interface, response_id,
                                      stdAnnos, options, error);
            if (error.Empty()) {
                continue;
            }
            Errors tmpErr;
            StopContainerHelper(response_id, tmpErr);
            if (tmpErr.NotEmpty()) {
                WARN("Failed to stop sandbox container %s for pod %s: %s", response_id.c_str(), networks[i]->name,
                     tmpErr.GetCMessage());
            }
            goto cleanup;
        }
    }
cleanup:
    free_cri_pod_network(networks, len);
}

void CRIRuntimeServiceImpl::SetupSandboxNetwork(const runtime::v1alpha2::PodSandboxConfig &config,
                                                const std::string &response_id, const std::string &jsonCheckpoint,
                                                Errors &error)
{
    std::map<std::string, std::string> stdAnnos;
    std::map<std::string, std::string> networkOptions;

    container_inspect *inspect_data = InspectContainer(response_id, error);
    if (error.NotEmpty()) {
        return;
    }

    // Setup sandbox files
    if (config.has_dns_config() && inspect_data->resolv_conf_path != nullptr) {
        INFO("Over write resolv.conf: %s", inspect_data->resolv_conf_path);
        SetupSandboxFiles(inspect_data->resolv_conf_path, config, error);
        if (error.NotEmpty()) {
            ERROR("failed to setup sandbox files");
            goto cleanup;
        }
    }
    // Do not invoke network plugins if in hostNetwork mode.
    if (config.linux().security_context().namespace_options().network() == runtime::v1alpha2::NamespaceMode::NODE) {
        goto cleanup;
    }

    // Setup networking for the sandbox.
    CRIHelpers::ProtobufAnnoMapToStd(config.annotations(), stdAnnos);
    stdAnnos[CRIHelpers::Constants::POD_CHECKPOINT_KEY] = jsonCheckpoint;
    networkOptions["UID"] = config.metadata().uid();

    m_pluginManager->SetUpPod(config.metadata().namespace_(), config.metadata().name(),
                              Network::DEFAULT_NETWORK_INTERFACE_NAME, response_id, stdAnnos, networkOptions, error);
    if (error.NotEmpty()) {
        ERROR("SetupPod failed: %s", error.GetCMessage());
        StopContainerHelper(response_id, error);
        goto cleanup;
    }

cleanup:
    free_container_inspect(inspect_data);
}

std::string CRIRuntimeServiceImpl::RunPodSandbox(const runtime::v1alpha2::PodSandboxConfig &config,
                                                 const std::string &runtimeHandler,
                                                 Errors &error)
{
    std::string response_id;
    std::string jsonCheckpoint;
    if (m_cb == nullptr || m_cb->container.create == nullptr || m_cb->container.start == nullptr) {
        error.SetError("Unimplemented callback");
        return response_id;
    }

    // Step 1: Pull the image for the sandbox.
    const std::string &image = m_podSandboxImage;
    if (!EnsureSandboxImageExists(image, error)) {
        ERROR("Failed to pull sandbox image %s: %s", image.c_str(), error.NotEmpty() ? error.GetCMessage() : "");
        error.Errorf("Failed to pull sandbox image %s: %s", image.c_str(), error.NotEmpty() ? error.GetCMessage() : "");
        goto cleanup;
    }

    // Step 2: Create the sandbox container.
    response_id = CreateSandboxContainer(config, image, jsonCheckpoint, runtimeHandler, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    // Step 3: Enable network
    SetNetworkReady(response_id, false, error);
    if (error.NotEmpty()) {
        WARN("disable network: %s", error.GetCMessage());
        error.Clear();
    }

    // Step 4: Start the sandbox container.
    StartSandboxContainer(response_id, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }
    // Step 5: Setup networking for the sandbox.
    SetupSandboxNetwork(config, response_id, jsonCheckpoint, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

cleanup:
    if (error.Empty()) {
        SetNetworkReady(response_id, true, error);
        DEBUG("set %s ready", response_id.c_str());
        error.Clear();
    }
    return response_id;
}

int CRIRuntimeServiceImpl::GetRealSandboxIDToStop(const std::string &podSandboxID, bool &hostNetwork, std::string &name,
                                                  std::string &ns, std::string &realSandboxID,
                                                  std::map<std::string, std::string> &stdAnnos, Errors &error)
{
    Errors statusErr;

    auto status = PodSandboxStatus(podSandboxID, statusErr);
    if (statusErr.Empty()) {
        if (status->linux().namespaces().has_options()) {
            hostNetwork = (status->linux().namespaces().options().network() == runtime::v1alpha2::NamespaceMode::NODE);
        }
        if (status->has_metadata()) {
            name = status->metadata().name();
            ns = status->metadata().namespace_();
        }
        realSandboxID = status->id();
        CRIHelpers::ProtobufAnnoMapToStd(status->annotations(), stdAnnos);
    } else {
        if (CRIHelpers::IsContainerNotFoundError(statusErr.GetMessage())) {
            WARN("Both sandbox container and checkpoint for id %s could not be found. "
                 "Proceed without further sandbox information.",
                 podSandboxID.c_str());
        } else {
            error.Errorf("failed to get sandbox status: %s", statusErr.GetCMessage());
            return -1;
        }
    }
    if (realSandboxID.empty()) {
        realSandboxID = podSandboxID;
    }
    return 0;
}

int CRIRuntimeServiceImpl::StopAllContainersInSandbox(const std::string &realSandboxID, Errors &error)
{
    int ret = 0;
    container_list_request *list_request = nullptr;
    container_list_response *list_response = nullptr;

    if (m_cb == nullptr || m_cb->container.list == nullptr) {
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
        StopContainer(list_response->containers[i]->id, 0, stopError);
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

int CRIRuntimeServiceImpl::TearDownPodCniNetwork(const std::string &realSandboxID, std::vector<std::string> &errlist,
                                                 std::map<std::string, std::string> &stdAnnos, const std::string &ns,
                                                 const std::string &name, Errors &error)
{
    int ret = 0;
    cri_pod_network_element **networks = nullptr;
    container_inspect *inspect_data = InspectContainer(realSandboxID, error);
    if (inspect_data == nullptr) {
        return -1;
    }

    google::protobuf::Map<std::string, std::string> annotations;
    CRIHelpers::ExtractAnnotations(inspect_data->config->annotations, annotations);
    size_t len = 0;

    networks = CRIHelpers::GetNetworkPlaneFromPodAnno(annotations, &len, error);
    if (error.NotEmpty()) {
        ERROR("Couldn't get network plane from pod annotations: %s", error.GetCMessage());
        error.Errorf("Couldn't get network plane from pod annotations: %s", error.GetCMessage());
        ret = -1;
        goto cleanup;
    }
    for (size_t i = 0; i < len; i++) {
        if (networks[i] && networks[i]->name && networks[i]->interface &&
            strcmp(networks[i]->name, Network::DEFAULT_NETWORK_PLANE_NAME.c_str()) != 0) {
            Errors tmpErr;
            m_pluginManager->TearDownPod(ns, name, networks[i]->interface, inspect_data->id, stdAnnos, tmpErr);
            if (tmpErr.NotEmpty()) {
                WARN("TearDownPod cni network failed: %s", tmpErr.GetCMessage());
                errlist.push_back(tmpErr.GetMessage());
            }
        }
    }
cleanup:
    free_cri_pod_network(networks, len);
    free_container_inspect(inspect_data);
    return ret;
}

int CRIRuntimeServiceImpl::ClearCniNetwork(const std::string &realSandboxID, bool hostNetwork, const std::string &ns,
                                           const std::string &name, std::vector<std::string> &errlist,
                                           std::map<std::string, std::string> &stdAnnos, Errors &error)
{
    Errors networkErr;

    bool ready = GetNetworkReady(realSandboxID, networkErr);
    if (!hostNetwork && (ready || networkErr.NotEmpty())) {
        Errors pluginErr;
        m_pluginManager->TearDownPod(ns, name, Network::DEFAULT_NETWORK_INTERFACE_NAME, realSandboxID, stdAnnos, pluginErr);
        if (pluginErr.NotEmpty()) {
            WARN("TearDownPod cni network failed: %s", pluginErr.GetCMessage());
            errlist.push_back(pluginErr.GetMessage());
        } else {
            INFO("TearDownPod cni network: success");
            SetNetworkReady(realSandboxID, false, pluginErr);
            if (pluginErr.NotEmpty()) {
                WARN("set network ready: %s", pluginErr.GetCMessage());
            }
        }
    }
    return 0;
}

void CRIRuntimeServiceImpl::StopPodSandbox(const std::string &podSandboxID, Errors &error)
{
    std::string name, ns, realSandboxID;
    bool hostNetwork = false;
    Errors statusErr, networkErr;
    std::map<std::string, std::string> stdAnnos;
    std::vector<std::string> errlist;

    if (m_cb == nullptr || m_cb->container.list == nullptr || m_cb->container.stop == nullptr) {
        error.SetError("Unimplemented callback");
        return;
    }

    INFO("TearDownPod begin");
    if (podSandboxID.empty()) {
        error.SetError("Invalid empty sandbox id.");
        return;
    }

    if (GetRealSandboxIDToStop(podSandboxID, hostNetwork, name, ns, realSandboxID, stdAnnos, error)) {
        return;
    }

    if (StopAllContainersInSandbox(realSandboxID, error)) {
        return;
    }

    if (ClearCniNetwork(realSandboxID, hostNetwork, ns, name, errlist, stdAnnos, error)) {
        return;
    }

    StopContainerHelper(realSandboxID, error);
    if (error.NotEmpty()) {
        errlist.push_back(error.GetMessage());
    }
    error.SetAggregate(errlist);
}

void CRIRuntimeServiceImpl::StopContainerHelper(const std::string &containerID, Errors &error)
{
    int ret;
    container_stop_request *request { nullptr };
    container_stop_response *response { nullptr };
    // Termination grace period
    constexpr int32_t DefaultSandboxGracePeriod { 10 };

    if (m_cb == nullptr || m_cb->container.stop == nullptr) {
        error.SetError("Unimplemented callback");
        goto cleanup;
    }

    request = (container_stop_request *)util_common_calloc_s(sizeof(container_stop_request));
    if (request == nullptr) {
        error.SetError("Out of memory");
        goto cleanup;
    }
    request->id = util_strdup_s(containerID.c_str());
    request->timeout = DefaultSandboxGracePeriod;

    ret = m_cb->container.stop(request, &response);
    if (ret != 0) {
        std::string msg = (response != nullptr && response->errmsg != nullptr) ? response->errmsg : "internal";
        ERROR("Failed to stop sandbox %s: %s", containerID.c_str(), msg.c_str());
        error.SetError(msg);
    }
cleanup:
    free_container_stop_request(request);
    free_container_stop_response(response);
}

int CRIRuntimeServiceImpl::DoRemovePodSandbox(const std::string &realSandboxID, std::vector<std::string> &errors)
{
    int ret = 0;
    container_delete_request *remove_request { nullptr };
    container_delete_response *remove_response { nullptr };

    if (m_cb == nullptr || m_cb->container.remove == nullptr) {
        errors.push_back("Unimplemented callback");
        return -1;
    }

    remove_request = (container_delete_request *)util_common_calloc_s(sizeof(container_delete_request));
    if (remove_request == nullptr) {
        errors.push_back("Out of memory");
        return -1;
    }
    remove_request->id = util_strdup_s(realSandboxID.c_str());
    remove_request->force = true;

    ret = m_cb->container.remove(remove_request, &remove_response);
    if (ret == 0 || (remove_response != nullptr && remove_response->errmsg != nullptr &&
                     CRIHelpers::IsContainerNotFoundError(remove_response->errmsg))) {
        // Only clear network ready when the sandbox has actually been
        // removed from docker or doesn't exist
        ClearNetworkReady(realSandboxID);
    } else {
        if (remove_response != nullptr && remove_response->errmsg) {
            errors.push_back(remove_response->errmsg);
        } else {
            errors.push_back("Failed to call remove container callback");
        }
    }
    free_container_delete_request(remove_request);
    free_container_delete_response(remove_response);
    return ret;
}
int CRIRuntimeServiceImpl::RemoveAllContainersInSandbox(const std::string &realSandboxID,
                                                        std::vector<std::string> &errors)
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
    for (size_t i = 0; i < list_response->containers_len; i++) {
        Errors rmError;
        RemoveContainer(list_response->containers[i]->id, rmError);
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

void CRIRuntimeServiceImpl::RemovePodSandbox(const std::string &podSandboxID, Errors &error)
{
    std::vector<std::string> errors;
    Errors localErr;
    std::string realSandboxID;

    if (podSandboxID.empty()) {
        errors.push_back("Invalid empty sandbox id.");
        goto cleanup;
    }
    realSandboxID = GetRealContainerOrSandboxID(podSandboxID, true, error);
    if (error.NotEmpty()) {
        if (CRIHelpers::IsContainerNotFoundError(error.GetMessage())) {
            error.Clear();
            realSandboxID = podSandboxID;
        } else {
            ERROR("Failed to find sandbox id %s: %s", podSandboxID.c_str(), error.GetCMessage());
            errors.push_back("Failed to find sandbox id " + podSandboxID + ": " + error.GetMessage());
            goto cleanup;
        }
    }

    if (RemoveAllContainersInSandbox(realSandboxID, errors)) {
        goto cleanup;
    }

    if (DoRemovePodSandbox(realSandboxID, errors)) {
        goto cleanup;
    }

cleanup:
    error.SetAggregate(errors);
}

bool CRIRuntimeServiceImpl::IsDefaultNetworkPlane(cri_pod_network_element *network)
{
    if (network && network->name && network->interface &&
        strcmp(network->name, Network::DEFAULT_NETWORK_PLANE_NAME.c_str()) != 0) {
        return true;
    }

    return false;
}

void CRIRuntimeServiceImpl::SetSandboxStatusNetwork(container_inspect *inspect, const std::string &podSandboxID,
                                                    std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> &podStatus,
                                                    Errors &error)
{
    std::string interfaceIP = GetIP(podSandboxID, inspect, Network::DEFAULT_NETWORK_INTERFACE_NAME, error);
    podStatus->mutable_network()->set_ip(interfaceIP);
}

void CRIRuntimeServiceImpl::PodSandboxStatusToGRPC(container_inspect *inspect, const std::string &podSandboxID,
                                                   std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> &podStatus,
                                                   Errors &error)
{
    int64_t createdAt {};
    runtime::v1alpha2::NamespaceOption *options { nullptr };

    if (inspect->id) {
        podStatus->set_id(inspect->id);
    }

    GetContainerTimeStamps(inspect, &createdAt, nullptr, nullptr, error);
    if (error.NotEmpty()) {
        return;
    }
    podStatus->set_created_at(createdAt);

    if (inspect->state && inspect->state->running) {
        podStatus->set_state(runtime::v1alpha2::SANDBOX_READY);
    } else {
        podStatus->set_state(runtime::v1alpha2::SANDBOX_NOTREADY);
    }

    if (inspect->config) {
        CRIHelpers::ExtractLabels(inspect->config->labels, *podStatus->mutable_labels());
        CRIHelpers::ExtractAnnotations(inspect->config->annotations, *podStatus->mutable_annotations());
    }

    options = podStatus->mutable_linux()->mutable_namespaces()->mutable_options();
    options->set_network(SharesHostNetwork(inspect));
    options->set_pid(SharesHostPid(inspect));
    options->set_ipc(SharesHostIpc(inspect));

    // add networks
    // get default network status
    SetSandboxStatusNetwork(inspect, podSandboxID, podStatus, error);
    if (error.NotEmpty()) {
        ERROR("Set network status failed: %s", error.GetCMessage());
        return;
    }

    if (inspect->name) {
        CRINaming::ParseSandboxName(inspect->name, *podStatus->mutable_metadata(), error);
        if (error.NotEmpty()) {
            return;
        }
    }
}

std::string CRIRuntimeServiceImpl::GetIPFromPlugin(container_inspect *inspect, std::string networkInterface,
                                                   Errors &error)
{
    if (inspect == nullptr || inspect->id == nullptr || inspect->name == nullptr) {
        error.SetError("Empty arguments");
        return "";
    }

    runtime::v1alpha2::PodSandboxMetadata metadata;
    CRINaming::ParseSandboxName(inspect->name, metadata, error);
    if (error.NotEmpty()) {
        return "";
    }
    std::string cid = inspect->id;
    Network::PodNetworkStatus status;
    if (networkInterface == "") {
        m_pluginManager->GetPodNetworkStatus(metadata.namespace_(), metadata.name(),
                                             Network::DEFAULT_NETWORK_INTERFACE_NAME, cid, status, error);
    } else {
        m_pluginManager->GetPodNetworkStatus(metadata.namespace_(), metadata.name(), networkInterface, cid, status,
                                             error);
    }
    if (error.NotEmpty()) {
        return "";
    }

    return status.GetIP();
}

std::string CRIRuntimeServiceImpl::GetIP(const std::string &podSandboxID, container_inspect *inspect,
                                         const std::string &networkInterface, Errors &error)
{
    if (inspect == nullptr || inspect->network_settings == nullptr) {
        return "";
    }
    if (SharesHostNetwork(inspect)) {
        // For sandboxes using host network, the shim is not responsible for reporting the IP.
        return "";
    }

    bool ready = GetNetworkReady(podSandboxID, error);
    if (error.Empty() && !ready) {
        WARN("Network %s do not ready", podSandboxID.c_str());
        return "";
    }

    error.Clear();
    auto ip = GetIPFromPlugin(inspect, networkInterface, error);
    if (error.Empty()) {
        return ip;
    }

    if (inspect->network_settings->ip_address) {
        WARN("Use container inspect ip info: %s", error.GetCMessage());
        error.Clear();
        return inspect->network_settings->ip_address;
    }

    WARN("Failed to read pod IP from plugin/docker: %s", error.GetCMessage());
    return "";
}

std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> CRIRuntimeServiceImpl::PodSandboxStatus(
    const std::string &podSandboxID, Errors &error)
{
    container_inspect *inspect { nullptr };
    std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> podStatus(new runtime::v1alpha2::PodSandboxStatus);

    if (podSandboxID.empty()) {
        error.SetError("Empty pod sandbox id");
        return nullptr;
    }
    std::string realSandboxID = GetRealContainerOrSandboxID(podSandboxID, true, error);
    if (error.NotEmpty()) {
        ERROR("Failed to find sandbox id %s: %s", podSandboxID.c_str(), error.GetCMessage());
        error.Errorf("Failed to find sandbox id %s: %s", podSandboxID.c_str(), error.GetCMessage());
        return nullptr;
    }
    inspect = InspectContainer(realSandboxID, error);
    if (error.NotEmpty()) {
        ERROR("Inspect pod failed: %s", error.GetCMessage());
        return nullptr;
    }
    PodSandboxStatusToGRPC(inspect, realSandboxID, podStatus, error);
    free_container_inspect(inspect);
    return podStatus;
}

void CRIRuntimeServiceImpl::ListPodSandboxToGRPC(container_list_response *response,
                                                 std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods,
                                                 bool filterOutReadySandboxes, Errors &error)
{
    for (size_t i = 0; i < response->containers_len; i++) {
        std::unique_ptr<runtime::v1alpha2::PodSandbox> pod(new runtime::v1alpha2::PodSandbox);

        if (response->containers[i]->id) {
            pod->set_id(response->containers[i]->id);
        }
        if (response->containers[i]->status == CONTAINER_STATUS_RUNNING) {
            pod->set_state(runtime::v1alpha2::SANDBOX_READY);
        } else {
            pod->set_state(runtime::v1alpha2::SANDBOX_NOTREADY);
        }
        pod->set_created_at(response->containers[i]->created);

        CRINaming::ParseSandboxName(response->containers[i]->name, *pod->mutable_metadata(), error);

        CRIHelpers::ExtractLabels(response->containers[i]->labels, *pod->mutable_labels());

        CRIHelpers::ExtractAnnotations(response->containers[i]->annotations, *pod->mutable_annotations());

        if (filterOutReadySandboxes && pod->state() == runtime::v1alpha2::SANDBOX_READY) {
            continue;
        }

        pods->push_back(std::move(pod));
    }
}

void CRIRuntimeServiceImpl::ListPodSandboxFromGRPC(const runtime::v1alpha2::PodSandboxFilter *filter,
                                                   container_list_request **request, bool *filterOutReadySandboxes,
                                                   Errors &error)
{
    *request = (container_list_request *)util_common_calloc_s(sizeof(container_list_request));
    if (*request == nullptr) {
        error.SetError("Out of memory");
        return;
    }
    (*request)->filters = (defs_filters *)util_common_calloc_s(sizeof(defs_filters));
    if ((*request)->filters == nullptr) {
        error.SetError("Out of memory");
        return;
    }
    (*request)->all = true;

    if (CRIHelpers::FiltersAddLabel((*request)->filters, CRIHelpers::Constants::CONTAINER_TYPE_LABEL_KEY,
                                    CRIHelpers::Constants::CONTAINER_TYPE_LABEL_SANDBOX) != 0) {
        error.SetError("Failed to add label");
        return;
    }

    if (filter != nullptr) {
        if (!filter->id().empty()) {
            if (CRIHelpers::FiltersAdd((*request)->filters, "id", filter->id()) != 0) {
                error.SetError("Failed to add label");
                return;
            }
        }
        if (filter->has_state()) {
            if (filter->state().state() == runtime::v1alpha2::SANDBOX_READY) {
                (*request)->all = false;
            } else {
                *filterOutReadySandboxes = true;
            }
        }

        // Add some label
        for (auto &iter : filter->label_selector()) {
            if (CRIHelpers::FiltersAddLabel((*request)->filters, iter.first, iter.second) != 0) {
                error.SetError("Failed to add label");
                return;
            }
        }
    }
}

void CRIRuntimeServiceImpl::ListPodSandbox(const runtime::v1alpha2::PodSandboxFilter *filter,
                                           std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods,
                                           Errors &error)
{
    int ret;
    container_list_request *request { nullptr };
    container_list_response *response { nullptr };
    bool filterOutReadySandboxes { false };

    if (m_cb == nullptr || m_cb->container.list == nullptr) {
        error.SetError("Unimplemented callback");
        return;
    }

    ListPodSandboxFromGRPC(filter, &request, &filterOutReadySandboxes, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    ret = m_cb->container.list(request, &response);
    if (ret != 0) {
        if (response != nullptr && response->errmsg) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call start container callback");
        }
        goto cleanup;
    }
    ListPodSandboxToGRPC(response, pods, filterOutReadySandboxes, error);

cleanup:
    free_container_list_request(request);
    free_container_list_response(response);
}

void CRIRuntimeServiceImpl::PortForward(const runtime::v1alpha2::PortForwardRequest &req,
                                        runtime::v1alpha2::PortForwardResponse *resp, Errors &error)
{
}

bool CRIRuntimeServiceImpl::GetNetworkReady(const std::string &podSandboxID, Errors &error)
{
    bool ready { false };

    if (pthread_mutex_lock(&m_networkReadyLock) != 0) {
        error.SetError("lock failed");
        return ready;
    }
    auto iter = m_networkReady.find(podSandboxID);
    if (iter != m_networkReady.end()) {
        ready = iter->second;
    } else {
        error.Errorf("Do not find network: %s", podSandboxID.c_str());
    }

    pthread_mutex_unlock(&m_networkReadyLock);
    return ready;
}

void CRIRuntimeServiceImpl::SetNetworkReady(const std::string &podSandboxID, bool ready, Errors &error)
{
    if (pthread_mutex_lock(&m_networkReadyLock) != 0) {
        error.SetError("lock failed");
        return;
    }

    m_networkReady[podSandboxID] = ready;

    pthread_mutex_unlock(&m_networkReadyLock);
}

void CRIRuntimeServiceImpl::ClearNetworkReady(const std::string &podSandboxID)
{
    if (pthread_mutex_lock(&m_networkReadyLock) != 0) {
        return;
    }

    auto iter = m_networkReady.find(podSandboxID);
    if (iter != m_networkReady.end()) {
        m_networkReady.erase(iter);
    }

    pthread_mutex_unlock(&m_networkReadyLock);
}
