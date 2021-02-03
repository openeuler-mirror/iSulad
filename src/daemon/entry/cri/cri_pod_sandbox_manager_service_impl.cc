/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-12-15
 * Description: provide cri pod sandbox manager service implementation
 *********************************************************************************/
#include "cri_pod_sandbox_manager_service_impl.h"

#include <sys/mount.h>
#include "isula_libutils/log.h"
#include "isula_libutils/host_config.h"
#include "isula_libutils/container_config.h"
#include "checkpoint_handler.h"
#include "utils.h"
#include "cri_helpers.h"
#include "cri_security_context.h"
#include "cri_constants.h"
#include "naming.h"
#include "service_container_api.h"
#include "cxxutils.h"
#include "network_namespace_api.h"
#include "cri_image_manager_service_impl.h"
#include "utils_network.h"
#include "namespace.h"
#include "constants.h"

namespace CRI {
auto PodSandboxManagerServiceImpl::EnsureSandboxImageExists(const std::string &image, Errors &error) -> bool
{
    ImageManagerServiceImpl imageServiceImpl;
    ImageManagerService &imageService = imageServiceImpl;
    runtime::v1alpha2::ImageSpec imageRef;
    runtime::v1alpha2::AuthConfig auth;
    runtime::v1alpha2::ImageSpec imageSpec;
    Errors err;

    imageSpec.set_image(image);
    std::unique_ptr<runtime::v1alpha2::Image> imageStatus = imageService.ImageStatus(imageSpec, err);
    if (err.Empty()) {
        return true;
    }
    imageStatus.reset();

    imageRef.set_image(image);
    std::string outRef = imageService.PullImage(imageRef, auth, error);
    return !(!error.Empty() || outRef.empty());
}

void PodSandboxManagerServiceImpl::ApplySandboxLinuxOptions(const runtime::v1alpha2::LinuxPodSandboxConfig &lc,
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

void PodSandboxManagerServiceImpl::ApplySandboxResources(const runtime::v1alpha2::LinuxPodSandboxConfig * /*lc*/,
                                                         host_config *hc, Errors & /*error*/)
{
    hc->memory_swap = CRI::Constants::DefaultMemorySwap;
    hc->cpu_shares = CRI::Constants::DefaultSandboxCPUshares;
}

void PodSandboxManagerServiceImpl::MakeSandboxIsuladConfig(const runtime::v1alpha2::PodSandboxConfig &c,
                                                           host_config *hc,
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

    // Apply a container name label for infra container. This is used in summary v1.
    if (append_json_map_string_string(custom_config->labels,
                                      CRIHelpers::Constants::KUBERNETES_CONTAINER_NAME_LABEL.c_str(),
                                      CRIHelpers::Constants::POD_INFRA_CONTAINER_NAME.c_str()) != 0) {
        error.SetError("Append kubernetes container name into labels failed");
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
    if (c.has_metadata()) {
        if (append_json_map_string_string(custom_config->annotations,
                                          CRIHelpers::Constants::SANDBOX_NAMESPACE_ANNOTATION_KEY.c_str(),
                                          c.metadata().namespace_().c_str()) != 0) {
            error.SetError("Append sandbox namespace into annotation failed");
            return;
        }
        if (append_json_map_string_string(custom_config->annotations,
                                          CRIHelpers::Constants::SANDBOX_NAME_ANNOTATION_KEY.c_str(),
                                          c.metadata().name().c_str()) != 0) {
            error.SetError("Append sandbox name into annotation failed");
            return;
        }
        if (append_json_map_string_string(custom_config->annotations,
                                          CRIHelpers::Constants::SANDBOX_UID_ANNOTATION_KEY.c_str(),
                                          c.metadata().uid().c_str()) != 0) {
            error.SetError("Append sandbox uid into annotation failed");
            return;
        }
        if (append_json_map_string_string(custom_config->annotations,
                                          CRIHelpers::Constants::SANDBOX_ATTEMPT_ANNOTATION_KEY.c_str(),
                                          std::to_string(c.metadata().attempt()).c_str()) != 0) {
            error.SetError("Append sandbox attempt into annotation failed");
            return;
        }
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

    hc->oom_score_adj = CRI::Constants::PodInfraOOMAdj;

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
        if (!securityOpts.empty()) {
            char **tmp_security_opt = nullptr;

            if (securityOpts.size() > (SIZE_MAX / sizeof(char *)) - hc->security_opt_len) {
                error.Errorf("Out of memory");
                return;
            }
            size_t newSize = (hc->security_opt_len + securityOpts.size()) * sizeof(char *);
            size_t oldSize = hc->security_opt_len * sizeof(char *);
            int ret = util_mem_realloc((void **)(&tmp_security_opt), newSize, (void *)hc->security_opt, oldSize);
            if (ret != 0) {
                error.Errorf("Out of memory");
                return;
            }
            hc->security_opt = tmp_security_opt;
            for (const auto &securityOpt : securityOpts) {
                hc->security_opt[hc->security_opt_len] = util_strdup_s(securityOpt.c_str());
                hc->security_opt_len++;
            }
        }
    }
}

auto PodSandboxManagerServiceImpl::ParseCheckpointProtocol(runtime::v1alpha2::Protocol protocol) -> std::string
{
    switch (protocol) {
        case runtime::v1alpha2::UDP:
            return "udp";
        case runtime::v1alpha2::TCP:
        default:
            return "tcp";
    }
}

void PodSandboxManagerServiceImpl::ConstructPodSandboxCheckpoint(const runtime::v1alpha2::PodSandboxConfig &config,
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

container_create_request *PodSandboxManagerServiceImpl::PackCreateContainerRequest(
    const runtime::v1alpha2::PodSandboxConfig &config, const std::string &image, host_config *hostconfig,
    container_config *custom_config, const std::string &runtimeHandler, Errors &error)
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
        create_request->runtime = CRIHelpers::cri_runtime_convert(runtimeHandler.c_str());
        if (create_request->runtime == nullptr) {
            create_request->runtime = util_strdup_s(runtimeHandler.c_str());
        }
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

container_create_request *PodSandboxManagerServiceImpl::GenerateSandboxCreateContainerRequest(
    const runtime::v1alpha2::PodSandboxConfig &config, const std::string &image, std::string &jsonCheckpoint,
    const std::string &runtimeHandler, Errors &error)
{
    container_create_request *create_request = nullptr;
    host_config *hostconfig = nullptr;
    container_config *custom_config = nullptr;
    CRI::PodSandboxCheckpoint checkpoint;

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

auto PodSandboxManagerServiceImpl::CreateSandboxContainer(const runtime::v1alpha2::PodSandboxConfig &config,
                                                          const std::string &image, std::string &jsonCheckpoint,
                                                          const std::string &runtimeHandler, Errors &error)
-> std::string
{
    std::string response_id;
    container_create_request *create_request =
        GenerateSandboxCreateContainerRequest(config, image, jsonCheckpoint, runtimeHandler, error);
    if (error.NotEmpty()) {
        return response_id;
    }

    container_create_response *create_response = nullptr;
    if (m_cb->container.create(create_request, &create_response) != 0) {
        if (create_response != nullptr && (create_response->errmsg != nullptr)) {
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

void PodSandboxManagerServiceImpl::SetNetworkReady(const std::string &podSandboxID, bool ready, Errors &error)
{
    std::lock_guard<std::mutex> lockGuard(m_networkReadyLock);

    m_networkReady[podSandboxID] = ready;
}

void PodSandboxManagerServiceImpl::StartSandboxContainer(const std::string &response_id, Errors &error)
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
        if (start_response != nullptr && (start_response->errmsg != nullptr)) {
            error.SetError(start_response->errmsg);
        } else {
            error.SetError("Failed to call start container callback");
        }
    }
    free_container_start_request(start_request);
    free_container_start_response(start_response);
}

void PodSandboxManagerServiceImpl::SetupSandboxFiles(const std::string &resolvPath,
                                                     const runtime::v1alpha2::PodSandboxConfig &config, Errors &error)
{
    if (resolvPath.empty()) {
        return;
    }
    std::vector<std::string> resolvContentStrs;

    /* set DNS options */
    int len = config.dns_config().searches_size();
    if (len > CRI::Constants::MAX_DNS_SEARCHES) {
        error.SetError("DNSOption.Searches has more than 6 domains");
        return;
    }

    std::vector<std::string> servers(config.dns_config().servers().begin(), config.dns_config().servers().end());
    if (!servers.empty()) {
        resolvContentStrs.push_back("nameserver " + CXXUtils::StringsJoin(servers, "\nnameserver "));
    }

    std::vector<std::string> searches(config.dns_config().searches().begin(), config.dns_config().searches().end());
    if (!searches.empty()) {
        resolvContentStrs.push_back("search " + CXXUtils::StringsJoin(searches, " "));
    }

    std::vector<std::string> options(config.dns_config().options().begin(), config.dns_config().options().end());
    if (!options.empty()) {
        resolvContentStrs.push_back("options " + CXXUtils::StringsJoin(options, " "));
    }

    if (!resolvContentStrs.empty()) {
        std::string resolvContent = CXXUtils::StringsJoin(resolvContentStrs, "\n") + "\n";
        if (util_write_file(resolvPath.c_str(), resolvContent.c_str(), resolvContent.size(),
                            DEFAULT_SECURE_FILE_MODE) != 0) {
            error.SetError("Failed to write resolv content");
        }
    }
}

void PodSandboxManagerServiceImpl::StopContainerHelper(const std::string &containerID, Errors &error)
{
    int ret = 0;
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

void PodSandboxManagerServiceImpl::SetupSandboxNetwork(const runtime::v1alpha2::PodSandboxConfig &config,
                                                       const std::string &response_id, const std::string &jsonCheckpoint,
                                                       const container_inspect *inspect_data, 
                                                       std::string &network_settings_json, Errors &error)
{
    std::map<std::string, std::string> stdAnnos;
    std::map<std::string, std::string> networkOptions;
    char* sandbox_key = get_sandbox_key(inspect_data);

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
    if (sandbox_key == NULL) {
        goto cleanup;
    }
    stdAnnos.insert(std::pair<std::string, std::string>(CRIHelpers::Constants::POD_SANDBOX_KEY, sandbox_key));
    m_pluginManager->SetUpPod(config.metadata().namespace_(), config.metadata().name(),
                              Network::DEFAULT_NETWORK_INTERFACE_NAME, response_id, stdAnnos, networkOptions, network_settings_json, error);
    if (error.NotEmpty()) {
        ERROR("SetupPod failed: %s", error.GetCMessage());
        StopContainerHelper(response_id, error);
        goto cleanup;
    }

cleanup:
    free(sandbox_key);
    return;
}

auto PodSandboxManagerServiceImpl::GenerateUpdateNetworkSettingsReqest(const std::string &id,
                                                                       const std::string &json,
                                                                       Errors &error) -> container_update_network_settings_request*
{
    if (json.empty()) {
        return nullptr;
    }

    container_update_network_settings_request *req = (container_update_network_settings_request *)util_common_calloc_s(
              sizeof(container_update_network_settings_request));
    if (req == nullptr) {
        error.Errorf("container update network settings request: Out of memory");
        return nullptr;
    }
    req->id = util_strdup_s(id.c_str());
    req->setting_json = util_strdup_s(json.c_str());

    return req;
}

auto PodSandboxManagerServiceImpl::RunPodSandbox(const runtime::v1alpha2::PodSandboxConfig &config,
                                                 const std::string &runtimeHandler, Errors &error) -> std::string
{
    std::string response_id;
    std::string jsonCheckpoint;
    char *netnsPath = nullptr;
    std::string network_setting_json;
    container_inspect *inspect_data { nullptr };
    container_update_network_settings_request *ips_request { nullptr };
    container_update_network_settings_response *ips_response { nullptr };

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

    // Step 4: mount network namespace when network mode is file
    inspect_data = CRIHelpers::InspectContainer(response_id, error, true);
    if (error.NotEmpty()) {
        goto cleanup;
    }
    if (inspect_data == nullptr || inspect_data->host_config == nullptr) {
        error.Errorf("Failed to retrieve inspect data");
        ERROR("Failed to retrieve inspect data");
        goto cleanup;
    }
    netnsPath = get_sandbox_key(inspect_data);
    if (namespace_is_file(inspect_data->host_config->network_mode)) {
        if (!util_file_exists(netnsPath) || util_mount_namespace(netnsPath) != 0) {
            error.Errorf("Failed to mount network namespace");
            ERROR("Failed to mount network namespace");
            goto cleanup;
        }
    }

    // Step 5: Setup networking for the sandbox.
    SetupSandboxNetwork(config, response_id, jsonCheckpoint, inspect_data, network_setting_json, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    // Step 6: Start the sandbox container.
    StartSandboxContainer(response_id, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    // Step 6: Save network settings json to disk
    ips_request = GenerateUpdateNetworkSettingsReqest(response_id, network_setting_json, error);
    if (ips_request != nullptr) {
        if (m_cb->container.update_network_settings(ips_request, &ips_response) != 0) {
            if (ips_response != nullptr && ips_response->errmsg != nullptr) {
                error.SetError(ips_response->errmsg);
            } else {
                error.SetError("Failed to update container network settings");
            }
            goto cleanup;
        }
    }

cleanup:
    if (error.Empty()) {
        SetNetworkReady(response_id, true, error);
        DEBUG("set %s ready", response_id.c_str());
        error.Clear();
    } else {
        if (netnsPath != nullptr && remove_network_namespace(netnsPath) != 0) {
            ERROR("Failed to remove network namespace");
        }
    }

    free(netnsPath);
    free_container_inspect(inspect_data);
    free_container_update_network_settings_request(ips_request);
    free_container_update_network_settings_response(ips_response);
    return response_id;
}

auto PodSandboxManagerServiceImpl::GetRealSandboxIDToStop(const std::string &podSandboxID, bool &hostNetwork,
                                                          std::string &name, std::string &ns,
                                                          std::string &realSandboxID,
                                                          std::map<std::string, std::string> &stdAnnos, Errors &error)
-> int
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

auto PodSandboxManagerServiceImpl::StopAllContainersInSandbox(const std::string &realSandboxID, Errors &error) -> int
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

auto PodSandboxManagerServiceImpl::GetNetworkReady(const std::string &podSandboxID, Errors &error) -> bool
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

auto PodSandboxManagerServiceImpl::ClearCniNetwork(const std::string &realSandboxID, bool hostNetwork,
                                                   const std::string &ns, const std::string &name,
                                                   std::vector<std::string> &errlist,
                                                   std::map<std::string, std::string> &stdAnnos, Errors &
                                                   /*error*/) -> int
{
    Errors networkErr;
    container_inspect* inspect_data = nullptr;

    bool ready = GetNetworkReady(realSandboxID, networkErr);
    if (!hostNetwork && (ready || networkErr.NotEmpty())) {
        Errors pluginErr;

        // hostNetwork has indicated network mode which render host config unnecessary
        // so that with_host_config is set to be false.
        inspect_data = CRIHelpers::InspectContainer(realSandboxID, pluginErr, false);
        if (pluginErr.NotEmpty()) {
            ERROR("Failed to inspect container");
        }

        char* netnsPath = get_sandbox_key(inspect_data);
        if (netnsPath == nullptr) {
            ERROR("Failed to get network namespace path");
            return 0;
        }

        stdAnnos.insert(std::pair<std::string, std::string>(CRIHelpers::Constants::POD_SANDBOX_KEY, netnsPath));
        m_pluginManager->TearDownPod(ns, name, Network::DEFAULT_NETWORK_INTERFACE_NAME, realSandboxID, stdAnnos,
                                     pluginErr);
        if (pluginErr.NotEmpty()) {
            WARN("TearDownPod cni network failed: %s", pluginErr.GetCMessage());
            errlist.push_back(pluginErr.GetMessage());
        } else {
            INFO("TearDownPod cni network: success");
            SetNetworkReady(realSandboxID, false, pluginErr);
            if (pluginErr.NotEmpty()) {
                WARN("set network ready: %s", pluginErr.GetCMessage());
            }
            // umount netns when cni removed network successfully
            if (util_umount_namespace(netnsPath) != 0) {
                ERROR("Failed to umount directory %s:%s", netnsPath, strerror(errno));
            }
        }
        free(netnsPath);
    }
    free_container_inspect(inspect_data);
    return 0;
}

void PodSandboxManagerServiceImpl::StopPodSandbox(const std::string &podSandboxID, Errors &error)
{
    std::string name;
    std::string ns;
    std::string realSandboxID;
    bool hostNetwork = false;
    Errors statusErr;
    Errors networkErr;
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

    if (GetRealSandboxIDToStop(podSandboxID, hostNetwork, name, ns, realSandboxID, stdAnnos, error) != 0) {
        return;
    }

    if (StopAllContainersInSandbox(realSandboxID, error) != 0) {
        return;
    }

    if (ClearCniNetwork(realSandboxID, hostNetwork, ns, name, errlist, stdAnnos, error) != 0) {
        return;
    }

    StopContainerHelper(realSandboxID, error);
    if (error.NotEmpty()) {
        errlist.push_back(error.GetMessage());
    }
    error.SetAggregate(errlist);
}

auto PodSandboxManagerServiceImpl::RemoveAllContainersInSandbox(const std::string &realSandboxID,
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
    for (size_t i = 0; i < list_response->containers_len; i++) {
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

void PodSandboxManagerServiceImpl::ClearNetworkReady(const std::string &podSandboxID)
{
    std::lock_guard<std::mutex> lockGuard(m_networkReadyLock);

    auto iter = m_networkReady.find(podSandboxID);
    if (iter != m_networkReady.end()) {
        m_networkReady.erase(iter);
    }
}

int PodSandboxManagerServiceImpl::DoRemovePodSandbox(const std::string &realSandboxID, std::vector<std::string> &errors)
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
        if (remove_response != nullptr && (remove_response->errmsg != nullptr)) {
            errors.push_back(remove_response->errmsg);
        } else {
            errors.push_back("Failed to call remove container callback");
        }
    }
    free_container_delete_request(remove_request);
    free_container_delete_response(remove_response);
    return ret;
}

void PodSandboxManagerServiceImpl::RemovePodSandbox(const std::string &podSandboxID, Errors &error)
{
    std::vector<std::string> errors;
    Errors localErr;
    std::string realSandboxID;

    if (podSandboxID.empty()) {
        errors.push_back("Invalid empty sandbox id.");
        goto cleanup;
    }
    realSandboxID = CRIHelpers::GetRealContainerOrSandboxID(m_cb, podSandboxID, true, error);
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

    if (RemoveAllContainersInSandbox(realSandboxID, errors) != 0) {
        goto cleanup;
    }

    if (DoRemovePodSandbox(realSandboxID, errors) != 0) {
        goto cleanup;
    }

cleanup:
    error.SetAggregate(errors);
}

auto PodSandboxManagerServiceImpl::SharesHostNetwork(const container_inspect *inspect)
-> runtime::v1alpha2::NamespaceMode
{
    if (inspect != nullptr && inspect->host_config != nullptr && (inspect->host_config->network_mode != nullptr) &&
        std::string(inspect->host_config->network_mode) == CRI::Constants::namespaceModeHost) {
        return runtime::v1alpha2::NamespaceMode::NODE;
    }
    return runtime::v1alpha2::NamespaceMode::POD;
}

auto PodSandboxManagerServiceImpl::SharesHostPid(const container_inspect *inspect) -> runtime::v1alpha2::NamespaceMode
{
    if (inspect != nullptr && inspect->host_config != nullptr && (inspect->host_config->pid_mode != nullptr) &&
        std::string(inspect->host_config->pid_mode) == CRI::Constants::namespaceModeHost) {
        return runtime::v1alpha2::NamespaceMode::NODE;
    }
    return runtime::v1alpha2::NamespaceMode::CONTAINER;
}

auto PodSandboxManagerServiceImpl::SharesHostIpc(const container_inspect *inspect) -> runtime::v1alpha2::NamespaceMode
{
    if (inspect != nullptr && inspect->host_config != nullptr && (inspect->host_config->ipc_mode != nullptr) &&
        std::string(inspect->host_config->ipc_mode) == CRI::Constants::namespaceModeHost) {
        return runtime::v1alpha2::NamespaceMode::NODE;
    }
    return runtime::v1alpha2::NamespaceMode::POD;
}

void PodSandboxManagerServiceImpl::GetIPs(const std::string &podSandboxID, const container_inspect *inspect,
                                          const std::string &networkInterface, std::vector<std::string> &ips, Errors &error)
{
    if (inspect == nullptr) {
        return;
    }

    if (SharesHostNetwork(inspect) != 0) {
        // For sandboxes using host network, the shim is not responsible for reporting the IP.
        return;
    }

    bool ready = GetNetworkReady(podSandboxID, error);
    if (error.Empty() && !ready) {
        WARN("Network %s do not ready", podSandboxID.c_str());
        return;
    }

    error.Clear();
    if (inspect->network_settings == NULL || inspect->network_settings->networks == NULL) {
        WARN("inspect network is empty");
        return;
    }

    for (size_t i = 0; i < inspect->network_settings->networks->len; i++) {
        if (inspect->network_settings->networks->values[i] != nullptr &&
            inspect->network_settings->networks->values[i]->ip_address != nullptr) {
            WARN("Use container inspect ip: %s", inspect->network_settings->networks->values[i]->ip_address);
            ips.push_back(inspect->network_settings->networks->values[i]->ip_address);
        }
    }
}

void PodSandboxManagerServiceImpl::SetSandboxStatusNetwork(
    const container_inspect *inspect, const std::string &podSandboxID,
    std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> &podStatus, Errors &error)
{
    std::vector<std::string> ips;
    size_t i;

    GetIPs(podSandboxID, inspect, Network::DEFAULT_NETWORK_INTERFACE_NAME, ips, error);
    if (ips.size() == 0) {
        return;
    }
    podStatus->mutable_network()->set_ip(ips[0]);

    for (i = 1; i < ips.size(); i++) {
        auto tPoint = podStatus->mutable_network()->add_additional_ips();
        tPoint->set_ip(ips[i]);
    }
}

void PodSandboxManagerServiceImpl::PodSandboxStatusToGRPC(
    const container_inspect *inspect, const std::string &podSandboxID,
    std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> &podStatus, Errors &error)
{
    int64_t createdAt {};
    runtime::v1alpha2::NamespaceOption *options { nullptr };

    if (inspect->id != nullptr) {
        podStatus->set_id(inspect->id);
    }

    CRIHelpers::GetContainerTimeStamps(inspect, &createdAt, nullptr, nullptr, error);
    if (error.NotEmpty()) {
        return;
    }
    podStatus->set_created_at(createdAt);

    if ((inspect->state != nullptr) && inspect->state->running) {
        podStatus->set_state(runtime::v1alpha2::SANDBOX_READY);
    } else {
        podStatus->set_state(runtime::v1alpha2::SANDBOX_NOTREADY);
    }

    if (inspect->config == nullptr) {
        ERROR("Invalid container information! Must include config info");
        return;
    }

    CRIHelpers::ExtractLabels(inspect->config->labels, *podStatus->mutable_labels());
    CRIHelpers::ExtractAnnotations(inspect->config->annotations, *podStatus->mutable_annotations());
    CRINaming::ParseSandboxName(podStatus->annotations(), *podStatus->mutable_metadata(), error);
    if (error.NotEmpty()) {
        return;
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
}

std::unique_ptr<runtime::v1alpha2::PodSandboxStatus>
PodSandboxManagerServiceImpl::PodSandboxStatus(const std::string &podSandboxID, Errors &error)
{
    container_inspect *inspect { nullptr };
    std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> podStatus(new runtime::v1alpha2::PodSandboxStatus);

    if (podSandboxID.empty()) {
        error.SetError("Empty pod sandbox id");
        return nullptr;
    }
    std::string realSandboxID = CRIHelpers::GetRealContainerOrSandboxID(m_cb, podSandboxID, true, error);
    if (error.NotEmpty()) {
        ERROR("Failed to find sandbox id %s: %s", podSandboxID.c_str(), error.GetCMessage());
        error.Errorf("Failed to find sandbox id %s: %s", podSandboxID.c_str(), error.GetCMessage());
        return nullptr;
    }
    inspect = CRIHelpers::InspectContainer(realSandboxID, error, true);
    if (error.NotEmpty()) {
        ERROR("Inspect pod failed: %s", error.GetCMessage());
        return nullptr;
    }
    PodSandboxStatusToGRPC(inspect, realSandboxID, podStatus, error);
    free_container_inspect(inspect);
    return podStatus;
}

void PodSandboxManagerServiceImpl::ListPodSandboxFromGRPC(const runtime::v1alpha2::PodSandboxFilter *filter,
                                                          container_list_request **request,
                                                          bool *filterOutReadySandboxes, Errors &error)
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

void PodSandboxManagerServiceImpl::ListPodSandboxToGRPC(
    container_list_response *response, std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods,
    bool filterOutReadySandboxes, Errors &error)
{
    for (size_t i = 0; i < response->containers_len; i++) {
        std::unique_ptr<runtime::v1alpha2::PodSandbox> pod(new runtime::v1alpha2::PodSandbox);

        if (response->containers[i]->id != nullptr) {
            pod->set_id(response->containers[i]->id);
        }
        if (response->containers[i]->status == CONTAINER_STATUS_RUNNING) {
            pod->set_state(runtime::v1alpha2::SANDBOX_READY);
        } else {
            pod->set_state(runtime::v1alpha2::SANDBOX_NOTREADY);
        }
        pod->set_created_at(response->containers[i]->created);

        CRIHelpers::ExtractLabels(response->containers[i]->labels, *pod->mutable_labels());

        CRIHelpers::ExtractAnnotations(response->containers[i]->annotations, *pod->mutable_annotations());

        CRINaming::ParseSandboxName(pod->annotations(), *pod->mutable_metadata(), error);

        if (filterOutReadySandboxes && pod->state() == runtime::v1alpha2::SANDBOX_READY) {
            continue;
        }

        pods->push_back(std::move(pod));
    }
}

void PodSandboxManagerServiceImpl::ListPodSandbox(const runtime::v1alpha2::PodSandboxFilter *filter,
                                                  std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods,
                                                  Errors &error)
{
    int ret = 0;
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
        if (response != nullptr && (response->errmsg != nullptr)) {
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

void PodSandboxManagerServiceImpl::PortForward(const runtime::v1alpha2::PortForwardRequest &req,
                                               runtime::v1alpha2::PortForwardResponse *resp, Errors &error)
{
    // This feature is temporarily not supported
}

} // namespace CRI
