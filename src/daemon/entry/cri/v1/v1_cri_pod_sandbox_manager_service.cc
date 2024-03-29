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
#include "v1_cri_pod_sandbox_manager_service.h"

#include <sys/mount.h>
#include <isula_libutils/log.h>
#include <isula_libutils/host_config.h>
#include <isula_libutils/container_config.h>
#include <isula_libutils/auto_cleanup.h>
#include <algorithm>

#include "checkpoint_handler.h"
#include "utils.h"
#include "v1_cri_helpers.h"
#include "cri_helpers.h"
#include "v1_cri_security_context.h"
#include "cri_constants.h"
#include "v1_naming.h"
#include "service_container_api.h"
#include "cxxutils.h"
#include "network_namespace.h"
#include "v1_cri_image_manager_service_impl.h"
#include "namespace.h"
#include "sandbox_manager.h"
#include "transform.h"
#include "isulad_config.h"
#include "mailbox.h"

namespace CRIV1 {
void PodSandboxManagerService::PrepareSandboxData(const runtime::v1::PodSandboxConfig &config,
                                                  const std::string &runtimeHandler, std::string &sandboxName,
                                                  sandbox::RuntimeInfo &runtimeInfo, std::string &networkMode,
                                                  Errors &error)
{
    // Prepare sandboxName
    sandboxName = CRINamingV1::MakeSandboxName(config.metadata());

    // Prepare runtimeInfo
    runtimeInfo.runtimeHandler = runtimeHandler;
    runtimeInfo.runtime = CRIHelpers::CRIRuntimeConvert(runtimeHandler);
    if (runtimeInfo.runtime.empty()) {
        runtimeInfo.runtime = std::string(runtimeHandler);
    }
    runtimeInfo.sandboxer = CRIHelpersV1::CRISandboxerConvert(runtimeHandler);
    if (runtimeInfo.sandboxer.empty()) {
        ERROR("Failed to convert runtimehandler: %s to sandboxer", runtimeHandler.c_str());
        error.Errorf("Failed to convert runtimehandler: %s to sandboxer", runtimeHandler.c_str());
        return;
    }

    // Prepare network mode
    networkMode = CRI::Constants::namespaceModeCNI;
    if (config.linux().security_context().namespace_options().network() == runtime::v1::NamespaceMode::NODE) {
        networkMode = CRI::Constants::namespaceModeHost;
    }
}

auto PodSandboxManagerService::EnsureSandboxImageExists(const std::string &image, const std::string &sandboxer,
                                                        Errors &error) -> bool
{
    ImageManagerServiceImpl imageServiceImpl;
    ImageManagerService &imageService = imageServiceImpl;
    runtime::v1::ImageSpec imageRef;
    runtime::v1::AuthConfig auth;
    runtime::v1::ImageSpec imageSpec;
    Errors err;

    if (sandboxer != std::string(DEFAULT_SANDBOXER_NAME)) {
        // Skip pull image if sandboxer controller,
        // because sandboxer controller does not need image
        return true;
    }

    imageSpec.set_image(image);
    std::unique_ptr<runtime::v1::Image> imageStatus = imageService.ImageStatus(imageSpec, err);
    if (err.Empty()) {
        return true;
    }
    imageStatus.reset();

    imageRef.set_image(image);
    std::string outRef = imageService.PullImage(imageRef, auth, error);
    return !(!error.Empty() || outRef.empty());
}

void PodSandboxManagerService::PrepareSandboxKey(std::string &sandboxKey, Errors &error)
{
    __isula_auto_free char *sandboxKeyChars = new_sandbox_network_key();
    if (sandboxKeyChars == NULL || strlen(sandboxKeyChars) == 0) {
        error.SetError("Failed to generate sandbox key");
        return;
    }

    if (create_network_namespace_file(sandboxKeyChars) != 0) {
        error.SetError("Failed to create network namespace");
        return;
    }

    sandboxKey = std::string(sandboxKeyChars);
}

void PodSandboxManagerService::ApplySandboxDefaultResources(runtime::v1::LinuxPodSandboxConfig *linuxConfig)
{
    if (!linuxConfig->has_resources()) {
        linuxConfig->mutable_resources()->set_memory_swap_limit_in_bytes((google::protobuf::int64)
                                                                         CRI::Constants::DefaultMemorySwap);
        linuxConfig->mutable_resources()->set_cpu_shares((google::protobuf::int64)CRI::Constants::DefaultSandboxCPUshares);
        linuxConfig->mutable_resources()->set_cpu_quota((google::protobuf::int64)CRI::Constants::DefaultSandboxCPUQuota);
        linuxConfig->mutable_resources()->set_cpu_period((google::protobuf::int64)CRI::Constants::DefaultSandboxCPUPeriod);
        linuxConfig->mutable_resources()->set_memory_limit_in_bytes((google::protobuf::int64)
                                                                    CRI::Constants::DefaultSandboxMemoryLimitInBytes);
    }

    // set default oom score adj
    linuxConfig->mutable_resources()->set_oom_score_adj((google::protobuf::int64)(CRI::Constants::PodInfraOOMAdj));
}

auto PodSandboxManagerService::ParseCheckpointProtocol(runtime::v1::Protocol protocol) -> std::string
{
    switch (protocol) {
        case runtime::v1::UDP:
            return "udp";
        case runtime::v1::TCP:
        default:
            return "tcp";
    }
}

void PodSandboxManagerService::ConstructPodSandboxCheckpoint(const runtime::v1::PodSandboxConfig &config,
                                                             CRI::PodSandboxCheckpoint &checkpoint)
{
    checkpoint.SetName(config.metadata().name());
    checkpoint.SetNamespace(config.metadata().namespace_());
    checkpoint.SetData(new CRI::CheckpointData);

    int len = config.port_mappings_size();
    for (int i = 0; i < len; i++) {
        CRI::PortMapping item;

        const runtime::v1::PortMapping &iter = config.port_mappings(i);
        item.SetProtocol(ParseCheckpointProtocol(iter.protocol()));
        item.SetContainerPort(iter.container_port());
        item.SetHostPort(iter.host_port());
        (checkpoint.GetData())->InsertPortMapping(item);
    }
    if (config.linux().security_context().namespace_options().network() == runtime::v1::NamespaceMode::NODE) {
        (checkpoint.GetData())->SetHostNetwork(true);
    }
}

void PodSandboxManagerService::PrepareSandboxCheckpoint(const runtime::v1::PodSandboxConfig &config,
                                                        std::string &jsonCheckpoint, Errors &error)
{
    CRI::PodSandboxCheckpoint checkpoint;
    ConstructPodSandboxCheckpoint(config, checkpoint);
    jsonCheckpoint = CRIHelpers::CreateCheckpoint(checkpoint, error);
}

void PodSandboxManagerService::UpdateSandboxConfig(runtime::v1::PodSandboxConfig &config,
                                                   std::string &jsonCheckpoint, Errors &error)
{
    auto labels = config.mutable_labels();
    auto annotations = config.mutable_annotations();

    (*labels)[CRIHelpers::Constants::CONTAINER_TYPE_LABEL_KEY] = CRIHelpers::Constants::CONTAINER_TYPE_LABEL_SANDBOX;
    // Apply a container name label for infra container. This is used in summary v1.
    (*labels)[CRIHelpers::Constants::KUBERNETES_CONTAINER_NAME_LABEL] = CRIHelpers::Constants::POD_INFRA_CONTAINER_NAME;

    (*annotations)[CRIHelpers::Constants::CONTAINER_TYPE_ANNOTATION_KEY] =
        CRIHelpers::Constants::CONTAINER_TYPE_ANNOTATION_SANDBOX;
    // Add checkpoint into annotations
    (*annotations)[CRIHelpers::Constants::POD_CHECKPOINT_KEY] = jsonCheckpoint;

    if (config.has_metadata()) {
        (*annotations)[CRIHelpers::Constants::SANDBOX_NAMESPACE_ANNOTATION_KEY] = config.metadata().namespace_();
        (*annotations)[CRIHelpers::Constants::SANDBOX_NAME_ANNOTATION_KEY] = config.metadata().name();
        (*annotations)[CRIHelpers::Constants::SANDBOX_UID_ANNOTATION_KEY] = config.metadata().uid();
        (*annotations)[CRIHelpers::Constants::SANDBOX_ATTEMPT_ANNOTATION_KEY] = std::to_string(config.metadata().attempt());
    }

    ApplySandboxDefaultResources(config.mutable_linux());

    // TODO: Update LinuxPodSandboxConfig with default values

    // TODO: Update SecurityContext with default values
}

void PodSandboxManagerService::SetupSandboxFiles(const std::string &resolvPath,
                                                 const runtime::v1::PodSandboxConfig &config, Errors &error)
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

void PodSandboxManagerService::SetupSandboxNetwork(const std::shared_ptr<sandbox::Sandbox> sandbox,
                                                   std::string &network_settings_json, Errors &error)
{
    const auto config = sandbox->GetSandboxConfig();

    sandbox->SetNetworkReady(false);
    // Setup sandbox files
    if (config.has_dns_config() && !sandbox->GetResolvPath().empty()) {
        INFO("Overwrite resolv.conf: %s", sandbox->GetResolvPath().c_str());
        SetupSandboxFiles(sandbox->GetResolvPath(), config, error);
        if (error.NotEmpty()) {
            ERROR("Failed to setup sandbox files");
            return;
        }
    }

    if (!namespace_is_cni(sandbox->GetNetMode().c_str())) {
        return;
    }

    const std::string &sandboxKey = sandbox->GetNetNsPath();
    if (sandboxKey.empty()) {
        error.Errorf("Sandbox key is invalid");
        ERROR("Sandbox key is invalid");
        return;
    }

    std::map<std::string, std::string> stdAnnos;
    CRIHelpers::ProtobufAnnoMapToStd(config.annotations(), stdAnnos);
    stdAnnos.insert(std::pair<std::string, std::string>(CRIHelpers::Constants::POD_SANDBOX_KEY, sandboxKey));

    std::map<std::string, std::string> networkOptions;
    networkOptions["UID"] = config.metadata().uid();

    if (prepare_network_namespace(sandboxKey.c_str(), false, 0) != 0) {
        error.Errorf("Failed to prepare network namespace: %s", sandboxKey.c_str());
        ERROR("Failed to prepare network namespace: %s", sandboxKey.c_str());
        return;
    }

    // Setup networking for the sandbox.
    m_pluginManager->SetUpPod(config.metadata().namespace_(), config.metadata().name(),
                              Network::DEFAULT_NETWORK_INTERFACE_NAME, sandbox->GetId(), stdAnnos, networkOptions,
                              network_settings_json, error);
    if (error.NotEmpty()) {
        ERROR("SetupPod failed: %s", error.GetCMessage());
        if (remove_network_namespace(sandboxKey.c_str()) != 0) {
            ERROR("Failed to remove network namespace: %s", sandboxKey.c_str());
        }
        return;
    }

    sandbox->SetNetworkReady(true);
    DEBUG("set %s ready", sandbox->GetId().c_str());
}

auto PodSandboxManagerService::RunPodSandbox(const runtime::v1::PodSandboxConfig &config,
                                             const std::string &runtimeHandler, Errors &error) -> std::string
{
    std::string response_id;
    std::string sandboxName;
    sandbox::RuntimeInfo runtimeInfo;
    std::string networkMode;
    std::string sandboxKey;
    std::string jsonCheckpoint;
    std::string network_setting_json;
    runtime::v1::PodSandboxConfig copyConfig = config;
    cri_container_message_t msg = { 0 };

    // Step 1: Parepare sandbox name, runtime and networkMode
    PrepareSandboxData(config, runtimeHandler, sandboxName, runtimeInfo, networkMode, error);
    if (error.NotEmpty()) {
        return response_id;
    }

    // Step 2: Pull the image for the sandbox.
    // Maybe we should pull image in shim controller ?
    // But pull image interface is only in CRI image service, and it can't be called in shim controller,
    // so we pull image in CRI pod service.
    const std::string &image = m_podSandboxImage;
    if (!EnsureSandboxImageExists(image, runtimeInfo.sandboxer, error)) {
        ERROR("Failed to pull sandbox image %s: %s", image.c_str(), error.NotEmpty() ? error.GetCMessage() : "");
        error.Errorf("Failed to pull sandbox image %s: %s", image.c_str(), error.NotEmpty() ? error.GetCMessage() : "");
        return response_id;
    }

    // Step 3: Prepare sandbox checkpoint
    PrepareSandboxCheckpoint(config, jsonCheckpoint, error);
    if (error.NotEmpty()) {
        return response_id;
    }

    // Step 4: Update sandbox instance config
    UpdateSandboxConfig(copyConfig, jsonCheckpoint, error);
    if (error.NotEmpty()) {
        return response_id;
    }

    // Step 5: Prepare sandboxKey
    if (namespace_is_cni(networkMode.c_str())) {
        // cleanup sandboxKey file in DeleteSandbox
        PrepareSandboxKey(sandboxKey, error);
        if (error.NotEmpty()) {
            return response_id;
        }
    }

    // Step 6: Create sandbox instance
    auto sandbox = sandbox::SandboxManager::GetInstance()->CreateSandbox(sandboxName, runtimeInfo, sandboxKey,
                                                                         networkMode, copyConfig, image, error);
    if (error.NotEmpty()) {
        if (namespace_is_cni(networkMode.c_str())) {
            (void)remove_network_namespace_file(sandboxKey.c_str());
        }
        return response_id;
    }

    // Step 7: Setup networking for the sandbox.
    // Setup sandbox network before create sandbox since the remote create might fail for sandbox
    SetupSandboxNetwork(sandbox, network_setting_json, error);
    if (error.NotEmpty()) {
        goto cleanup_sandbox;
    }

    // Step 8: Save sandbox to disk
    sandbox->Save(error);
    if (error.NotEmpty()) {
        ERROR("Failed to save sandbox, %s", sandboxName.c_str());
        goto cleanup_network;
    }

    // Step 9: Call sandbox create.
    sandbox->Create(error);
    if (error.NotEmpty()) {
        ERROR("Failed to create sandbox: %s", sandboxName.c_str());
        goto cleanup_network;
    }

    msg.container_id = sandbox->GetId().c_str();
    msg.sandbox_id = sandbox->GetId().c_str();
    msg.type = CRI_CONTAINER_MESSAGE_TYPE_CREATED;
    mailbox_publish(MAILBOX_TOPIC_CRI_CONTAINER, &msg);

    // Step 10: Save network settings json to disk
    // Update network settings before start sandbox since sandbox container will use the sandbox key
    if (namespace_is_cni(networkMode.c_str())) {
        Errors tmpErr;
        sandbox->UpdateNetworkSettings(network_setting_json, tmpErr);
        // If saving network settings failed, ignore error
        if (tmpErr.NotEmpty()) {
            WARN("%s", tmpErr.GetCMessage());
        }
    }

    // Step 11: Call sandbox start.
    sandbox->Start(error);
    if (error.NotEmpty()) {
        ERROR("Failed to start sandbox: %s", sandboxName.c_str());
        // If start failed, sandbox should be NotReady, we cleanup network and delete sandbox in remove
        return response_id;
    }

    msg.type = CRI_CONTAINER_MESSAGE_TYPE_STARTED;
    mailbox_publish(MAILBOX_TOPIC_CRI_CONTAINER, &msg);

    return sandbox->GetId();

cleanup_network:
    if (namespace_is_cni(sandbox->GetNetMode().c_str())) {
        Errors clearErr;
        ClearCniNetwork(sandbox, clearErr);
        if (clearErr.NotEmpty()) {
            ERROR("Failed to clean cni network: %s", clearErr.GetCMessage());
            return response_id;
        }
    }

cleanup_sandbox:
    sandbox::SandboxManager::GetInstance()->DeleteSandbox(sandbox->GetId(), error);
    if (error.NotEmpty()) {
        ERROR("Failed to delete sandbox: %s", sandbox->GetId().c_str());
    }

    return response_id;
}

void PodSandboxManagerService::ClearCniNetwork(const std::shared_ptr<sandbox::Sandbox> sandbox, Errors &error)
{
    std::string networkMode = sandbox->GetNetMode();
    if (!namespace_is_cni(networkMode.c_str()) || !sandbox->GetNetworkReady()) {
        return;
    }

    std::string sandboxKey = sandbox->GetNetNsPath();
    if (sandboxKey.size() == 0) {
        error.SetError("Failed to get network namespace path");
        return;
    }

    const auto config = sandbox->GetSandboxConfig();
    std::map<std::string, std::string> stdAnnos;
    CRIHelpers::ProtobufAnnoMapToStd(config.annotations(), stdAnnos);
    stdAnnos.insert(std::pair<std::string, std::string>(CRIHelpers::Constants::POD_SANDBOX_KEY, sandboxKey));

    Errors pluginErr;
    m_pluginManager->TearDownPod(config.metadata().namespace_(), config.metadata().name(),
                                 Network::DEFAULT_NETWORK_INTERFACE_NAME,
                                 sandbox->GetId(), stdAnnos, pluginErr);
    if (pluginErr.NotEmpty()) {
        WARN("TearDownPod cni network failed: %s", pluginErr.GetCMessage());
        error.AppendError(pluginErr.GetMessage());
        return;
    }

    INFO("TearDownPod cni network: success");
    sandbox->SetNetworkReady(false);

    // umount netns when cni removed network successfully
    if (remove_network_namespace(sandboxKey.c_str()) != 0) {
        SYSERROR("Failed to umount directory %s", sandboxKey.c_str());
        error.Errorf("Failed to umount directory %s", sandboxKey.c_str());
    }
}

auto PodSandboxManagerService::GetSandboxKey(const container_inspect *inspect_data) -> std::string
{
    if (inspect_data == nullptr || inspect_data->network_settings == nullptr ||
        inspect_data->network_settings->sandbox_key == nullptr) {
        ERROR("Inspect data does not have network settings");
        return std::string("");
    }

    return std::string(inspect_data->network_settings->sandbox_key);
}

auto PodSandboxManagerService::GetContainerListResponse(const std::string &readSandboxID,
                                                        std::vector<std::string> &errors) -> std::unique_ptr<CStructWrapper<container_list_response>>
{
    int ret = 0;
    container_list_request *list_request { nullptr };
    container_list_response *list_response { nullptr };

    if (m_cb == nullptr || m_cb->container.list == nullptr) {
        ERROR("Unimplemented callback");
        errors.push_back("Unimplemented callback");
        return nullptr;
    }

    // list all containers to stop
    auto list_request_wrapper = makeUniquePtrCStructWrapper<container_list_request>(free_container_list_request);
    if (list_request_wrapper == nullptr) {
        ERROR("Out of memory");
        errors.push_back("Out of memory");
        return nullptr;
    }
    list_request = list_request_wrapper->get();
    list_request->all = true;

    list_request->filters = (defs_filters *)util_common_calloc_s(sizeof(defs_filters));
    if (list_request->filters == nullptr) {
        ERROR("Out of memory");
        errors.push_back("Out of memory");
        return nullptr;
    }

    // Add sandbox label
    if (CRIHelpers::FiltersAddLabel(list_request->filters, CRIHelpers::Constants::SANDBOX_ID_LABEL_KEY,
                                    readSandboxID) != 0) {
        std::string tmp_errmsg = "Failed to add label in sandbox" + readSandboxID;
        ERROR(tmp_errmsg.c_str());
        errors.push_back(tmp_errmsg);
        return nullptr;
    }

    ret = m_cb->container.list(list_request, &list_response);
    auto list_response_wrapper = makeUniquePtrCStructWrapper<container_list_response>(list_response,
                                                                                      free_container_list_response);
    if (list_response_wrapper == nullptr) {
        ERROR("Failed to call list container callback");
        errors.push_back("Failed to call list container callback");
        return nullptr;
    }
    if (ret != 0) {
        if (list_response != nullptr && list_response->errmsg != nullptr) {
            ERROR(list_response->errmsg);
            errors.push_back(list_response->errmsg);
        } else {
            ERROR("Failed to call list container callback");
            errors.push_back("Failed to call list container callback");
        }
        return nullptr;
    }

    return list_response_wrapper;
}

auto PodSandboxManagerService::StopAllContainersInSandbox(const std::string &readSandboxID,
                                                          Errors &error) -> int
{
    int ret = 0;
    std::vector<std::string> errors;
    auto list_response_wrapper = GetContainerListResponse(readSandboxID, errors);
    if (list_response_wrapper == nullptr) {
        error.SetAggregate(errors);
        return -1;
    }
    auto list_response = list_response_wrapper->get();

    // Stop all containers in the sandbox.
    for (size_t i = 0; i < list_response->containers_len; i++) {
        Errors stopError;
        CRIHelpers::StopContainerHelper(m_cb, list_response->containers[i]->id, 0, stopError);
        if (stopError.NotEmpty() && !CRIHelpers::IsContainerNotFoundError(stopError.GetMessage())) {
            ERROR("Error stop container: %s: %s", list_response->containers[i]->id, stopError.GetCMessage());
            error.SetError(stopError.GetMessage());
            return -1;
        }
    }

    return ret;
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

void PodSandboxManagerService::StopPodSandbox(const std::string &podSandboxID, Errors &error)
{
    if (m_cb == nullptr || m_cb->container.stop == nullptr) {
        ERROR("Unimplemented callback");
        error.SetError("Unimplemented callback");
        return;
    }

    INFO("TearDownPod begin");
    if (podSandboxID.empty()) {
        ERROR("Invalid empty sandbox id.");
        error.SetError("Invalid empty sandbox id.");
        return;
    }

    std::shared_ptr<sandbox::Sandbox> sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(podSandboxID);
    if (sandbox == nullptr) {
        ERROR("Failed to find sandbox id %s", podSandboxID.c_str());
        error.Errorf("Failed to find sandbox id %s", podSandboxID.c_str());
        return;
    }

    // Stop all containers inside the sandbox. This terminates the container forcibly,
    // and container may still be created, so production should not rely on this behavior.
    // TODO: according to the state(stopping and removal) in sandbox to avoid future container creation.
    if (StopAllContainersInSandbox(sandbox->GetId(), error) != 0) {
        return;
    }

    ClearCniNetwork(sandbox, error);
    if (error.NotEmpty()) {
        return;
    }

    if (!sandbox->CleanupSandboxFiles(error)) {
        return;
    }

    sandbox->Stop(sandbox::DEFAULT_STOP_TIMEOUT, error);
}

void PodSandboxManagerService::RemoveAllContainersInSandbox(const std::string &readSandboxID,
                                                            std::vector<std::string> &errors)
{
    auto list_response_wrapper = GetContainerListResponse(readSandboxID, errors);
    if (list_response_wrapper == nullptr) {
        return;
    }

    auto list_response = list_response_wrapper->get();

    // Remove all containers in the sandbox.
    for (size_t i = 0; i < list_response->containers_len; i++) {
        Errors rmError;
        CRIHelpers::RemoveContainerHelper(m_cb, list_response->containers[i]->id, rmError);
        if (rmError.NotEmpty() && !CRIHelpers::IsContainerNotFoundError(rmError.GetMessage())) {
            ERROR("Error remove container: %s: %s", list_response->containers[i]->id, rmError.GetCMessage());
            errors.push_back(rmError.GetMessage());
        }
    }
}

void PodSandboxManagerService::ClearNetworkReady(const std::string &podSandboxID)
{
    std::lock_guard<std::mutex> lockGuard(m_networkReadyLock);

    auto iter = m_networkReady.find(podSandboxID);
    if (iter != m_networkReady.end()) {
        m_networkReady.erase(iter);
    }
}

void PodSandboxManagerService::RemovePodSandbox(const std::string &podSandboxID, Errors &error)
{
    std::vector<std::string> errors;
    std::string realSandboxID;

    if (m_cb == nullptr || m_cb->container.remove == nullptr) {
        ERROR("Unimplemented callback");
        error.SetError("Unimplemented callback");
        return;
    }

    if (podSandboxID.empty()) {
        ERROR("Empty pod sandbox id");
        error.SetError("Empty pod sandbox id");
        return;
    }

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(podSandboxID);
    if (sandbox == nullptr) {
        ERROR("Failed to find sandbox id %s", podSandboxID.c_str());
        error.Errorf("Failed to find sandbox id %s", podSandboxID.c_str());
        return;
    }

    // TODO: On sandbox exited by reasons rather than stopp, we might not have cleared the network
    // or cleaned up the sandbox files. For now, 1. we check if the network is ready and then cleared
    // the cni network 2. clean up the sandbox files the second time anyway. Fix it later.
    if (namespace_is_cni(sandbox->GetNetMode().c_str())) {
        if (sandbox->GetNetworkReady()) {
            ClearCniNetwork(sandbox, error);
            if (error.NotEmpty()) {
                ERROR("Failed to clear network that is ready");
                return;
            }
        }

        // Do not return even if removal failed, file in /var/run/... would not remain once reboot
        if (remove_network_namespace_file(sandbox->GetNetNsPath().c_str()) != 0) {
            WARN("Failed to delete networkns file: %s", sandbox->GetNetNsPath().c_str());
        }
    }

    if (!sandbox->CleanupSandboxFiles(error)) {
        ERROR("Failed to clean up sandbox files");
        return;
    }

    // Remove all containers inside the sandbox.
    // container may still be created, so production should not rely on this behavior.
    // TODO: according to the state(stopping and removal) in sandbox to avoid future container creation.
    RemoveAllContainersInSandbox(sandbox->GetId(), errors);
    if (errors.size() != 0) {
        error.SetAggregate(errors);
        return;
    }

    if (!sandbox->Remove(error)) {
        ERROR("Failed to remove sandbox %s: %s", podSandboxID.c_str(), error.GetCMessage());
        return;
    }

    if (!sandbox::SandboxManager::GetInstance()->DeleteSandbox(podSandboxID, error)) {
        ERROR("Failed to delete sandbox %s: %s", podSandboxID.c_str(), error.GetCMessage());
    }

    if (error.Empty()) {
        cri_container_message_t msg = { 0 };
        msg.container_id = sandbox->GetId().c_str();
        msg.sandbox_id = sandbox->GetId().c_str();
        msg.type = CRI_CONTAINER_MESSAGE_TYPE_DELETED;
        mailbox_publish(MAILBOX_TOPIC_CRI_CONTAINER, &msg);
    }
}

auto PodSandboxManagerService::SharesHostNetwork(const container_inspect *inspect) -> runtime::v1::NamespaceMode
{
    if (inspect != nullptr && inspect->host_config != nullptr && (inspect->host_config->network_mode != nullptr) &&
        std::string(inspect->host_config->network_mode) == CRI::Constants::namespaceModeHost) {
        return runtime::v1::NamespaceMode::NODE;
    }
    return runtime::v1::NamespaceMode::POD;
}

auto PodSandboxManagerService::SharesHostPid(const container_inspect *inspect) -> runtime::v1::NamespaceMode
{
    if (inspect != nullptr && inspect->host_config != nullptr && (inspect->host_config->pid_mode != nullptr) &&
        std::string(inspect->host_config->pid_mode) == CRI::Constants::namespaceModeHost) {
        return runtime::v1::NamespaceMode::NODE;
    }
    return runtime::v1::NamespaceMode::CONTAINER;
}

auto PodSandboxManagerService::SharesHostIpc(const container_inspect *inspect) -> runtime::v1::NamespaceMode
{
    if (inspect != nullptr && inspect->host_config != nullptr && (inspect->host_config->ipc_mode != nullptr) &&
        std::string(inspect->host_config->ipc_mode) == CRI::Constants::namespaceModeHost) {
        return runtime::v1::NamespaceMode::NODE;
    }
    return runtime::v1::NamespaceMode::POD;
}

void PodSandboxManagerService::GetIPs(std::shared_ptr<sandbox::Sandbox> sandbox, std::vector<std::string> &ips)
{
    const auto id = sandbox->GetId();
    parser_error err;
    if (sandbox == nullptr) {
        return;
    }

    if (namespace_is_host(sandbox->GetNetMode().c_str())) {
        // For sandboxes using host network, the shim is not responsible for reporting the IP.
        return;
    }

    bool ready = sandbox->GetNetworkReady();
    if (!ready) {
        WARN("Network %s is not ready", id.c_str());
        return;
    }

    std::string networkSettings = sandbox->GetNetworkSettings();
    if (networkSettings.empty()) {
        WARN("NetworkSettings of %s is empty", id.c_str());
        return;
    }

    container_network_settings *network_settings = container_network_settings_parse_data(networkSettings.c_str(), NULL,
                                                                                         &err);
    if (network_settings == NULL) {
        ERROR("Failed to Parse network settings: %s", err);
        return;
    }

    auto settings = std::unique_ptr<CStructWrapper<container_network_settings>>(new
                                                                                CStructWrapper<container_network_settings>(network_settings, free_container_network_settings));
    if (settings == nullptr) {
        ERROR("Out of memory");
        return;
    }

    if (settings->get()->networks == NULL) {
        WARN("NetworkSettings of %s is empty", id.c_str());
        return;
    }

    for (size_t i = 0; i < settings->get()->networks->len; i++) {
        if (settings->get()->networks->values[i] != nullptr &&
            settings->get()->networks->values[i]->ip_address != nullptr) {
            WARN("Use container inspect ip: %s", settings->get()->networks->values[i]->ip_address);
            ips.push_back(settings->get()->networks->values[i]->ip_address);
        }
    }
}

void PodSandboxManagerService::SetSandboxStatusNetwork(std::shared_ptr<sandbox::Sandbox> sandbox,
                                                       std::unique_ptr<runtime::v1::PodSandboxStatus> &podStatus)
{
    std::vector<std::string> ips;
    size_t i;

    GetIPs(sandbox, ips);
    if (ips.size() == 0) {
        return;
    }
    podStatus->mutable_network()->set_ip(ips[0]);

    for (i = 1; i < ips.size(); i++) {
        auto tPoint = podStatus->mutable_network()->add_additional_ips();
        tPoint->set_ip(ips[i]);
    }
}

void PodSandboxManagerService::GetContainerStatuses(const std::string &podSandboxID,
                                                    std::vector<std::unique_ptr<runtime::v1::ContainerStatus>> &containerStatuses,
                                                    std::vector<std::string> &errors) {
    auto list_response_wrapper = GetContainerListResponse(podSandboxID, errors);
    if (list_response_wrapper == nullptr) {
        return;
    }

    auto list_response = list_response_wrapper->get();
    // Remove all containers in the sandbox.
    for (size_t i = 0; i < list_response->containers_len; i++) {
        Errors stError;
        containerStatuses.push_back(CRIHelpersV1::GetContainerStatus(m_cb, list_response->containers[i]->id, stError));
        if (stError.NotEmpty()) {
            ERROR("Error get container status: %s: %s", list_response->containers[i]->id, stError.GetCMessage());
            errors.push_back(stError.GetMessage());
        }
    }
}

std::unique_ptr<runtime::v1::PodSandboxStatus> PodSandboxManagerService::GetPodSandboxStatus(const std::string &podSandboxID, Errors &error)
{
    std::unique_ptr<runtime::v1::PodSandboxStatus> podStatus(new (std::nothrow) runtime::v1::PodSandboxStatus);
    if (podStatus == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return nullptr;
    }

    if (podSandboxID.empty()) {
        ERROR("Empty pod sandbox id");
        error.SetError("Empty pod sandbox id");
        return nullptr;
    }

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(podSandboxID);
    if (sandbox == nullptr) {
        ERROR("Failed to find sandbox id %s", podSandboxID.c_str());
        error.Errorf("Failed to find sandbox id %s", podSandboxID.c_str());
        return nullptr;
    }

    sandbox->Status(*podStatus);

    // add networks
    // get default network status
    SetSandboxStatusNetwork(sandbox, podStatus);
    return podStatus;
}

void PodSandboxManagerService::PodSandboxStatus(const std::string &podSandboxID,
                                                runtime::v1::PodSandboxStatusResponse *reply, Errors &error)
{
    if (reply == nullptr) {
        ERROR("Invalid NULL reply");
        error.SetError("Invalid NULL reply");
        return;
    }

 
    auto podStatus = GetPodSandboxStatus(podSandboxID, error);
    if (error.NotEmpty()) {
        ERROR("Failed to get pod sandbox status: %s", error.GetCMessage());
        return;
    }

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(podSandboxID);
    if (sandbox == nullptr) {
        ERROR("Failed to find sandbox id %s", podSandboxID.c_str());
        error.Errorf("Failed to find sandbox id %s", podSandboxID.c_str());
        return;
    }

    *(reply->mutable_status()) = *podStatus;


    if (!m_enablePodEvents) {
        return;
    }

    std::vector<std::unique_ptr<runtime::v1::ContainerStatus>> containerStatuses;
    std::vector<std::string> errors;
    GetContainerStatuses(sandbox->GetId(), containerStatuses, errors);
    if (errors.size() != 0) {
        error.SetAggregate(errors);
        return;
    }

    for (auto &containerStatus : containerStatuses) {
        *(reply->add_containers_statuses()) = *containerStatus;
    }
    return;
}

void PodSandboxManagerService::ListPodSandbox(const runtime::v1::PodSandboxFilter &filter,
                                              std::vector<std::unique_ptr<runtime::v1::PodSandbox>> &pods,
                                              Errors &error)
{
    std::vector<std::shared_ptr<sandbox::Sandbox>> sandboxes;

    sandbox::SandboxManager::GetInstance()->ListAllSandboxes(filter, sandboxes);

    for (const auto &sandbox : sandboxes) {
        std::unique_ptr<runtime::v1::PodSandbox> pod(new runtime::v1::PodSandbox);

        pod->set_id(sandbox->GetId());
        if (sandbox->IsReady()) {
            pod->set_state(runtime::v1::SANDBOX_READY);
        } else {
            pod->set_state(runtime::v1::SANDBOX_NOTREADY);
        }
        pod->set_created_at(sandbox->GetCreatedAt());

        auto config = sandbox->GetSandboxConfig();

        *pod->mutable_labels() = config.labels();

        *pod->mutable_annotations() = config.annotations();

        *pod->mutable_metadata() = config.metadata();

        pods.push_back(std::move(pod));
    }
}

void PodSandboxManagerService::GetPodSandboxCgroupMetrics(const std::string &cgroupParent,
                                                          cgroup_metrics_t &cgroupMetrics, Errors &error)
{
    int nret { 0 };

    if (cgroupParent.empty()) {
        error.SetError("Invalid cgroup parent");
        return;
    }

    nret = common_get_cgroup_metrics(cgroupParent.c_str(), &cgroupMetrics);
    if (nret != 0) {
        error.Errorf("Failed to get cgroup metrics");
    }
}

auto PodSandboxManagerService::GetNsenterPath(Errors &error) -> std::string
{
    char *err { nullptr };

    auto nsenterPath = look_path(std::string("nsenter").c_str(), &err);
    if (nsenterPath == nullptr) {
        error.SetError(err);
        free(err);
        return std::string();
    }

    auto path = std::string(nsenterPath);
    free(nsenterPath);
    return path;
}

void PodSandboxManagerService::GetPodSandboxNetworkMetrics(const std::string &netnsPath,
                                                           std::map<std::string, std::string> &annotations,
                                                           std::vector<Network::NetworkInterfaceStats> &netMetrics,
                                                           Errors &error)
{
    Errors tmpErr;

    auto nsenterPath = GetNsenterPath(tmpErr);
    if (tmpErr.NotEmpty()) {
        error.Errorf("Failed to get nsenter: %s", tmpErr.GetCMessage());
        return;
    }

    Network::NetworkInterfaceStats netStats;
    Network::GetPodNetworkStats(nsenterPath, netnsPath, Network::DEFAULT_NETWORK_INTERFACE_NAME, netStats, tmpErr);
    if (tmpErr.NotEmpty()) {
        error.Errorf("Failed to get network stats: %s", tmpErr.GetCMessage());
        return;
    }
    netMetrics.push_back(netStats);

    auto networks = CRIHelpers::GetNetworkPlaneFromPodAnno(annotations, tmpErr);
    if (tmpErr.NotEmpty()) {
        WARN("Failed to get network plane: %s", tmpErr.GetCMessage());
        return;
    }
    if (networks == nullptr || networks->len == 0 || networks->items == nullptr) {
        // none extral networks
        return;
    }

    for (size_t i = 0; i < networks->len; i++) {
        if (networks->items[i] == nullptr || networks->items[i]->interface == nullptr) {
            continue;
        }

        Network::NetworkInterfaceStats netStats;
        Network::GetPodNetworkStats(nsenterPath, netnsPath, std::string(networks->items[i]->interface), netStats, tmpErr);
        if (tmpErr.NotEmpty()) {
            WARN("Failed to get network stats: %s", tmpErr.GetCMessage());
            tmpErr.Clear();
            continue;
        }
        netMetrics.push_back(netStats);
    }
}

void PodSandboxManagerService::PackagePodSandboxStatsAttributes(
    const std::string &id, std::unique_ptr<runtime::v1::PodSandboxStats> &podStatsPtr, Errors &error)
{
    auto status = GetPodSandboxStatus(id, error);
    if (error.NotEmpty()) {
        return;
    }

    podStatsPtr->mutable_attributes()->set_id(id);
    if (status->has_metadata()) {
        std::unique_ptr<runtime::v1::PodSandboxMetadata> metadata(
            new (std::nothrow) runtime::v1::PodSandboxMetadata(status->metadata()));
        if (metadata == nullptr) {
            error.SetError("Out of memory");
            return;
        }
        podStatsPtr->mutable_attributes()->set_allocated_metadata(metadata.release());
    }
    if (status->labels_size() > 0) {
        auto labels = podStatsPtr->mutable_attributes()->mutable_labels();
        *labels = status->labels();
    }
    if (status->annotations_size() > 0) {
        auto annotations = podStatsPtr->mutable_attributes()->mutable_annotations();
        *annotations = status->annotations();
    }
}

auto PodSandboxManagerService::GetAvailableBytes(const uint64_t &memoryLimit, const uint64_t &workingSetBytes)
-> uint64_t
{
    // maxMemorySize is define in
    // cadvisor/blob/2b6fbacac7598e0140b5bc8428e3bdd7d86cf5b9/metrics/prometheus.go#L1969-L1971
    const uint64_t maxMemorySize = 1UL << 62;

    if (memoryLimit < maxMemorySize && memoryLimit > workingSetBytes) {
        return memoryLimit - workingSetBytes;
    }

    return 0;
}

void PodSandboxManagerService::PackagePodSandboxContainerStats(
    const std::string &id,
    const std::unique_ptr<ContainerManagerService> &containerManager,
    std::unique_ptr<runtime::v1::PodSandboxStats> &podStatsPtr, Errors &error)
{
    std::vector<std::unique_ptr<runtime::v1::ContainerStats>> containerStats;
    runtime::v1::ContainerStatsFilter filter;

    filter.set_pod_sandbox_id(id);
    containerManager->ListContainerStats(&filter, containerStats, error);
    if (error.NotEmpty()) {
        error.Errorf("Failed to list container stats: %s", error.GetCMessage());
        return;
    }

    for (auto &itor : containerStats) {
        auto container = podStatsPtr->mutable_linux()->add_containers();
        if (container == nullptr) {
            ERROR("Out of memory");
            error.SetError("Out of memory");
            return;
        }
        *container = *itor;
    }
}

void PodSandboxManagerService::PodSandboxStatsToGRPC(const std::string &id, const cgroup_metrics_t &cgroupMetrics,
                                                     const std::vector<Network::NetworkInterfaceStats> &netMetrics,
                                                     const std::unique_ptr<ContainerManagerService> &containerManager,
                                                     std::unique_ptr<runtime::v1::PodSandboxStats> &podStats,
                                                     sandbox::StatsInfo &oldStatsRec,
                                                     Errors &error)
{
    std::unique_ptr<runtime::v1::PodSandboxStats> podStatsPtr(
        new (std::nothrow) runtime::v1::PodSandboxStats);
    if (podStatsPtr == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return;
    }

    PackagePodSandboxStatsAttributes(id, podStatsPtr, error);
    if (error.NotEmpty()) {
        return;
    }

    int64_t timestamp = util_get_now_time_nanos();
    // CPU
    auto cpu = podStatsPtr->mutable_linux()->mutable_cpu();
    cpu->set_timestamp(timestamp);
    cpu->mutable_usage_core_nano_seconds()->set_value(cgroupMetrics.cgcpu_metrics.cpu_use_nanos);
    if (oldStatsRec.cpuUseNanos != 0 && timestamp > oldStatsRec.timestamp &&
        cgroupMetrics.cgcpu_metrics.cpu_use_nanos > oldStatsRec.cpuUseNanos) {
        uint64_t usage = cgroupMetrics.cgcpu_metrics.cpu_use_nanos - oldStatsRec.cpuUseNanos;
        uint64_t nanoSeconds = timestamp - oldStatsRec.timestamp;
        uint64_t usage_nano_cores = (uint64_t)(((double)usage / (double)nanoSeconds) * (double)Time_Second);
        cpu->mutable_usage_nano_cores()->set_value(usage_nano_cores);
    }

    // Memory
    auto memory = podStatsPtr->mutable_linux()->mutable_memory();
    uint64_t workingSetBytes = 0;
    if (cgroupMetrics.cgmem_metrics.mem_used > cgroupMetrics.cgmem_metrics.total_inactive_file) {
        workingSetBytes = cgroupMetrics.cgmem_metrics.mem_used - cgroupMetrics.cgmem_metrics.total_inactive_file;
    }
    uint64_t availableBytes = GetAvailableBytes(cgroupMetrics.cgmem_metrics.mem_limit, workingSetBytes);

    memory->set_timestamp(timestamp);
    memory->mutable_working_set_bytes()->set_value(workingSetBytes);
    memory->mutable_available_bytes()->set_value(availableBytes);
    memory->mutable_usage_bytes()->set_value(cgroupMetrics.cgmem_metrics.mem_used);
    memory->mutable_rss_bytes()->set_value(cgroupMetrics.cgmem_metrics.total_rss);
    memory->mutable_page_faults()->set_value(cgroupMetrics.cgmem_metrics.total_pgfault);
    memory->mutable_major_page_faults()->set_value(cgroupMetrics.cgmem_metrics.total_pgmajfault);

    // Network
    if (netMetrics.size() > 0) {
        auto network = podStatsPtr->mutable_linux()->mutable_network();
        network->set_timestamp(timestamp);
        network->mutable_default_interface()->set_name(netMetrics[0].name);
        network->mutable_default_interface()->mutable_rx_bytes()->set_value(netMetrics[0].rxBytes);
        network->mutable_default_interface()->mutable_rx_errors()->set_value(netMetrics[0].rxErrors);
        network->mutable_default_interface()->mutable_tx_bytes()->set_value(netMetrics[0].txBytes);
        network->mutable_default_interface()->mutable_tx_errors()->set_value(netMetrics[0].txErrors);

        for (size_t i = 1; i < netMetrics.size(); i++) {
            auto extra = network->add_interfaces();
            extra->set_name(netMetrics[i].name);
            extra->mutable_rx_bytes()->set_value(netMetrics[i].rxBytes);
            extra->mutable_rx_errors()->set_value(netMetrics[i].rxErrors);
            extra->mutable_tx_bytes()->set_value(netMetrics[i].txBytes);
            extra->mutable_tx_errors()->set_value(netMetrics[i].txErrors);
        }
    }

    // Process
    auto process = podStatsPtr->mutable_linux()->mutable_process();
    process->set_timestamp(timestamp);
    process->mutable_process_count()->set_value(cgroupMetrics.cgpids_metrics.pid_current);

    PackagePodSandboxContainerStats(id, containerManager, podStatsPtr, error);
    if (error.NotEmpty()) {
        return;
    }

    podStats = move(podStatsPtr);
    return;
}

auto PodSandboxManagerService::PodSandboxStats(const std::string &podSandboxID,
                                               const std::unique_ptr<ContainerManagerService> &containerManager,
                                               Errors &error) -> std::unique_ptr<runtime::v1::PodSandboxStats>
{
    Errors tmpErr;
    cgroup_metrics_t cgroupMetrics { 0 };
    std::vector<Network::NetworkInterfaceStats> netMetrics;
    std::map<std::string, std::string> annotations;
    std::unique_ptr<runtime::v1::PodSandboxStats> podStats { nullptr };

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(podSandboxID);
    if (sandbox == nullptr) {
        ERROR("Failed to find sandbox id %s", podSandboxID.c_str());
        error.Errorf("Failed to find sandbox id %s", podSandboxID.c_str());
        return nullptr;
    }
    auto &config = sandbox->GetSandboxConfig();
    auto oldStatsRec = sandbox->GetStatsInfo();

    auto status = GetPodSandboxStatus(sandbox->GetId(), tmpErr);
    if (tmpErr.NotEmpty()) {
        ERROR("Failed to get podsandbox %s status: %s", sandbox->GetId().c_str(), tmpErr.GetCMessage());
        error.Errorf("Failed to get podsandbox %s status", sandbox->GetId().c_str());
        return nullptr;
    }
    CRIHelpers::ProtobufAnnoMapToStd(status->annotations(), annotations);

    GetPodSandboxCgroupMetrics(config.linux().cgroup_parent(), cgroupMetrics, tmpErr);
    if (tmpErr.NotEmpty()) {
        ERROR("Failed to get cgroup metrics of sandbox id %s: %s", podSandboxID.c_str(), tmpErr.GetCMessage());
        error.Errorf("Failed to get cgroup metrics of sandbox id %s", podSandboxID.c_str());
        return nullptr;
    }

    GetPodSandboxNetworkMetrics(sandbox->GetNetNsPath(), annotations, netMetrics, tmpErr);
    if (tmpErr.NotEmpty()) {
        WARN("Failed to get network metrics of sandbox id %s: %s", podSandboxID.c_str(), tmpErr.GetCMessage());
        tmpErr.Clear();
    }

    PodSandboxStatsToGRPC(sandbox->GetId(), cgroupMetrics, netMetrics, containerManager, podStats, oldStatsRec, tmpErr);
    if (tmpErr.NotEmpty()) {
        ERROR("Failed to set PodSandboxStats: %s", tmpErr.GetCMessage());
        error.Errorf("Failed to set PodSandboxStats");
        return nullptr;
    }

    // update stats info that sandbox recorded
    sandbox::StatsInfo newStatsRec { podStats->linux().cpu().timestamp(), podStats->linux().cpu().usage_core_nano_seconds().value() };
    sandbox->UpdateStatsInfo(newStatsRec);

    return podStats;
}

void PodSandboxManagerService::GetFilterPodSandbox(const runtime::v1::PodSandboxStatsFilter *filter,
                                                   std::vector<std::string> &podSandboxIDs, Errors &error)
{
    int ret = 0;
    container_list_request *request { nullptr };
    container_list_response *response { nullptr };

    if (m_cb == nullptr || m_cb->container.list == nullptr) {
        error.SetError("Unimplemented callback list");
        return;
    }

    request = (container_list_request *)util_common_calloc_s(sizeof(container_list_request));
    if (request == nullptr) {
        error.SetError("Out of memory");
        return;
    }
    request->filters = (defs_filters *)util_common_calloc_s(sizeof(defs_filters));
    if (request->filters == nullptr) {
        error.SetError("Out of memory");
        goto cleanup;
    }
    // only get running pod metrics
    request->all = false;

    // add filter
    if (CRIHelpers::FiltersAddLabel(request->filters, CRIHelpers::Constants::CONTAINER_TYPE_LABEL_KEY,
                                    CRIHelpers::Constants::CONTAINER_TYPE_LABEL_SANDBOX) != 0) {
        error.Errorf("Failed to add label %s", CRIHelpers::Constants::CONTAINER_TYPE_LABEL_KEY.c_str());
        goto cleanup;
    }
    if (filter != nullptr) {
        if (!filter->id().empty()) {
            if (CRIHelpers::FiltersAdd(request->filters, "id", filter->id()) != 0) {
                error.SetError("Failed to add label id");
                goto cleanup;
            }
        }
        for (auto &iter : filter->label_selector()) {
            if (CRIHelpers::FiltersAddLabel(request->filters, iter.first, iter.second) != 0) {
                error.Errorf("Failed to add label %s", iter.first.c_str());
                goto cleanup;
            }
        }
    }

    ret = m_cb->container.list(request, &response);
    if (ret != 0) {
        if (response != nullptr && (response->errmsg != nullptr)) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call list container callback");
        }
        goto cleanup;
    }

    for (size_t i = 0; i < response->containers_len; i++) {
        podSandboxIDs.push_back(response->containers[i]->id);
    }

cleanup:
    free_container_list_request(request);
    free_container_list_response(response);
}

void PodSandboxManagerService::ListPodSandboxStats(const runtime::v1::PodSandboxStatsFilter *filter,
                                                   const std::unique_ptr<ContainerManagerService> &containerManager,
                                                   std::vector<std::unique_ptr<runtime::v1::PodSandboxStats>> &podsStats,
                                                   Errors &error)
{
    std::vector<std::string> podSandboxIDs;

    GetFilterPodSandbox(filter, podSandboxIDs, error);
    if (error.NotEmpty()) {
        ERROR("Failed to get podsandbox filter: %s", error.GetCMessage());
        error.SetError("Failed to get podsandbox filter");
        return;
    }

    if (podSandboxIDs.size() == 0) {
        // none ready pods
        return;
    }

    for (auto &id : podSandboxIDs) {
        Errors tmpErr;
        auto podStats = PodSandboxStats(id, containerManager, tmpErr);
        if (podStats == nullptr) {
            WARN("Failed to get podSandbox %s stats: %s", id.c_str(), tmpErr.GetCMessage());
            continue;
        }

        podsStats.push_back(move(podStats));
    }
}

void PodSandboxManagerService::PortForward(const runtime::v1::PortForwardRequest &req,
                                           runtime::v1::PortForwardResponse *resp, Errors &error)
{
    // This feature is temporarily not supported
}

} // namespace CRI
