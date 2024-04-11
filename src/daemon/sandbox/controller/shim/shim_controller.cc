/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-07-06
 * Description: provide shim controller implementation
 *********************************************************************************/

#include "shim_controller.h"

#include <thread>
#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/log.h>
#include <isula_libutils/utils_memory.h>

#include "cri_helpers.h"
#include "namespace.h"
#include "service_container_api.h"
#include "utils.h"
#include "v1_cri_helpers.h"
#include "v1_cri_security_context.h"

namespace sandbox {

ShimController::ShimController(const std::string &sandboxer): m_sandboxer(sandboxer) {}

ShimController::~ShimController() {}

bool ShimController::Init(Errors &error)
{
    // Assembly implementation for CRIRuntimeServiceImpl
    m_cb = get_service_executor();
    if (m_cb == nullptr) {
        ERROR("Fail to register shim controller.");
        error.SetError("Fail to register shim controller.");
        return false;
    }
    return true;
}

void ShimController::Destroy() {}

void ShimController::ApplySandboxLinuxOptions(const runtime::v1::LinuxPodSandboxConfig &lc, host_config *hc,
                                              container_config *custom_config, Errors &error)
{
    CRISecurityV1::ApplySandboxSecurityContext(lc, custom_config, hc, error);
    if (error.NotEmpty()) {
        ERROR("Failed to apply sandbox security context");
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
        ERROR("Too many sysctls, the limit is %lld", LIST_SIZE_MAX);
        error.Errorf("Too many sysctls, the limit is %lld", LIST_SIZE_MAX);
        return;
    }
    hc->sysctls = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if (hc->sysctls == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return;
    }

    auto iter = lc.sysctls().begin();
    while (iter != lc.sysctls().end()) {
        if (append_json_map_string_string(hc->sysctls, iter->first.c_str(), iter->second.c_str()) != 0) {
            ERROR("Failed to append sysctl");
            error.SetError("Failed to append sysctl");
            return;
        }
        ++iter;
    }
}

void ShimController::MakeSandboxIsuladConfig(const runtime::v1::PodSandboxConfig &config,
                                             host_config *hostConfig, container_config *customConfig,
                                             const std::string &networkMode, Errors &error)
{
    customConfig->labels = CRIHelpers::MakeLabels(config.labels(), error);
    if (error.NotEmpty()) {
        ERROR("Failed to make labels for sandbox config");
        return;
    }

    customConfig->annotations = CRIHelpers::MakeAnnotations(config.annotations(), error);
    if (error.NotEmpty()) {
        ERROR("Failed to make annotations for sandbox config");
        return;
    }

    if (!config.hostname().empty()) {
        customConfig->hostname = util_strdup_s(config.hostname().c_str());
    }

    hostConfig->network_mode = util_strdup_s(networkMode.c_str());

    // Since in UpdateSandoxConfig, linux is set for resources no matter what
    // Return error if we do not have linux config
    if (!config.has_linux() || !config.linux().has_resources()) {
        ERROR("Pod sandbox config does not have linux config or resources");
        error.SetError("Pod sandbox config does not have linux config or resources");
        return;
    }

    // sandbox resources
    hostConfig->memory_swap = config.linux().resources().memory_swap_limit_in_bytes();
    hostConfig->cpu_shares = config.linux().resources().cpu_shares();
    hostConfig->cpu_quota = config.linux().resources().cpu_quota();
    hostConfig->cpu_period = config.linux().resources().cpu_period();
    hostConfig->memory = config.linux().resources().memory_limit_in_bytes();

    hostConfig->oom_score_adj = config.linux().resources().oom_score_adj();

    ApplySandboxLinuxOptions(config.linux(), hostConfig, customConfig, error);
    if (error.NotEmpty()) {
        return;
    }

    // Security Opts
    if (!config.linux().has_security_context()) {
        return;
    }

    const ::runtime::v1::LinuxSandboxSecurityContext &context = config.linux().security_context();
    CRIHelpersV1::ApplySandboxSecurityContextToHostConfig(context, hostConfig, error);
    if (error.NotEmpty()) {
        ERROR("Failed to apply sandbox security context to host config for sandbox: %s",
              config.metadata().name().c_str());
        return;
    }
}

auto ShimController::GenerateSandboxInfo(const std::string &sandboxId,
                                         const ControllerCreateParams &params,
                                         Errors &err) -> container_sandbox_info *
{
    auto sandboxInfoWrapper = makeUniquePtrCStructWrapper<container_sandbox_info>(free_container_sandbox_info);
    if (sandboxInfoWrapper == nullptr) {
        ERROR("Failed to generate sandbox info, out of memory");
        err.SetError("Failed to generate sandbox info, out of memory");
        return nullptr;
    }
    auto sandboxInfo = sandboxInfoWrapper->get();

    sandboxInfo->id = isula_strdup_s(sandboxId.c_str());
    sandboxInfo->sandboxer = isula_strdup_s(params.sandboxer.c_str());
    sandboxInfo->hostname = isula_strdup_s(params.hostname.c_str());
    sandboxInfo->hostname_path = isula_strdup_s(params.hostnamePath.c_str());
    sandboxInfo->hosts_path = isula_strdup_s(params.hostsPath.c_str());
    sandboxInfo->resolv_conf_path = isula_strdup_s(params.resolvConfPath.c_str());
    sandboxInfo->shm_path = isula_strdup_s(params.shmPath.c_str());
    sandboxInfo->is_sandbox_container = true;

    return sandboxInfoWrapper->move();
}

auto ShimController::PackCreateContainerRequest(const std::string &sandboxId,
                                                const ControllerCreateParams &params,
                                                host_config *hostconfig, container_config *customconfig,
                                                Errors &error) -> std::unique_ptr<CStructWrapper<container_create_request>>
{
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    __isula_auto_free parser_error perror = nullptr;
    auto requestWrapper = makeUniquePtrCStructWrapper<container_create_request>(free_container_create_request);
    if (requestWrapper == nullptr) {
        ERROR("Out of memory");
        error.Errorf("Out of memory");
        return nullptr;
    }
    auto request = requestWrapper->get();

    request->id = isula_strdup_s(params.sandboxName.c_str());

    request->runtime = isula_strdup_s(params.runtime.c_str());

    request->image = isula_strdup_s(params.image.c_str());

    request->sandbox = GenerateSandboxInfo(sandboxId, params, error);
    if (error.NotEmpty()) {
        ERROR("Failed to generate sandbox info");
        error.Errorf("Failed to generate sandbox info");
        return nullptr;
    }

    request->hostconfig = host_config_generate_json(hostconfig, &ctx, &perror);
    if (request->hostconfig == nullptr) {
        ERROR("Failed to generate host config json: %s", perror);
        error.Errorf("Failed to generate host config json: %s", perror);
        return nullptr;
    }

    request->customconfig = container_config_generate_json(customconfig, &ctx, &perror);
    if (request->customconfig == nullptr) {
        ERROR("Failed to generate custom config json: %s", perror);
        error.Errorf("Failed to generate custom config json: %s", perror);
        return nullptr;
    }

    return requestWrapper;
}

auto ShimController::GenerateSandboxCreateContainerRequest(const std::string &sandboxId,
                                                           const ControllerCreateParams &params,
                                                           Errors &error) -> std::unique_ptr<CStructWrapper<container_create_request>>
{
    if (params.config == nullptr) {
        ERROR("Invalid params");
        error.SetError("Invalid prams");
        return nullptr;
    }
    auto &config = *params.config;

    auto hostConfigWrapper = makeUniquePtrCStructWrapper<host_config>(free_host_config);
    if (hostConfigWrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return nullptr;
    }

    auto customConfigWrapper = makeUniquePtrCStructWrapper<container_config>(free_container_config);
    if (customConfigWrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return nullptr;
    }

    MakeSandboxIsuladConfig(config, hostConfigWrapper->get(), customConfigWrapper->get(), params.netMode, error);
    if (error.NotEmpty()) {
        ERROR("Failed to make sandbox config for pod %s: %s", config.metadata().name().c_str(), error.GetCMessage());
        error.Errorf("Failed to make sandbox config for pod %s: %s", config.metadata().name().c_str(),
                     error.GetCMessage());
        return nullptr;
    }

    auto requestWrapper = PackCreateContainerRequest(sandboxId, params, hostConfigWrapper->get(),
                                                     customConfigWrapper->get(), error);
    if (requestWrapper == nullptr) {
        ERROR("Failed to pack create container request");
        error.SetError("Failed to pack create container request");
    }

    return requestWrapper;
}

bool ShimController::Create(const std::string &sandboxId,
                            const ControllerCreateParams &params,
                            Errors &error)
{
    if (m_cb == nullptr || m_cb->container.create == nullptr) {
        ERROR("Unimplemented callback");
        error.SetError("Unimplemented callback");
        return false;
    }

    auto requestWrapper = GenerateSandboxCreateContainerRequest(sandboxId, params, error);
    if (error.NotEmpty()) {
        return false;
    }

    container_create_response *response {nullptr};
    int ret = m_cb->container.create(requestWrapper->get(), &response);
    auto responseWrapper = makeUniquePtrCStructWrapper<container_create_response>(response, free_container_create_response);

    if (ret != 0) {
        if (response != nullptr && (response->errmsg != nullptr)) {
            ERROR("Failed to call create container callback: %s", response->errmsg);
            error.SetError(response->errmsg);
        } else {
            ERROR("Failed to call create container callback");
            error.SetError("Failed to call create container callback");
        }
    }

    return error.Empty();
}

std::unique_ptr<ControllerSandboxInfo> ShimController::Start(const std::string &sandboxId, Errors &error)
{
    std::unique_ptr<ControllerSandboxInfo> sandboxInfo(new ControllerSandboxInfo());
    auto requestWrapper = makeUniquePtrCStructWrapper<container_start_request>(free_container_start_request);
    if (requestWrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return nullptr;
    }
    requestWrapper->get()->id = isula_strdup_s(sandboxId.c_str());

    container_start_response *response {nullptr};

    int ret = m_cb->container.start(requestWrapper->get(), &response, -1, nullptr, nullptr);
    auto responseWrapper = makeUniquePtrCStructWrapper<container_start_response>(response, free_container_start_response);

    if (ret != 0) {
        if (response != nullptr && (response->errmsg != nullptr)) {
            ERROR("Failed to call start container callback: %s", response->errmsg);
            error.SetError(response->errmsg);
        } else {
            ERROR("Failed to call start container callback");
            error.SetError("Failed to call start container callback");
        }
        return nullptr;
    }

    auto podStatus = Status(sandboxId, false, error);
    if (error.NotEmpty()) {
        ERROR("Failed to get sandbox status: %s", error.GetCMessage());
        Errors tempError;
        if (!Stop(sandboxId, 0, tempError)) {
            ERROR("Failed to stop sandbox %s: %s", sandboxId.c_str(), tempError.GetCMessage());
        }
        return nullptr;
    }

    sandboxInfo->id = podStatus->id;
    sandboxInfo->pid = podStatus->pid;
    sandboxInfo->createdAt = podStatus->createdAt;
    sandboxInfo->labels = podStatus->info;

    return sandboxInfo;
}

std::unique_ptr<ControllerPlatformInfo> ShimController::Platform(const std::string &sandboxId, Errors &error)
{
    error.SetError("Not supported");
    return nullptr;
}

std::string ShimController::Prepare(const std::string &sandboxId,
                                    const ControllerPrepareParams &params,
                                    Errors &error)
{
    return std::string("");
}

bool ShimController::Purge(const std::string &sandboxId, const std::string &containerId,
                           const std::string &execId, Errors &error)
{
    return true;
}

bool ShimController::UpdateResources(const std::string &sandboxId,
                                     const ControllerUpdateResourcesParams &params,
                                     Errors &error)
{
    return true;
}

bool ShimController::Stop(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error)
{
    // Termination grace period
    constexpr int32_t DefaultSandboxGracePeriod { 10 };

    if (m_cb == nullptr || m_cb->container.stop == nullptr) {
        ERROR("Unimplemented callback");
        error.SetError("Unimplemented callback");
        return false;
    }

    auto requestWrapper = makeUniquePtrCStructWrapper<container_stop_request>(free_container_stop_request);
    if (requestWrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }
    auto request = requestWrapper->get();

    request->id = isula_strdup_s(sandboxId.c_str());
    request->timeout = DefaultSandboxGracePeriod;
    container_stop_response *response { nullptr };

    int ret = m_cb->container.stop(request, &response);
    auto responseWrapper = makeUniquePtrCStructWrapper<container_stop_response>(response, free_container_stop_response);

    if (ret != 0) {
        std::string msg = (response != nullptr && response->errmsg != nullptr) ? response->errmsg : "internal";
        ERROR("Failed to stop sandbox %s: %s", sandboxId.c_str(), msg.c_str());
        error.SetError(msg);
    }

    return error.Empty();
}

bool ShimController::Wait(std::shared_ptr<SandboxStatusCallback> cb, const std::string &sandboxId, Errors &error)
{
    // ShimController will use sandbox_on_exit callback of supervisor in lower container level
    // to notify the sandbox exit event
    return true;
}

void ShimController::GetContainerTimeStamps(const container_inspect *inspect, int64_t *createdAt, int64_t *startedAt,
                                            int64_t *finishedAt, Errors &err)
{
    if (inspect == nullptr) {
        ERROR("Invalid arguments");
        err.SetError("Invalid arguments");
        return;
    }
    if (createdAt != nullptr) {
        if (util_to_unix_nanos_from_str(inspect->created, createdAt) != 0) {
            ERROR("Parse createdAt failed: %s", inspect->created);
            err.Errorf("Parse createdAt failed: %s", inspect->created);
            return;
        }
    }
    if (inspect->state == nullptr) {
        return;
    }

    if (startedAt != nullptr) {
        if (util_to_unix_nanos_from_str(inspect->state->started_at, startedAt) != 0) {
            ERROR("Parse startedAt failed: %s", inspect->state->started_at);
            err.Errorf("Parse startedAt failed: %s", inspect->state->started_at);
            return;
        }
    }
    if (finishedAt != nullptr) {
        if (util_to_unix_nanos_from_str(inspect->state->finished_at, finishedAt) != 0) {
            ERROR("Parse finishedAt failed: %s", inspect->state->finished_at);
            err.Errorf("Parse finishedAt failed: %s", inspect->state->finished_at);
            return;
        }
    }
}

void ShimController::InspectResponseToSandboxStatus(container_inspect *inspect,
                                                    ControllerSandboxStatus &sandboxStatus,
                                                    Errors &error)
{
    int64_t createdAt {};
    int64_t finishedAt {};
    sandboxStatus.id = inspect->id;
    if (inspect->state != nullptr) {
        sandboxStatus.pid = inspect->state->pid;
        if (inspect->state->status != nullptr) {
            sandboxStatus.state = std::string(inspect->state->status);
        }
    }

    GetContainerTimeStamps(inspect, &createdAt, nullptr, &finishedAt, error);
    if (error.NotEmpty()) {
        return;
    }
    if (createdAt < 0 || finishedAt < 0) {
        ERROR("Failed to convert created time or finished time to nanoseconds");
        error.SetError("Failed to convert created time or finished time to nanoseconds");
        return;
    }
    sandboxStatus.createdAt = static_cast<uint64_t>(createdAt);
    sandboxStatus.exitedAt = static_cast<uint64_t>(finishedAt);

    if (inspect->process_label != nullptr) {
        sandboxStatus.info["selinux_label"] = inspect->process_label;
    }
}

std::unique_ptr<ControllerSandboxStatus> ShimController::Status(const std::string &sandboxId, bool verbose,
                                                                Errors &error)
{
    std::unique_ptr<ControllerSandboxStatus> sandboxStatus(new ControllerSandboxStatus());

    if (sandboxId.empty()) {
        ERROR("Empty pod sandbox id");
        error.SetError("Empty pod sandbox id");
        return nullptr;
    }

    auto inspect = CRIHelpers::InspectContainer(sandboxId, error, true);
    if (error.NotEmpty()) {
        ERROR("Inspect pod failed: %s", error.GetCMessage());
        return nullptr;
    }

    auto inspectWrapper = makeUniquePtrCStructWrapper<container_inspect>(inspect, free_container_inspect);
    InspectResponseToSandboxStatus(inspect, *sandboxStatus, error);
    if (error.NotEmpty()) {
        ERROR("Failed to convert inspect response to sandbox status: %s", error.GetCMessage());
        return nullptr;
    }

    return sandboxStatus;
}

bool ShimController::Shutdown(const std::string &sandboxId, Errors &error)
{
    if (m_cb == nullptr || m_cb->container.remove == nullptr) {
        ERROR("Unimplemented callback");
        error.SetError("Unimplemented callback");
        return false;
    }

    auto requestWrapper = makeUniquePtrCStructWrapper<container_delete_request>(free_container_delete_request);
    if (requestWrapper == nullptr) {
        ERROR("Out of memory");
        error.SetError("Out of memory");
        return false;
    }

    auto request = requestWrapper->get();
    request->id = isula_strdup_s(sandboxId.c_str());
    request->force = true;

    container_delete_response *response {nullptr};
    int ret = m_cb->container.remove(request, &response);
    auto responseWrapper = makeUniquePtrCStructWrapper<container_delete_response>(response, free_container_delete_response);
    if (ret == 0) {
        return true;
    }

    std::string errMsg = "internal";
    if (response != nullptr && response->errmsg != nullptr) {
        if (strstr(response->errmsg, "No such container") != nullptr) {
            ERROR("Container for sandbox %s not found", sandboxId.c_str());
            return true;
        }
        errMsg = response->errmsg;
    }
    ERROR("Failed to remove sandbox %s: %s", sandboxId.c_str(), errMsg.c_str());
    error.SetError(errMsg);
    return error.Empty();
}

bool ShimController::UpdateNetworkSettings(const std::string &sandboxId, const std::string &networkSettings,
                                           Errors &error)
{
    if (networkSettings.empty()) {
        return true;
    }

    if (m_cb == nullptr || m_cb->container.update_network_settings == nullptr) {
        ERROR("Unimplemented callback");
        error.SetError("Unimplemented callback");
        return false;
    }

    auto requestWrapper = makeUniquePtrCStructWrapper<container_update_network_settings_request>(
                              free_container_update_network_settings_request);
    if (requestWrapper == nullptr) {
        ERROR("container update network settings request: Out of memory");
        error.Errorf("container update network settings request: Out of memory");
        return false;
    }
    auto request = requestWrapper->get();
    request->id = isula_strdup_s(sandboxId.c_str());
    request->setting_json = isula_strdup_s(networkSettings.c_str());

    container_update_network_settings_response *response { nullptr };
    int ret = m_cb->container.update_network_settings(request, &response);
    auto responseWrapper = makeUniquePtrCStructWrapper<container_update_network_settings_response>(
                               response, free_container_update_network_settings_response);

    if (ret != 0) {
        if (response != nullptr && response->errmsg != nullptr) {
            ERROR("Failed to update container network settings: %s", response->errmsg);
            error.SetError(response->errmsg);
        } else {
            ERROR("Failed to update container network settings");
            error.SetError("Failed to update container network settings");
        }
    }

    return error.Empty();
}

} // namespace
