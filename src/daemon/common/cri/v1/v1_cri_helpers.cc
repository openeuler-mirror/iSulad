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
 * Description: provide cni network plugin
 *********************************************************************************/
#include "v1_cri_helpers.h"
#include "constants.h"
#include <algorithm>
#include <functional>
#include <iostream>
#include <sys/utsname.h>
#include <utility>

#include <isula_libutils/log.h>
#include <isula_libutils/parse_common.h>
#include <isula_libutils/auto_cleanup.h>

#include "v1_cri_security_context.h"
#include "cri_helpers.h"
#include "cri_constants.h"
#include "cxxutils.h"
#include "path.h"
#include "utils.h"
#include "service_container_api.h"
#include "isulad_config.h"
#include "sha256.h"
#include "v1_naming.h"
#ifdef ENABLE_CDI
#include "cdi_operate_api.h"
#endif /* ENABLE_CDI */

namespace CRIHelpersV1 {

auto ContainerStatusToRuntime(Container_Status status) -> runtime::v1::ContainerState
{
    switch (status) {
        case CONTAINER_STATUS_CREATED:
        case CONTAINER_STATUS_STARTING:
            return runtime::v1::CONTAINER_CREATED;
        case CONTAINER_STATUS_PAUSED:
        case CONTAINER_STATUS_RESTARTING:
        case CONTAINER_STATUS_RUNNING:
            return runtime::v1::CONTAINER_RUNNING;
        case CONTAINER_STATUS_STOPPED:
            return runtime::v1::CONTAINER_EXITED;
        default:
            return runtime::v1::CONTAINER_UNKNOWN;
    }
}

auto CheckpointToSandbox(const std::string &id, const CRI::PodSandboxCheckpoint &checkpoint)
-> std::unique_ptr<runtime::v1::PodSandbox>
{
    std::unique_ptr<runtime::v1::PodSandbox> result(new (std::nothrow) runtime::v1::PodSandbox);
    if (result == nullptr) {
        return nullptr;
    }
    runtime::v1::PodSandboxMetadata *metadata = new (std::nothrow) runtime::v1::PodSandboxMetadata;
    if (metadata == nullptr) {
        return nullptr;
    }

    metadata->set_name(checkpoint.GetName());
    metadata->set_namespace_(checkpoint.GetNamespace());
    result->set_allocated_metadata(metadata);
    result->set_id(id);
    result->set_state(runtime::v1::SANDBOX_NOTREADY);

    return result;
}

void UpdateCreateConfig(container_config *createConfig, host_config *hc,
                        const runtime::v1::ContainerConfig &config, const std::string &podSandboxID,
                        Errors &error)
{
    if (createConfig == nullptr || hc == nullptr) {
        return;
    }
    DEBUG("Apply security context");
    CRISecurityV1::ApplyContainerSecurityContext(config.linux(), podSandboxID, createConfig, hc, error);
    if (error.NotEmpty()) {
        error.SetError("failed to apply container security context for container " + config.metadata().name() + ": " +
                       error.GetCMessage());
        return;
    }
    if (config.linux().has_resources()) {
        runtime::v1::LinuxContainerResources rOpts = config.linux().resources();
        hc->memory = rOpts.memory_limit_in_bytes();
        hc->memory_swap = rOpts.memory_swap_limit_in_bytes();
        hc->cpu_shares = rOpts.cpu_shares();
        hc->cpu_quota = rOpts.cpu_quota();
        hc->cpu_period = rOpts.cpu_period();
        if (!rOpts.cpuset_cpus().empty()) {
            hc->cpuset_cpus = util_strdup_s(rOpts.cpuset_cpus().c_str());
        }
        if (!rOpts.cpuset_mems().empty()) {
            hc->cpuset_mems = util_strdup_s(rOpts.cpuset_mems().c_str());
        }
        hc->oom_score_adj = rOpts.oom_score_adj();

        if (!rOpts.unified().empty()) {
            hc->unified = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
            if (hc->unified == nullptr) {
                error.SetError("Out of memory");
                return;
            }
            for (auto &iter : rOpts.unified()) {
                if (append_json_map_string_string(hc->unified, iter.first.c_str(), iter.second.c_str()) != 0) {
                    error.SetError("Failed to append string");
                    return;
                }
            }
        }

        if (rOpts.hugepage_limits_size() != 0) {
            hc->hugetlbs = (host_config_hugetlbs_element **)util_smart_calloc_s(sizeof(host_config_hugetlbs_element *),
                                                                                rOpts.hugepage_limits_size());
            if (hc->hugetlbs == nullptr) {
                error.SetError("Out of memory");
                return;
            }
            for (int i = 0; i < rOpts.hugepage_limits_size(); i++) {
                hc->hugetlbs[i] =
                    (host_config_hugetlbs_element *)util_common_calloc_s(sizeof(host_config_hugetlbs_element));
                if (hc->hugetlbs[i] == nullptr) {
                    error.SetError("Out of memory");
                    return;
                }
                hc->hugetlbs[i]->page_size = util_strdup_s(rOpts.hugepage_limits(i).page_size().c_str());
                hc->hugetlbs[i]->limit = rOpts.hugepage_limits(i).limit();
                hc->hugetlbs_len++;
            }
        }
    }
    createConfig->open_stdin = config.stdin();
    createConfig->tty = config.tty();
}

void GenerateMountBindings(const google::protobuf::RepeatedPtrField<runtime::v1::Mount> &mounts,
                           host_config *hostconfig, Errors &err)
{
    if (mounts.empty() || hostconfig == nullptr) {
        return;
    }

    hostconfig->binds = (char **)util_smart_calloc_s(sizeof(char *), mounts.size());
    if (hostconfig->binds == nullptr) {
        err.SetError("Out of memory");
        return;
    }
    for (int i = 0; i < mounts.size(); i++) {
        std::string bind = mounts[i].host_path() + ":" + mounts[i].container_path();
        std::vector<std::string> attrs;
        if (mounts[i].readonly()) {
            attrs.push_back("ro");
        }
        // Only request relabeling if the pod provides an SELinux context. If the pod
        // does not provide an SELinux context relabeling will label the volume with
        // the container's randomly allocated MCS label. This would restrict access
        // to the volume to the container which mounts it first.
        if (mounts[i].selinux_relabel()) {
            attrs.push_back("Z");
        }
        if (mounts[i].propagation() == runtime::v1::PROPAGATION_PRIVATE) {
            DEBUG("noop, private is default");
        } else if (mounts[i].propagation() == runtime::v1::PROPAGATION_BIDIRECTIONAL) {
            attrs.push_back("rshared");
        } else if (mounts[i].propagation() == runtime::v1::PROPAGATION_HOST_TO_CONTAINER) {
            attrs.push_back("rslave");
        } else {
            WARN("unknown propagation mode for hostPath %s", mounts[i].host_path().c_str());
            // Falls back to "private"
        }

        if (!attrs.empty()) {
            bind += ":" + CXXUtils::StringsJoin(attrs, ",");
        }
        hostconfig->binds[i] = util_strdup_s(bind.c_str());
        hostconfig->binds_len++;
    }
}

auto GenerateEnvList(const ::google::protobuf::RepeatedPtrField<::runtime::v1::KeyValue> &envs)
-> std::vector<std::string>
{
    std::vector<std::string> vect;
    std::for_each(envs.begin(), envs.end(), [&vect](const ::runtime::v1::KeyValue & elem) {
        vect.push_back(elem.key() + "=" + elem.value());
    });
    return vect;
}

auto ValidateCheckpointKey(const std::string &key, Errors &error) -> bool
{
    const std::string PATTERN { "^([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]$" };

    if (key.empty()) {
        goto err_out;
    }

    if (key.size() <= CRIHelpers::Constants::MAX_CHECKPOINT_KEY_LEN &&
        util_reg_match(PATTERN.c_str(), key.c_str()) == 0) {
        return true;
    }

err_out:
    error.Errorf("invalid key: %s", key.c_str());
    return false;
}

auto ToIsuladContainerStatus(const runtime::v1::ContainerStateValue &state) -> std::string
{
    if (state.state() == runtime::v1::CONTAINER_CREATED) {
        return "created";
    } else if (state.state() == runtime::v1::CONTAINER_RUNNING) {
        return "running";
    } else if (state.state() == runtime::v1::CONTAINER_EXITED) {
        return "exited";
    } else {
        return "unknown";
    }
}

auto GetSeccompiSuladOpts(const bool hasSeccomp, const ::runtime::v1::SecurityProfile &seccomp,
                          const std::string &seccompProfile, Errors &error)
-> std::vector<CRIHelpers::iSuladOpt>
{
    if (!hasSeccomp) {
        return CRIHelpers::GetlegacySeccompiSuladOpts(seccompProfile, error);
    }

    if (seccomp.profile_type() == ::runtime::v1::SecurityProfile_ProfileType_Unconfined) {
        DEBUG("Use set seccomp to unconfined");
        return std::vector<CRIHelpers::iSuladOpt> { { "seccomp", "unconfined", "" } };
    }

    if (seccomp.profile_type() == ::runtime::v1::SecurityProfile_ProfileType_RuntimeDefault) {
        // return nil so iSulad will load the default seccomp profile
        return std::vector<CRIHelpers::iSuladOpt> {};
    }

    if (seccomp.profile_type() == ::runtime::v1::SecurityProfile_ProfileType_Localhost) {
        return CRIHelpers::GetSeccompiSuladOptsByPath(seccomp.localhost_ref().c_str(), error);
    }

    error.Errorf("unsupported seccomp profile type %d", seccomp.profile_type());
    return std::vector<CRIHelpers::iSuladOpt> {};
}


auto GetSelinuxiSuladOpts(const ::runtime::v1::SELinuxOption &selinux, Errors &error)
-> std::vector<CRIHelpers::iSuladOpt>
{
    std::vector<CRIHelpers::iSuladOpt> selinuxOpts { };
    // LabeSep is consistent with the separator used when parsing labels
    const char labeSep { ':' };

    if (selinux.level().length() != 0 &&
        util_reg_match(CRIHelpers::Constants::SELINUX_LABEL_LEVEL_PATTERN.c_str(), selinux.level().c_str()) != 0) {
        error.Errorf("The format of 'level' %s is not correct", selinux.level().c_str());
        return selinuxOpts;
    }

    if (selinux.user().length() > 0) {
        selinuxOpts.push_back({ "label", std::string("user") + std::string(1, labeSep) + selinux.user(), "" });
    }
    if (selinux.role().length() > 0) {
        selinuxOpts.push_back({ "label", std::string("role") + std::string(1, labeSep) + selinux.role(), "" });
    }
    if (selinux.type().length() > 0) {
        selinuxOpts.push_back({ "label", std::string("type") + std::string(1, labeSep) + selinux.type(), "" });
    }
    if (selinux.level().length() > 0) {
        selinuxOpts.push_back({ "label", std::string("level") + std::string(1, labeSep) + selinux.level(), "" });
    }
    return selinuxOpts;
}

auto GetSeccompSecurityOpts(const bool hasSeccomp, const ::runtime::v1::SecurityProfile &seccomp,
                            const std::string &seccompProfile, const char &separator, Errors &error)
-> std::vector<std::string>
{
    std::vector<CRIHelpers::iSuladOpt> seccompOpts = GetSeccompiSuladOpts(hasSeccomp, seccomp, seccompProfile, error);
    if (error.NotEmpty()) {
        return std::vector<std::string>();
    }

    return CRIHelpers::fmtiSuladOpts(seccompOpts, separator);
}

auto GetSELinuxLabelOpts(const bool hasSELinuxOption, const ::runtime::v1::SELinuxOption &selinux,
                         const char &separator, Errors &error)
-> std::vector<std::string>
{
    if (!hasSELinuxOption) {
        return std::vector<std::string>();
    }

    std::vector<CRIHelpers::iSuladOpt> selinuxOpts = GetSelinuxiSuladOpts(selinux, error);
    if (error.NotEmpty()) {
        return std::vector<std::string>();
    }

    return CRIHelpers::fmtiSuladOpts(selinuxOpts, separator);
}

auto GetSecurityOpts(const commonSecurityContext &context, const char &separator, Errors &error)
-> std::vector<std::string>
{
    std::vector<std::string> securityOpts;
    std::vector<std::string> seccompSecurityOpts = GetSeccompSecurityOpts(context.hasSeccomp, context.seccomp,
                                                                          context.seccompProfile, separator, error);
    if (error.NotEmpty()) {
        error.Errorf("Failed to generate seccomp security options for container: %s", error.GetMessage().c_str());
        return securityOpts;
    }

    std::vector<std::string> selinuxOpts = CRIHelpersV1::GetSELinuxLabelOpts(context.hasSELinuxOption,
                                                                             context.selinuxOption, separator, error);
    if (error.NotEmpty()) {
        error.Errorf("Failed to generate SELinuxLabel options for container %s", error.GetMessage().c_str());
        return securityOpts;
    }
    securityOpts.insert(securityOpts.end(), seccompSecurityOpts.begin(), seccompSecurityOpts.end());
    securityOpts.insert(securityOpts.end(), selinuxOpts.begin(), selinuxOpts.end());
    return securityOpts;
}

void AddSecurityOptsToHostConfig(std::vector<std::string> &securityOpts, host_config *hostconfig, Errors &error)
{
    if (securityOpts.empty()) {
        return;
    }

    char **tmp_security_opt = nullptr;
    if (securityOpts.size() > (SIZE_MAX / sizeof(char *)) - hostconfig->security_opt_len) {
        error.Errorf("Out of memory");
        ERROR("Out of memory");
        return;
    }
    size_t newSize = (hostconfig->security_opt_len + securityOpts.size()) * sizeof(char *);
    size_t oldSize = hostconfig->security_opt_len * sizeof(char *);
    int ret = util_mem_realloc((void **)(&tmp_security_opt), newSize, (void *)hostconfig->security_opt, oldSize);
    if (ret != 0) {
        error.Errorf("Out of memory");
        ERROR("Out of memory");
        return;
    }
    hostconfig->security_opt = tmp_security_opt;
    for (const auto &securityOpt : securityOpts) {
        hostconfig->security_opt[hostconfig->security_opt_len] = util_strdup_s(securityOpt.c_str());
        hostconfig->security_opt_len++;
    }

}
void GetContainerSandboxID(const std::string &containerID, std::string &realContainerID, std::string &sandboxID,
                           Errors &error)
{
    std::string PodID;
    container_inspect *info = CRIHelpers::InspectContainer(containerID, error, false);
    if (error.NotEmpty()) {
        error.Errorf("Failed to inspect container %s: %s", containerID.c_str(), error.GetCMessage());
        return;
    }

    // TODO: Refactor after adding the ability to use sandbox manager for sandboxid query
    if (info->config != nullptr && info->config->labels != nullptr) {
        for (size_t j = 0; j < info->config->labels->len; j++) {
            if (strcmp(info->config->labels->keys[j], CRIHelpers::Constants::SANDBOX_ID_LABEL_KEY.c_str()) == 0
                && strcmp(info->config->labels->values[j], "") != 0) {
                PodID = info->config->labels->values[j];
                break;
            }
        }
    }

    if (PodID.empty()) {
        error.Errorf("Failed to get sandbox id for container %s", containerID.c_str());
    } else {
        sandboxID = PodID;
    }
    realContainerID = info->id;
}

#ifdef ENABLE_SANDBOXER
std::string CRISandboxerConvert(const std::string &runtime)
{
    std::string sandboxer;
    defs_map_string_object_sandboxer *criSandboxerList = nullptr;

    if (runtime.empty() || runtime == DEFAULT_SANDBOXER_NAME) {
        return DEFAULT_SANDBOXER_NAME;
    }

    if (isulad_server_conf_rdlock()) {
        ERROR("Lock isulad server conf failed");
        return sandboxer;
    }

    struct service_arguments *args = conf_get_server_conf();
    if (args == nullptr || args->json_confs == nullptr || args->json_confs->cri_sandboxers == nullptr) {
        ERROR("Cannot get cri sandboxer list");
        goto out;
    }

    criSandboxerList = args->json_confs->cri_sandboxers;
    for (size_t i = 0; i < criSandboxerList->len; i++) {
        if (criSandboxerList->keys[i] == nullptr || criSandboxerList->values[i] == nullptr ||
            criSandboxerList->values[i]->name == nullptr) {
            WARN("CRI runtimes key or value is null");
            continue;
        }

        if (runtime == std::string(criSandboxerList->keys[i])) {
            sandboxer = std::string(criSandboxerList->values[i]->name);
            break;
        }
    }

out:
    (void)isulad_server_conf_unlock();
    return sandboxer;
}
#else
std::string CRISandboxerConvert(const std::string &runtime)
{
    return DEFAULT_SANDBOXER_NAME;
}
#endif

void ApplySandboxSecurityContextToHostConfig(const runtime::v1::LinuxSandboxSecurityContext &context, host_config *hc,
                                             Errors &error)
{
    if (hc == nullptr) {
        ERROR("Invalid input arguments: empty hostconfig");
        error.Errorf("Invalid input arguments: empty hostconfig");
        return;
    }

    const char securityOptSep = '=';

    commonSecurityContext commonContext = {
        .hasSeccomp = context.has_seccomp(),
        .hasSELinuxOption = context.has_selinux_options(),
        .seccomp = context.seccomp(),
        .selinuxOption = context.selinux_options(),
        .seccompProfile = context.seccomp_profile_path(),
    };

    std::vector<std::string> securityOpts = GetSecurityOpts(commonContext, securityOptSep, error);
    if (error.NotEmpty()) {
        ERROR("Failed to generate security options: %s", error.GetMessage().c_str());
        error.Errorf("Failed to generate security options: %s", error.GetMessage().c_str());
        return;
    }
    AddSecurityOptsToHostConfig(securityOpts, hc, error);
    if (error.NotEmpty()) {
        ERROR("Failed to add securityOpts to hostconfig: %s", error.GetMessage().c_str());
        error.Errorf("Failed to add securityOpts to hostconfig: %s", error.GetMessage().c_str());
        return;
    }
}

void PackContainerImageToStatus(
    container_inspect *inspect, std::unique_ptr<runtime::v1::ContainerStatus> &contStatus, Errors &error)
{
    if (inspect->config == nullptr) {
        return;
    }

    if (inspect->config->image != nullptr) {
        contStatus->mutable_image()->set_image(inspect->config->image);
    }

    contStatus->set_image_ref(CRIHelpers::ToPullableImageID(inspect->config->image, inspect->config->image_ref));
}

void UpdateBaseStatusFromInspect(
    container_inspect *inspect, int64_t &createdAt, int64_t &startedAt, int64_t &finishedAt,
    std::unique_ptr<runtime::v1::ContainerStatus> &contStatus)
{
    runtime::v1::ContainerState state { runtime::v1::CONTAINER_UNKNOWN };
    std::string reason;
    std::string message;
    int32_t exitCode { 0 };

    if (inspect->state == nullptr) {
        goto pack_status;
    }

    if (inspect->state->running) {
        // Container is running
        state = runtime::v1::CONTAINER_RUNNING;
    } else {
        // Container is not running.
        if (finishedAt != 0) { // Case 1
            state = runtime::v1::CONTAINER_EXITED;
            if (inspect->state->exit_code == 0) {
                reason = "Completed";
            } else {
                reason = "Error";
            }
        } else if (inspect->state->exit_code != 0) { // Case 2
            state = runtime::v1::CONTAINER_EXITED;
            finishedAt = createdAt;
            startedAt = createdAt;
            reason = "ContainerCannotRun";
        } else { // Case 3
            state = runtime::v1::CONTAINER_CREATED;
        }
        if (inspect->state->oom_killed == true) {
            reason = "OOMKilled";
        }
        if (inspect->state->error != nullptr) {
            message = inspect->state->error;
        }
        exitCode = (int32_t)inspect->state->exit_code;
    }

pack_status:
    contStatus->set_exit_code(exitCode);
    contStatus->set_state(state);
    contStatus->set_created_at(createdAt);
    contStatus->set_started_at(startedAt);
    contStatus->set_finished_at(finishedAt);
    contStatus->set_reason(reason);
    contStatus->set_message(message);
}

void PackLabelsToStatus(container_inspect *inspect,
                        std::unique_ptr<runtime::v1::ContainerStatus> &contStatus)
{
    if (inspect->config == nullptr || inspect->config->labels == nullptr) {
        return;
    }
    CRIHelpers::ExtractLabels(inspect->config->labels, *contStatus->mutable_labels());
    CRIHelpers::ExtractAnnotations(inspect->config->annotations, *contStatus->mutable_annotations());
    for (size_t i = 0; i < inspect->config->labels->len; i++) {
        if (strcmp(inspect->config->labels->keys[i], CRIHelpers::Constants::CONTAINER_LOGPATH_LABEL_KEY.c_str()) == 0) {
            contStatus->set_log_path(inspect->config->labels->values[i]);
            break;
        }
    }
}

void ConvertMountsToStatus(container_inspect *inspect,
                           std::unique_ptr<runtime::v1::ContainerStatus> &contStatus)
{
    for (size_t i = 0; i < inspect->mounts_len; i++) {
        runtime::v1::Mount *mount = contStatus->add_mounts();
        mount->set_host_path(inspect->mounts[i]->source);
        mount->set_container_path(inspect->mounts[i]->destination);
        mount->set_readonly(!inspect->mounts[i]->rw);
        if (inspect->mounts[i]->propagation == nullptr || strcmp(inspect->mounts[i]->propagation, "rprivate") == 0) {
            mount->set_propagation(runtime::v1::PROPAGATION_PRIVATE);
        } else if (strcmp(inspect->mounts[i]->propagation, "rslave") == 0) {
            mount->set_propagation(runtime::v1::PROPAGATION_HOST_TO_CONTAINER);
        } else if (strcmp(inspect->mounts[i]->propagation, "rshared") == 0) {
            mount->set_propagation(runtime::v1::PROPAGATION_BIDIRECTIONAL);
        }
        // Note: Can't set SeLinuxRelabel
    }
}

void ConvertResourcesToStatus(container_inspect *inspect,
                              std::unique_ptr<runtime::v1::ContainerStatus> &contStatus)
{
    if (inspect->resources == nullptr) {
        return;
    }
    runtime::v1::LinuxContainerResources *resources = contStatus->mutable_resources()->mutable_linux();
    if (inspect->resources->cpu_shares != 0) {
        resources->set_cpu_shares(inspect->resources->cpu_shares);
    }
    if (inspect->resources->cpu_period != 0) {
        resources->set_cpu_period(inspect->resources->cpu_period);
    }
    if (inspect->resources->cpu_quota != 0) {
        resources->set_cpu_quota(inspect->resources->cpu_quota);
    }
    if (inspect->resources->memory != 0) {
        resources->set_memory_limit_in_bytes(inspect->resources->memory);
    }
    if (inspect->resources->memory_swap != 0) {
        resources->set_memory_swap_limit_in_bytes(inspect->resources->memory_swap);
    }
    for (size_t i = 0; i < inspect->resources->hugetlbs_len; i++) {
        runtime::v1::HugepageLimit *hugepage = resources->add_hugepage_limits();
        hugepage->set_page_size(inspect->resources->hugetlbs[i]->page_size);
        hugepage->set_limit(inspect->resources->hugetlbs[i]->limit);
    }
    if (inspect->resources->unified != nullptr) {
        for (size_t i = 0; i < inspect->resources->unified->len; i++) {
            auto &resUnified = *(resources->mutable_unified());
            resUnified[inspect->resources->unified->keys[i]] = inspect->resources->unified->values[i];
        }
    }
}

void ContainerStatusToGRPC(container_inspect *inspect,
                           std::unique_ptr<runtime::v1::ContainerStatus> &contStatus,
                           Errors &error)
{
    if (inspect->id != nullptr) {
        contStatus->set_id(inspect->id);
    }

    int64_t createdAt {};
    int64_t startedAt {};
    int64_t finishedAt {};
    CRIHelpers::GetContainerTimeStamps(inspect, &createdAt, &startedAt, &finishedAt, error);
    if (error.NotEmpty()) {
        return;
    }
    contStatus->set_created_at(createdAt);
    contStatus->set_started_at(startedAt);
    contStatus->set_finished_at(finishedAt);

    PackContainerImageToStatus(inspect, contStatus, error);
    UpdateBaseStatusFromInspect(inspect, createdAt, startedAt, finishedAt, contStatus);
    PackLabelsToStatus(inspect, contStatus);
    CRINamingV1::ParseContainerName(contStatus->annotations(), contStatus->mutable_metadata(), error);
    if (error.NotEmpty()) {
        return;
    }
    ConvertMountsToStatus(inspect, contStatus);
    ConvertResourcesToStatus(inspect, contStatus);
}

std::unique_ptr<runtime::v1::ContainerStatus> GetContainerStatus(service_executor_t *m_cb, const std::string &containerID, Errors &error)
{
    if (m_cb == nullptr) {
        error.SetError("Invalid input arguments: empty service executor");
        return nullptr;
    }

    if (containerID.empty()) {
        error.SetError("Empty container id");
        return nullptr;
    }

    std::string realContainerID = CRIHelpers::GetRealContainerOrSandboxID(m_cb, containerID, false, error);
    if (error.NotEmpty()) {
        ERROR("Failed to find container id %s: %s", containerID.c_str(), error.GetCMessage());
        error.Errorf("Failed to find container id %s: %s", containerID.c_str(), error.GetCMessage());
        return nullptr;
    }

    container_inspect *inspect = CRIHelpers::InspectContainer(realContainerID, error, false);
    if (error.NotEmpty()) {
        return nullptr;
    }
    if (inspect == nullptr) {
        error.SetError("Get null inspect");
        return nullptr;
    }
    using ContainerStatusPtr = std::unique_ptr<runtime::v1::ContainerStatus>;
    ContainerStatusPtr contStatus(new (std::nothrow) runtime::v1::ContainerStatus);
    if (contStatus == nullptr) {
        error.SetError("Out of memory");
        free_container_inspect(inspect);
        return nullptr;
    }

    ContainerStatusToGRPC(inspect, contStatus, error);

    free_container_inspect(inspect);
    return contStatus;
}

#ifdef ENABLE_CDI
static int InsertCDIDevices(std::unordered_set<std::string> &fromCRI, const std::string &devName,
                            string_array *requested, Errors &err)
{
    if (fromCRI.find(devName) == fromCRI.end()) {
        fromCRI.insert(devName);
        if (util_append_string_array(requested, devName.c_str()) != 0) {
            ERROR("Out of memory");
            err.Errorf("Out of memory");
            return -1;
        }
        DEBUG("Appended device: %s", devName.c_str());
    } else {
        INFO("Skipping duplicate CDI device %s", devName.c_str());
    }
    return 0;
}
 
void GenerateCDIRequestedDevices(const runtime::v1::ContainerConfig &config, host_config *hostconfig, Errors &err)
{
    std::unordered_set<std::string> fromCRI;
    __isula_auto_string_array_t string_array *requested = nullptr;
    __isula_auto_string_array_t string_array *keys = nullptr;
    __isula_auto_string_array_t string_array *devices = nullptr;
    json_map_string_string *annotations = nullptr;
    __isula_auto_free char *error = nullptr;
 
    if (hostconfig == nullptr) {
        ERROR("Invalid input arguments");
        err.Errorf("Invalid input arguments");
        return;
    }
    
    if (config.cdi_devices().empty() && config.annotations().empty()) {
        return;
    }
    requested = (string_array *)util_common_calloc_s(sizeof(*requested));
    if (requested == nullptr) {
        ERROR("Out of memory");
        err.Errorf("Out of memory");
        return;
    }
    if (!config.cdi_devices().empty()) {
        for (int i = 0; i < config.cdi_devices().size(); i++) {
            if (InsertCDIDevices(fromCRI, config.cdi_devices(i).name(), requested, err) != 0) {
                goto free_out;
            }
        }
    }
    if (!config.annotations().empty()) {
        annotations = CRIHelpers::MakeAnnotations(config.annotations(), err);
        if (err.NotEmpty()) {
            goto free_out;
        }
        if (cdi_operate_parse_annotations(annotations, &keys, &devices, &error) != 0) {
            ERROR("Failed to parse CDI annotations: %s", error);
            err.Errorf("Failed to parse CDI annotations: %s", error);
            goto free_out;
        }
        for (size_t i = 0; i < devices->len; i++) {
            if (InsertCDIDevices(fromCRI, std::string(devices->items[i]), requested, err) != 0) {
                goto free_out;
            }
        }
    }
    hostconfig->cdi_requested_devices = requested->items;
    requested->items = nullptr;
    hostconfig->cdi_requested_devices_len = requested->len;
    requested->len = 0;
 
free_out:
    free_json_map_string_string(annotations);
}
#endif /* ENABLE_CDI */

} // v1 namespace CRIHelpers
