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

#include "v1_cri_runtime_service.h"
#include "v1_cri_security_context.h"
#include "cri_helpers.h"
#include "cri_constants.h"
#include "cxxutils.h"
#include "path.h"
#include "utils.h"
#include "service_container_api.h"
#include "isulad_config.h"
#include "sha256.h"

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

struct iSuladOpt {
    std::string key;
    std::string value;
    std::string msg;
};

auto fmtiSuladOpts(const std::vector<iSuladOpt> &opts, const char &sep) -> std::vector<std::string>
{
    std::vector<std::string> fmtOpts(opts.size());
    for (size_t i {}; i < opts.size(); i++) {
        fmtOpts[i] = opts.at(i).key + sep + opts.at(i).value;
    }
    return fmtOpts;
}

auto GetSeccompiSuladOptsByPath(const char *dstpath, Errors &error) -> std::vector<iSuladOpt>
{
    std::vector<iSuladOpt> ret { };
    parser_error err = nullptr;
    char *seccomp_json = nullptr;

    docker_seccomp *seccomp_spec = get_seccomp_security_opt_spec(dstpath);
    if (seccomp_spec == nullptr) {
        error.Errorf("failed to parse seccomp profile");
        return ret;
    }
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    seccomp_json = docker_seccomp_generate_json(seccomp_spec, &ctx, &err);
    if (seccomp_json == nullptr) {
        error.Errorf("failed to generate seccomp json: %s", err);
        goto out;
    }

    ret = std::vector<iSuladOpt> { { "seccomp", seccomp_json, "" } };

out:
    free(err);
    free(seccomp_json);
    free_docker_seccomp(seccomp_spec);
    return ret;
}

auto GetlegacySeccompiSuladOpts(const std::string &seccompProfile, Errors &error) -> std::vector<iSuladOpt>
{
    if (seccompProfile.empty() || seccompProfile == "unconfined") {
        DEBUG("Legacy seccomp is unconfined");
        return std::vector<iSuladOpt> { { "seccomp", "unconfined", "" } };
    }
    if (seccompProfile == "iSulad/default" || seccompProfile == "docker/default" ||
        seccompProfile == "runtime/default") {
        // return nil so docker will load the default seccomp profile
        return std::vector<iSuladOpt> {};
    }
    if (seccompProfile.compare(0, strlen("localhost/"), "localhost/") != 0) {
        error.Errorf("unknown seccomp profile option: %s", seccompProfile.c_str());
        return std::vector<iSuladOpt> {};
    }
    std::string fname = seccompProfile.substr(std::string("localhost/").length(), seccompProfile.length());
    char dstpath[PATH_MAX] { 0 };
    if (util_clean_path(fname.c_str(), dstpath, sizeof(dstpath)) == nullptr) {
        error.Errorf("failed to get clean path");
        return std::vector<iSuladOpt> {};
    }
    if (dstpath[0] != '/') {
        error.Errorf("seccomp profile path must be absolute, but got relative path %s", fname.c_str());
        return std::vector<iSuladOpt> {};
    }

    return GetSeccompiSuladOptsByPath(dstpath, error);
}

auto GetSeccompiSuladOpts(const bool hasSeccomp, const ::runtime::v1::SecurityProfile &seccomp,
                          const std::string &seccompProfile, Errors &error)
-> std::vector<iSuladOpt>
{
    if (!hasSeccomp) {
        return GetlegacySeccompiSuladOpts(seccompProfile, error);
    }

    if (seccomp.profile_type() == ::runtime::v1::SecurityProfile_ProfileType_Unconfined) {
        DEBUG("Use set seccomp to unconfined");
        return std::vector<iSuladOpt> { { "seccomp", "unconfined", "" } };
    }

    if (seccomp.profile_type() == ::runtime::v1::SecurityProfile_ProfileType_RuntimeDefault) {
        // return nil so iSulad will load the default seccomp profile
        return std::vector<iSuladOpt> {};
    }

    if (seccomp.profile_type() == ::runtime::v1::SecurityProfile_ProfileType_Localhost) {
        return GetSeccompiSuladOptsByPath(seccomp.localhost_ref().c_str(), error);
    }

    error.Errorf("unsupported seccomp profile type %d", seccomp.profile_type());
    return std::vector<iSuladOpt> {};
}


auto GetSelinuxiSuladOpts(const ::runtime::v1::SELinuxOption &selinux, Errors &error)
-> std::vector<iSuladOpt>
{
    std::vector<iSuladOpt> selinuxOpts { };
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
    std::vector<iSuladOpt> seccompOpts = GetSeccompiSuladOpts(hasSeccomp, seccomp, seccompProfile, error);
    if (error.NotEmpty()) {
        return std::vector<std::string>();
    }

    return fmtiSuladOpts(seccompOpts, separator);
}

auto GetSELinuxLabelOpts(const bool hasSELinuxOption, const ::runtime::v1::SELinuxOption &selinux,
                         const char &separator, Errors &error)
-> std::vector<std::string>
{
    if (!hasSELinuxOption) {
        return std::vector<std::string>();
    }

    std::vector<iSuladOpt> selinuxOpts = GetSelinuxiSuladOpts(selinux, error);
    if (error.NotEmpty()) {
        return std::vector<std::string>();
    }

    return fmtiSuladOpts(selinuxOpts, separator);
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

auto GetPodSELinuxLabelOpts(const std::string &selinuxLabel, Errors &error)
-> std::vector<std::string>
{
    // security Opt Separator Change Version : k8s v1.23.0 (Corresponds to docker 1.11.x)
    // New version '=' , old version ':', iSulad cri is based on v18.09, so iSulad cri use new version separator
    const char securityOptSep { '=' };
    // LabeSep is consistent with the separator used when parsing labels
    const char labeSep { ':' };
    std::vector<iSuladOpt> selinuxOpts { };
    char **labelArr = nullptr;
    size_t labelArrLen = 0;
    std::vector<std::string> opts = {"user", "role", "type", "level"};
    std::vector<std::string> vect;

    labelArr = util_string_split_n(selinuxLabel.c_str(), labeSep, 4);
    if (labelArr == nullptr) {
        error.Errorf("Invalid selinux label: %s", selinuxLabel.c_str());
        return vect;
    }

    labelArrLen = util_array_len((const char **)labelArr);
    for (size_t i {}; i < labelArrLen; i++) {
        iSuladOpt tmp = { "label", opts[i] + std::string(1, labeSep) + std::string(labelArr[i]), "" };
        selinuxOpts.push_back(tmp);
    }

    util_free_array(labelArr);

    return fmtiSuladOpts(selinuxOpts, securityOptSep);
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

} // v1alpha namespace CRIHelpers
