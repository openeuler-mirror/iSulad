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
 * Description: provide cri security context functions
 *********************************************************************************/
#include "cri_security_context.h"
#include "cri_runtime_service.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "cri_constants.h"
#include <memory>

namespace CRISecurity {
static void ModifyContainerConfig(const runtime::v1alpha2::LinuxContainerSecurityContext &sc, container_config *config)
{
    if (sc.has_run_as_user()) {
        free(config->user);
        config->user = util_strdup_s(std::to_string(sc.run_as_user().value()).c_str());
    }
    if (!sc.run_as_username().empty()) {
        free(config->user);
        config->user = util_strdup_s(sc.run_as_username().c_str());
    }
}

static void ModifyHostConfigCapabilities(const runtime::v1alpha2::LinuxContainerSecurityContext &sc,
                                         host_config *hostConfig, Errors &error)
{
    if (!sc.has_capabilities()) {
        return;
    }

    const google::protobuf::RepeatedPtrField<std::string> &capAdd = sc.capabilities().add_capabilities();
    if (!capAdd.empty()) {
        if (static_cast<size_t>(capAdd.size()) > SIZE_MAX / sizeof(char *)) {
            error.SetError("Invalid capability add size");
            return;
        }
        hostConfig->cap_add = (char **)util_common_calloc_s(sizeof(char *) * capAdd.size());
        if (hostConfig->cap_add == nullptr) {
            error.SetError("Out of memory");
            return;
        }
        for (int i {}; i < capAdd.size(); i++) {
            hostConfig->cap_add[i] = util_strdup_s(capAdd[i].c_str());
            hostConfig->cap_add_len++;
        }
    }
    const google::protobuf::RepeatedPtrField<std::string> &capDrop = sc.capabilities().drop_capabilities();
    if (!capDrop.empty()) {
        if (static_cast<size_t>(capDrop.size()) > SIZE_MAX / sizeof(char *)) {
            error.SetError("Invalid capability drop size");
            return;
        }
        hostConfig->cap_drop = (char **)util_common_calloc_s(sizeof(char *) * capDrop.size());
        if (hostConfig->cap_drop == nullptr) {
            error.SetError("Out of memory");
            return;
        }
        for (int i = 0; i < capDrop.size(); i++) {
            hostConfig->cap_drop[i] = util_strdup_s(capDrop[i].c_str());
            hostConfig->cap_drop_len++;
        }
    }
}

static void ModifyHostConfigNoNewPrivs(const runtime::v1alpha2::LinuxContainerSecurityContext &sc,
                                       host_config *hostConfig, Errors &error)
{
    char **tmp_security_opt { nullptr };

    if (!sc.no_new_privs()) {
        return;
    }

    if (hostConfig->security_opt_len > (SIZE_MAX / sizeof(char *)) - 1) {
        error.Errorf("Out of memory");
        return;
    }

    size_t oldSize = hostConfig->security_opt_len * sizeof(char *);
    size_t newSize = oldSize + sizeof(char *);
    int ret = util_mem_realloc((void **)(&tmp_security_opt), newSize, (void *)hostConfig->security_opt, oldSize);
    if (ret != 0) {
        error.Errorf("Out of memory");
        return;
    }
    hostConfig->security_opt = tmp_security_opt;
    hostConfig->security_opt[hostConfig->security_opt_len++] = util_strdup_s("no-new-privileges");
}

static void ModifyHostConfigscSupplementalGroups(const runtime::v1alpha2::LinuxContainerSecurityContext &sc,
                                                 host_config *hostConfig, Errors &error)
{
    if (sc.supplemental_groups().empty()) {
        return;
    }

    const google::protobuf::RepeatedField<google::protobuf::int64> &groups = sc.supplemental_groups();
    if (!groups.empty()) {
        if (static_cast<size_t>(groups.size()) > SIZE_MAX / sizeof(char *)) {
            error.SetError("Invalid group size");
            return;
        }
        hostConfig->group_add = (char **)util_common_calloc_s(sizeof(char *) * groups.size());
        if (hostConfig->group_add == nullptr) {
            error.SetError("Out of memory");
            return;
        }
        for (int i = 0; i < groups.size(); i++) {
            hostConfig->group_add[i] = util_strdup_s(std::to_string(groups[i]).c_str());
            hostConfig->group_add_len++;
        }
    }
}

static void ModifyHostConfig(const runtime::v1alpha2::LinuxContainerSecurityContext &sc, host_config *hostConfig,
                             Errors &error)
{
    hostConfig->privileged = sc.privileged();
    hostConfig->readonly_rootfs = sc.readonly_rootfs();
    // note: Apply apparmor options, selinux options, noNewPrivilege
    ModifyHostConfigCapabilities(sc, hostConfig, error);
    ModifyHostConfigNoNewPrivs(sc, hostConfig, error);
    ModifyHostConfigscSupplementalGroups(sc, hostConfig, error);
}

static void ModifyCommonNamespaceOptions(const runtime::v1alpha2::NamespaceOption &nsOpts, host_config *hostConfig)
{
    if (nsOpts.pid() == runtime::v1alpha2::NamespaceMode::NODE) {
        free(hostConfig->pid_mode);
        hostConfig->pid_mode = util_strdup_s(CRI::Constants::namespaceModeHost.c_str());
    }
}

static void ModifyHostNetworkOptionForContainer(const runtime::v1alpha2::NamespaceMode &hostNetwork,
                                                const std::string &podSandboxID, host_config *hostConfig)
{
    std::string sandboxNSMode = "container:" + podSandboxID;

    free(hostConfig->network_mode);
    hostConfig->network_mode = util_strdup_s(sandboxNSMode.c_str());
    free(hostConfig->ipc_mode);
    hostConfig->ipc_mode = util_strdup_s(sandboxNSMode.c_str());
    if (hostNetwork == runtime::v1alpha2::NamespaceMode::NODE) {
        free(hostConfig->uts_mode);
        hostConfig->uts_mode = util_strdup_s(CRI::Constants::namespaceModeHost.c_str());
    }
}

static void ModifyHostNetworkOptionForSandbox(const runtime::v1alpha2::NamespaceOption &nsOpts, host_config *hostConfig)
{
    if (nsOpts.ipc() == runtime::v1alpha2::NamespaceMode::NODE) {
        free(hostConfig->ipc_mode);
        hostConfig->ipc_mode = util_strdup_s(CRI::Constants::namespaceModeHost.c_str());
    }

    if (nsOpts.network() == runtime::v1alpha2::NamespaceMode::NODE) {
        free(hostConfig->network_mode);
        hostConfig->network_mode = util_strdup_s(CRI::Constants::namespaceModeHost.c_str());
        free(hostConfig->uts_mode);
        hostConfig->uts_mode = util_strdup_s(CRI::Constants::namespaceModeHost.c_str());
    } else {
        free(hostConfig->network_mode);
        hostConfig->network_mode = util_strdup_s(CRI::Constants::namespaceModeCNI.c_str());
    }
    // Note: default networkMode is not supported
}

static void ModifyContainerNamespaceOptions(const runtime::v1alpha2::NamespaceOption &nsOpts,
                                            const std::string &podSandboxID, host_config *hostConfig)
{
    std::string sandboxNSMode = "container:" + podSandboxID;
    if (nsOpts.pid() == runtime::v1alpha2::NamespaceMode::POD) {
        free(hostConfig->pid_mode);
        hostConfig->pid_mode = util_strdup_s(sandboxNSMode.c_str());
    }

    if (nsOpts.pid() == runtime::v1alpha2::NamespaceMode::TARGET) {
        std::string targetPidNsMode = "container:" + nsOpts.target_id();
        free(hostConfig->pid_mode);
        hostConfig->pid_mode = util_strdup_s(targetPidNsMode.c_str());
    }

    /* set common Namespace options */
    ModifyCommonNamespaceOptions(nsOpts, hostConfig);
    /* modify host network option for container */
    ModifyHostNetworkOptionForContainer(nsOpts.network(), podSandboxID, hostConfig);

    free(hostConfig->uts_mode);
    hostConfig->uts_mode = util_strdup_s(sandboxNSMode.c_str());
}

static void ModifySandboxNamespaceOptions(const runtime::v1alpha2::NamespaceOption &nsOpts, host_config *hostConfig)
{
    /* set common Namespace options */
    ModifyCommonNamespaceOptions(nsOpts, hostConfig);
    /* modify host network option for container */
    ModifyHostNetworkOptionForSandbox(nsOpts, hostConfig);
}

void ApplySandboxSecurityContext(const runtime::v1alpha2::LinuxPodSandboxConfig &lc, container_config *config,
                                 host_config *hc, Errors &error)
{
    std::unique_ptr<runtime::v1alpha2::LinuxContainerSecurityContext> sc(
        new (std::nothrow) runtime::v1alpha2::LinuxContainerSecurityContext);
    if (sc == nullptr) {
        error.SetError("Out of memory");
        return;
    }
    if (lc.has_security_context()) {
        const runtime::v1alpha2::LinuxSandboxSecurityContext &old = lc.security_context();
        if (old.has_run_as_user()) {
            *sc->mutable_run_as_user() = old.run_as_user();
        }
        if (old.has_namespace_options()) {
            *sc->mutable_namespace_options() = old.namespace_options();
        }
        if (old.has_selinux_options()) {
            *sc->mutable_selinux_options() = old.selinux_options();
        }
        *sc->mutable_supplemental_groups() = old.supplemental_groups();
        sc->set_readonly_rootfs(old.readonly_rootfs());
    }
    ModifyContainerConfig(*sc, config);
    ModifyHostConfig(*sc, hc, error);
    if (error.NotEmpty()) {
        return;
    }
    ModifySandboxNamespaceOptions(sc->namespace_options(), hc);
}

void ApplyContainerSecurityContext(const runtime::v1alpha2::LinuxContainerConfig &lc, const std::string &podSandboxID,
                                   container_config *config, host_config *hc, Errors &error)
{
    if (lc.has_security_context()) {
        const runtime::v1alpha2::LinuxContainerSecurityContext &sc = lc.security_context();
        ModifyContainerConfig(sc, config);
        ModifyHostConfig(sc, hc, error);
        if (error.NotEmpty()) {
            return;
        }
    }
    ModifyContainerNamespaceOptions(lc.security_context().namespace_options(), podSandboxID, hc);
}

} // namespace CRISecurity
