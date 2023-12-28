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
 * Description: provide cri helpers functions
 *********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_V1ALPHA_CRI_HELPERS_H
#define DAEMON_ENTRY_CRI_V1ALPHA_CRI_HELPERS_H
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <isula_libutils/docker_seccomp.h>
#include <isula_libutils/host_config.h>
#include <isula_libutils/container_config.h>

#include "api.pb.h"
#include "checkpoint_handler.h"
#include "constants.h"
#include "errors.h"

namespace CRIHelpersV1Alpha {

struct commonSecurityContext {
    const bool hasSeccomp;
    const bool hasSELinuxOption;
    const ::runtime::v1alpha2::SecurityProfile seccomp;
    const ::runtime::v1alpha2::SELinuxOption selinuxOption;
    const std::string seccompProfile;
};

auto ContainerStatusToRuntime(Container_Status status) -> runtime::v1alpha2::ContainerState;

auto CheckpointToSandbox(const std::string &id, const CRI::PodSandboxCheckpoint &checkpoint)
-> std::unique_ptr<runtime::v1alpha2::PodSandbox>;

void UpdateCreateConfig(container_config *createConfig, host_config *hc,
                        const runtime::v1alpha2::ContainerConfig &config, const std::string &podSandboxID,
                        Errors &error);

void GenerateMountBindings(const google::protobuf::RepeatedPtrField<runtime::v1alpha2::Mount> &mounts,
                           host_config *hostconfig, Errors &err);

auto GenerateEnvList(const ::google::protobuf::RepeatedPtrField<::runtime::v1alpha2::KeyValue> &envs)
-> std::vector<std::string>;

auto ValidateCheckpointKey(const std::string &key, Errors &error) -> bool;

auto ToIsuladContainerStatus(const runtime::v1alpha2::ContainerStateValue &state) -> std::string;

auto GetSeccompSecurityOpts(const bool hasSeccomp, const ::runtime::v1alpha2::SecurityProfile &seccomp,
                            const std::string &seccompProfile, const char &separator, Errors &error)
-> std::vector<std::string>;

auto GetSELinuxLabelOpts(const bool hasSELinuxOption, const ::runtime::v1alpha2::SELinuxOption &selinux,
                         const char &separator, Errors &error)
-> std::vector<std::string>;

auto GetSecurityOpts(const commonSecurityContext &context, const char &separator, Errors &error)
-> std::vector<std::string>;

void AddSecurityOptsToHostConfig(std::vector<std::string> &securityOpts, host_config *hostconfig, Errors &error);

}; // namespace CRIHelpers

#endif // DAEMON_ENTRY_CRI_V1ALPHA_CRI_HELPERS_H
