/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2024-03-16
 * Description: provide nri convert functions
 *********************************************************************************/
#ifndef DAEMON_COMMON_NRI_NRI_CONVERT_H
#define DAEMON_COMMON_NRI_NRI_CONVERT_H
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "isula_libutils/nri_pod_sandbox.h"
#include "isula_libutils/nri_container.h"
#include "isula_libutils/nri_mount.h"
#include "isula_libutils/nri_linux_resources.h"

#include "sandbox.h"
#include "api_v1.pb.h"

auto PodSandboxToNRI(const std::shared_ptr<const sandbox::Sandbox> &sandbox, nri_pod_sandbox &pod) -> bool;
auto ContainerToNRIByConConfig(const runtime::v1::ContainerConfig &containerConfig, nri_container &con) -> bool;
auto ContainerToNRIByID(const std::string &id, nri_container &con) -> bool;
auto PodSandboxesToNRI(const std::vector<std::shared_ptr<sandbox::Sandbox>> &arrs,
                       std::vector<nri_pod_sandbox *> &pods) -> bool;
auto ContainersToNRI(std::vector<std::unique_ptr<runtime::v1::Container>> &containers,
                     std::vector<nri_container *> &cons) -> bool;

auto LinuxResourcesFromNRI(const nri_linux_resources *src, runtime::v1::LinuxContainerResources &resources) -> bool;
auto LinuxResourcesToNRI(const runtime::v1::LinuxContainerResources &src) -> nri_linux_resources *;
#endif // DAEMON_COMMON_NRI_NRI_CONVERT_H
