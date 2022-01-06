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
 * Description: provide cri pod sandbox manager service interface definition
 *********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_POD_SANDBOX_MANAGER_H
#define DAEMON_ENTRY_CRI_POD_SANDBOX_MANAGER_H
#include <memory>
#include <string>
#include <vector>

#include "api.pb.h"
#include "errors.h"

namespace CRI {
class PodSandboxManagerService {
public:
    PodSandboxManagerService() = default;
    virtual ~PodSandboxManagerService() = default;
    virtual auto RunPodSandbox(const runtime::v1alpha2::PodSandboxConfig &config, const std::string &runtimeHandler,
                               Errors &error) -> std::string = 0;

    virtual void StopPodSandbox(const std::string &podSandboxID, Errors &error) = 0;

    virtual void RemovePodSandbox(const std::string &podSandboxID, Errors &error) = 0;

    virtual auto PodSandboxStatus(const std::string &podSandboxID,
                                  Errors &error) -> std::unique_ptr<runtime::v1alpha2::PodSandboxStatus> = 0;

    virtual void ListPodSandbox(const runtime::v1alpha2::PodSandboxFilter *filter,
                                std::vector<std::unique_ptr<runtime::v1alpha2::PodSandbox>> *pods, Errors &error) = 0;

    virtual void PortForward(const runtime::v1alpha2::PortForwardRequest &req,
                             runtime::v1alpha2::PortForwardResponse *resp, Errors &error) = 0;
};
} // namespace CRI

#endif // DAEMON_ENTRY_CRI_POD_SANDBOX_MANAGER_H