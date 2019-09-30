/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide cri service function definition
 *********************************************************************************/
#ifndef _CRI_SERVICES_H_
#define _CRI_SERVICES_H_

#include <string>
#include <memory>
#include <cstdint>
#include <vector>

#include "api.pb.h"
#include "errors.h"

namespace cri {
class RuntimeVersioner {
public:
    virtual void Version(const std::string &apiVersion, runtime::VersionResponse *versionResponse, Errors &error) = 0;
};

class ContainerManager {
public:
    virtual std::string CreateContainer(const std::string &podSandboxID,
                                        const runtime::ContainerConfig &containerConfig,
                                        const runtime::PodSandboxConfig &podSandboxConfig, Errors &error) = 0;

    virtual void StartContainer(const std::string &containerID, Errors &error) = 0;

    virtual void StopContainer(const std::string &containerID, int64_t timeout, Errors &error) = 0;

    virtual void RemoveContainer(const std::string &containerID, Errors &error) = 0;

    virtual void ListContainers(const runtime::ContainerFilter *filter,
                                std::vector<std::unique_ptr<runtime::Container>> *containers, Errors &error) = 0;

    virtual void ListContainerStats(const runtime::ContainerStatsFilter *filter,
                                    std::vector<std::unique_ptr<runtime::ContainerStats>> *containerstats,
                                    Errors &error) = 0;

    virtual std::unique_ptr<runtime::ContainerStatus> ContainerStatus(const std::string &containerID,
                                                                      Errors &error) = 0;

    virtual void UpdateContainerResources(const std::string &containerID,
                                          const runtime::LinuxContainerResources &resources, Errors &error) = 0;

    virtual void ExecSync(const std::string &containerID, const google::protobuf::RepeatedPtrField<std::string> &cmd,
                          int64_t timeout, runtime::ExecSyncResponse *reply, Errors &error) = 0;

    virtual void Exec(const runtime::ExecRequest &req, runtime::ExecResponse *resp, Errors &error) = 0;

    virtual void Attach(const runtime::AttachRequest &req, runtime::AttachResponse *resp, Errors &error) = 0;
};

class PodSandboxManager {
public:
    virtual std::string RunPodSandbox(const runtime::PodSandboxConfig &config, Errors &error) = 0;

    virtual void StopPodSandbox(const std::string &podSandboxID, Errors &error) = 0;

    virtual void RemovePodSandbox(const std::string &podSandboxID, Errors &error) = 0;

    virtual std::unique_ptr<runtime::PodSandboxStatus> PodSandboxStatus(const std::string &podSandboxID,
                                                                        Errors &error) = 0;

    virtual void ListPodSandbox(const runtime::PodSandboxFilter *filter,
                                std::vector<std::unique_ptr<runtime::PodSandbox>> *pods, Errors &error) = 0;

    virtual void PortForward(const runtime::PortForwardRequest &req, runtime::PortForwardResponse *resp,
                             Errors &error) = 0;
};

class RuntimeManager {
public:
    virtual void UpdateRuntimeConfig(const runtime::RuntimeConfig &config, Errors &error) = 0;

    virtual std::unique_ptr<runtime::RuntimeStatus> Status(Errors &error) = 0;
};

class ImageManagerService {
public:
    virtual void ListImages(const runtime::ImageFilter &filter, std::vector<std::unique_ptr<runtime::Image>> *images,
                            Errors &error) = 0;

    virtual std::unique_ptr<runtime::Image> ImageStatus(const runtime::ImageSpec &image, Errors &error) = 0;

    virtual std::string PullImage(const runtime::ImageSpec &image, const runtime::AuthConfig &auth, Errors &error) = 0;

    virtual void RemoveImage(const runtime::ImageSpec &image, Errors &error) = 0;

    virtual void ImageFsInfo(std::vector<std::unique_ptr<runtime::FilesystemUsage>> *usages, Errors &error) = 0;
};

}  // namespace cri
#endif /* _CRI_SERVICES_H_ */
