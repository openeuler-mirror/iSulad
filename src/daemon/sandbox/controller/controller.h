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
 * Create: 2023-06-15
 * Description: provide controller class definition
 *********************************************************************************/

#ifndef DAEMON_SANDBOX_CONTROLLER_CONTROLLER_H
#define DAEMON_SANDBOX_CONTROLLER_CONTROLLER_H

#include <string>
#include <vector>
#include <map>
#include <grpc++/grpc++.h>
#include <stdint.h>

#include "errors.h"
#include "api_v1.pb.h"

namespace sandbox {

#define SANDBOX_READY_STATE_STR "SANDBOX_READY"
#define SANDBOX_NOTREADY_STATE_STR "SANDBOX_NOTREADY"

struct ControllerMountInfo {
    std::string source;
    std::string destination;
    std::string type;
    std::vector<std::string> options;
};

struct ControllerCreateParams {
    // Shared ownership of the config with sandbox object
    std::shared_ptr<runtime::v1::PodSandboxConfig> config;
    std::vector<std::unique_ptr<ControllerMountInfo>> mounts;
    std::string netNSPath;
    std::string netMode;
    std::string sandboxName;
    std::string image;
    std::string sandboxer;
    std::string runtime;
    std::string hostname;
    std::string hostnamePath;
    std::string hostsPath;
    std::string resolvConfPath;
    std::string shmPath;
};

struct ControllerPlatformInfo {
    std::string os;
    std::string arch;
    std::string variant;
};

struct ControllerSandboxInfo {
    std::string id;
    uint32_t pid;
    uint64_t createdAt;
    std::string taskAddress;
    google::protobuf::Map<std::string, std::string> labels;
};

struct ControllerExitInfo {
    uint32_t exitStatus;
    uint64_t exitedAt;
};

struct ControllerSandboxStatus {
    std::string id;
    uint32_t pid;
    std::string state;
    std::string taskAddress;
    google::protobuf::Map<std::string, std::string> info;
    uint64_t createdAt;
    uint64_t exitedAt;
    // Currently unused
    std::string extra;
};

struct ControllerStreamInfo {
    std::string stdin;
    std::string stdout;
    std::string stderr;
    bool terminal;
};

struct ControllerPrepareParams {
    std::string containerId;
    std::string execId;
    std::unique_ptr<std::string> spec;
    std::vector<std::unique_ptr<ControllerMountInfo>> rootfs;
    std::unique_ptr<ControllerStreamInfo> streamInfo;
};

struct ControllerUpdateResourcesParams {
    std::string containerId;
    std::unique_ptr<std::string> resources;
    google::protobuf::Map<std::string, std::string> &annotations;
};

class SandboxStatusCallback {
public:
    virtual void OnSandboxReady() = 0;
    virtual void OnSandboxPending() = 0;
    virtual void OnSandboxExit(const ControllerExitInfo &exitInfo) = 0;
};

class Controller {
public:
    virtual ~Controller() {};
    virtual bool Init(Errors &error) = 0;
    virtual void Destroy() = 0;
    virtual bool Create(const std::string &sandboxId,
                        const ControllerCreateParams &params,
                        Errors &error) = 0;
    virtual std::unique_ptr<ControllerSandboxInfo> Start(const std::string &sandboxId, Errors &error) = 0 ;
    virtual std::unique_ptr<ControllerPlatformInfo> Platform(const std::string &sandboxId, Errors &error) = 0;
    virtual std::string Prepare(const std::string &sandboxId,
                                const ControllerPrepareParams &params,
                                Errors &error) = 0;
    virtual bool Purge(const std::string &sandboxId, const std::string &containerId,
                       const std::string &execId, Errors &error) = 0;
    virtual bool UpdateResources(const std::string &sandboxId,
                                 const ControllerUpdateResourcesParams &params,
                                 Errors &error) = 0;
    virtual bool Stop(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error) = 0;
    virtual bool Wait(std::shared_ptr<SandboxStatusCallback> cb, const std::string &sandboxId, Errors &error) = 0;
    virtual std::unique_ptr<ControllerSandboxStatus> Status(const std::string &sandboxId, bool verbose, Errors &error) = 0;
    virtual bool Shutdown(const std::string &sandboxId, Errors &error) = 0;
    virtual bool UpdateNetworkSettings(const std::string &sandboxId, const std::string &networkSettings, Errors &error) = 0;
};

} // namespace
#endif // DAEMON_SANDBOX_CONTROLLER_CONTROLLER_H
