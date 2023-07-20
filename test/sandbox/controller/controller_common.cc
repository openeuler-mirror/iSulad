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
 * Create: 2023-07-15
 * Description: Controller common functions for tests
 ******************************************************************************/

#include "controller_common.h"

std::unique_ptr<sandbox::ControllerMountInfo> CreateTestMountInfo() {
    std::unique_ptr<sandbox::ControllerMountInfo> mountInfo(new sandbox::ControllerMountInfo());
    mountInfo->source = "/rootfs";
    mountInfo->destination = "/rootfs";
    mountInfo->type = "bind";
    return mountInfo;
}

std::unique_ptr<sandbox::ControllerCreateParams> CreateTestCreateParams() {
    std::unique_ptr<sandbox::ControllerCreateParams> params(new sandbox::ControllerCreateParams());
    params->config = std::make_shared<runtime::v1::PodSandboxConfig>();
    params->netNSPath = "/proc/1/ns/net";
    params->mounts.push_back(std::move(CreateTestMountInfo()));
    return params;
}

std::unique_ptr<sandbox::ControllerStreamInfo> CreateTestStreamInfo() {
    std::unique_ptr<sandbox::ControllerStreamInfo> streamInfo(new sandbox::ControllerStreamInfo());
    streamInfo->stdin = "/tmp/stdin";
    streamInfo->stdout = "/tmp/stdout";
    streamInfo->stderr = "/tmp/stderr";
    streamInfo->terminal = true;
    return streamInfo;
}

std::unique_ptr<sandbox::ControllerPrepareParams> CreateTestPrepareParams() {
    std::unique_ptr<sandbox::ControllerPrepareParams> params(new sandbox::ControllerPrepareParams());
    params->containerId = DUMMY_CONTAINER_ID;
    params->execId = DUMMY_EXEC_ID;
    params->spec = std::unique_ptr<std::string>(new std::string("{spec: test}"));
    params->rootfs.push_back(std::move(CreateTestMountInfo()));
    params->rootfs.push_back(std::move(CreateTestMountInfo()));
    params->streamInfo = CreateTestStreamInfo();
    return params;
}

std::unique_ptr<sandbox::ControllerUpdateResourcesParams> CreateTestUpdateResourcesParams(google::protobuf::Map<std::string, std::string> &annotations) {
    std::unique_ptr<std::string> resources(new std::string("{cpu: 12}"));
    std::unique_ptr<sandbox::ControllerUpdateResourcesParams> params(
        new sandbox::ControllerUpdateResourcesParams{DUMMY_SANDBOX_ID, std::move(resources), annotations}
    );
    return params;
}
