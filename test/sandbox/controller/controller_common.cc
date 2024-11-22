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
#include "utils.h"

std::unique_ptr<sandbox::ControllerMountInfo> CreateTestMountInfo()
{
    std::unique_ptr<sandbox::ControllerMountInfo> mountInfo(new sandbox::ControllerMountInfo());
    mountInfo->source = "/rootfs";
    mountInfo->destination = "/rootfs";
    mountInfo->type = "bind";
    return mountInfo;
}

std::unique_ptr<sandbox::ControllerCreateParams> CreateTestCreateParams()
{
    std::unique_ptr<sandbox::ControllerCreateParams> params(new sandbox::ControllerCreateParams());
    params->config = std::make_shared<runtime::v1::PodSandboxConfig>();
    params->netNSPath = "/proc/1/ns/net";
    params->mounts.push_back(std::move(CreateTestMountInfo()));
    return params;
}

std::unique_ptr<sandbox::ControllerStreamInfo> CreateTestStreamInfo()
{
    std::unique_ptr<sandbox::ControllerStreamInfo> streamInfo(new sandbox::ControllerStreamInfo());
    streamInfo->stdin = "/tmp/stdin";
    streamInfo->stdout = "/tmp/stdout";
    streamInfo->stderr = "/tmp/stderr";
    streamInfo->terminal = true;
    return streamInfo;
}

std::unique_ptr<CStructWrapper<sandbox_sandbox>> CreateTestUpdateApiSandbox()
{
    sandbox_sandbox *apiSandbox = nullptr;

    auto apiSandbox_wrapper = makeUniquePtrCStructWrapper<sandbox_sandbox>(free_sandbox_sandbox);
    if (apiSandbox_wrapper == nullptr) {
        return nullptr;
    }
    apiSandbox = apiSandbox_wrapper->get();

    apiSandbox->sandbox_id = util_strdup_s(DUMMY_SANDBOX_ID.c_str());
    apiSandbox->sandboxer = util_strdup_s(DUMMY_SANDBOXER.c_str());

    return apiSandbox_wrapper;
}

std::unique_ptr<CStructWrapper<string_array>> CreateTestFields()
{
    size_t fields_len = 1;
    string_array *fields = nullptr;

    auto fields_wrapper = makeUniquePtrCStructWrapper<string_array>(util_free_string_array);
    if (fields_wrapper == nullptr) {
        return nullptr;
    }
    fields = fields_wrapper->get();

    fields = util_string_array_new(fields_len);
    if (fields == nullptr) {
        return nullptr;
    }
    if (util_append_string_array(fields, DUMMY_SANDBOX_EXTENSIONS_TASKS.c_str())) {
        return nullptr;
    }

    return fields_wrapper;
}