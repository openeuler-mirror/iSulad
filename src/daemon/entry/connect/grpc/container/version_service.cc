/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Start: 2022-09-29
 * Description: implement query version service functions
 ******************************************************************************/
#include "version_service.h"

void QueryVersionService::SetThreadName()
{
    SetOperationThreadName("VersionOp");
}

Status QueryVersionService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "docker_version");
}

bool QueryVersionService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.version != nullptr;
}

int QueryVersionService::FillRequestFromgRPC(const VersionRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_version_request *>(util_common_calloc_s(sizeof(container_version_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    *static_cast<container_version_request **>(contReq) = tmpreq;

    return 0;
}

void QueryVersionService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.version(static_cast<container_version_request *>(containerReq),
                                static_cast<container_version_response **>(containerRes));
}

void QueryVersionService::FillResponseTogRPC(void *containerRes, VersionResponse *gresponse)
{
    const container_version_response *response = static_cast<const container_version_response *>(containerRes);

    ResponseToGrpc(response, gresponse);

    if (response->version != nullptr) {
        gresponse->set_version(response->version);
    }
    if (response->git_commit != nullptr) {
        gresponse->set_git_commit(response->git_commit);
    }
    if (response->build_time != nullptr) {
        gresponse->set_build_time(response->build_time);
    }
    if (response->root_path != nullptr) {
        gresponse->set_root_path(response->root_path);
    }
}

void QueryVersionService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_version_request(static_cast<container_version_request *>(containerReq));
    free_container_version_response(static_cast<container_version_response *>(containerRes));
}