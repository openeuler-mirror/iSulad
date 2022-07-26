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
 * Start: 2022-06-30
 * Description: implement grpc container update service functions
 ******************************************************************************/
#include "update_service.h"

void ContainerUpdateService::SetThreadName()
{
    SetOperationThreadName("ContUpdate");
}

Status ContainerUpdateService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_update");
}

bool ContainerUpdateService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.update != nullptr;
}

int ContainerUpdateService::FillRequestFromgRPC(const UpdateRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_update_request *>(util_common_calloc_s(sizeof(container_update_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->name = util_strdup_s(request->id().c_str());
    }

    if (!request->hostconfig().empty()) {
        tmpreq->host_config = util_strdup_s(request->hostconfig().c_str());
    }

    *static_cast<container_update_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerUpdateService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.update(static_cast<container_update_request *>(containerReq),
                               static_cast<container_update_response **>(containerRes));
}

void ContainerUpdateService::FillResponseTogRPC(void *containerRes, UpdateResponse *gresponse)
{
    const container_update_response *response = static_cast<const container_update_response *>(containerRes);

    ResponseToGrpc(response, gresponse);

    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }
}

void ContainerUpdateService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_update_request(static_cast<container_update_request *>(containerReq));
    free_container_update_response(static_cast<container_update_response *>(containerRes));
}