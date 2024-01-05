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
 * Start: 2022-06-24
 * Description: implement grpc container inspect service functions
 ******************************************************************************/
#include "inspect_service.h"

void ContainerInspectService::SetThreadName()
{
    SetOperationThreadName("ContInspect");
}

Status ContainerInspectService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_inspect");
}

bool ContainerInspectService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.inspect != nullptr;
}

int ContainerInspectService::FillRequestFromgRPC(const containers::InspectContainerRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_inspect_request *>(util_common_calloc_s(sizeof(container_inspect_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->id = util_strdup_s(request->id().c_str());
    }

    tmpreq->bformat = request->bformat();
    tmpreq->timeout = request->timeout();

    *static_cast<container_inspect_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerInspectService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.inspect(static_cast<container_inspect_request *>(containerReq),
                                static_cast<container_inspect_response **>(containerRes));
}

void ContainerInspectService::FillResponseTogRPC(void *containerRes, containers::InspectContainerResponse *gresponse)
{
    const container_inspect_response *response = static_cast<const container_inspect_response *>(containerRes);

    ResponseToGrpc(response, gresponse);

    if (response->container_json != nullptr) {
        gresponse->set_containerjson(response->container_json);
    }
}

void ContainerInspectService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_inspect_request(static_cast<container_inspect_request *>(containerReq));
    free_container_inspect_response(static_cast<container_inspect_response *>(containerRes));
}