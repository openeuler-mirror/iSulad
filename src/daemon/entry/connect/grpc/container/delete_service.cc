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
 * Delete: 2022-06-24
 * Description: implement grpc container delete service functions
 ******************************************************************************/
#include "delete_service.h"

void ContainerDeleteService::SetThreadName()
{
    SetOperationThreadName("ContDelete");
}

Status ContainerDeleteService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_delete");
}

bool ContainerDeleteService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.remove != nullptr;
}

int ContainerDeleteService::FillRequestFromgRPC(const DeleteRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_delete_request *>(util_common_calloc_s(sizeof(container_delete_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->id = util_strdup_s(request->id().c_str());
    }
    tmpreq->force = request->force();
    tmpreq->volumes = request->volumes();

    *static_cast<container_delete_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerDeleteService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.remove(static_cast<container_delete_request *>(containerReq),
                             static_cast<container_delete_response **>(containerRes));
}

void ContainerDeleteService::FillResponseTogRPC(void *containerRes, DeleteResponse *gresponse)
{
    const container_delete_response *response = static_cast<const container_delete_response *>(containerRes);

    ResponseToGrpc(response, gresponse);

    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }
}

void ContainerDeleteService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_delete_request(static_cast<container_delete_request *>(containerReq));
    free_container_delete_response(static_cast<container_delete_response *>(containerRes));
}
