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
 * Description: implement grpc container rename service functions
 ******************************************************************************/
#include "rename_service.h"

void ContainerRenameService::SetThreadName()
{
    SetOperationThreadName("ContRename");
}

Status ContainerRenameService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_rename");
}

bool ContainerRenameService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.rename != nullptr;
}

int ContainerRenameService::FillRequestFromgRPC(const RenameRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<isulad_container_rename_request *>(
                       util_common_calloc_s(sizeof(isulad_container_rename_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->oldname().empty()) {
        tmpreq->old_name = util_strdup_s(request->oldname().c_str());
    }

    if (!request->newname().empty()) {
        tmpreq->new_name = util_strdup_s(request->newname().c_str());
    }

    *static_cast<isulad_container_rename_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerRenameService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.rename(static_cast<isulad_container_rename_request *>(containerReq),
                               static_cast<isulad_container_rename_response **>(containerRes));
}

void ContainerRenameService::FillResponseTogRPC(void *containerRes, RenameResponse *gresponse)
{
    const isulad_container_rename_response *response =
        static_cast<const isulad_container_rename_response *>(containerRes);

    ResponseToGrpc(response, gresponse);

    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }
}

void ContainerRenameService::CleanUp(void *containerReq, void *containerRes)
{
    isulad_container_rename_request_free(static_cast<isulad_container_rename_request *>(containerReq));
    isulad_container_rename_response_free(static_cast<isulad_container_rename_response *>(containerRes));
}