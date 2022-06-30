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
 * Create: 2022-06-14
 * Description: implement grpc container create service functions
 ******************************************************************************/
#include "create_service.h"

void ContainerCreateService::SetThreadName()
{
    SetOperationThreadName("ContCreate");
}

Status ContainerCreateService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_create");
}

bool ContainerCreateService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.create != nullptr;
}

int ContainerCreateService::FillRequestFromgRPC(const CreateRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_create_request *>(util_common_calloc_s(sizeof(container_create_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->id = util_strdup_s(request->id().c_str());
    }
    if (!request->rootfs().empty()) {
        tmpreq->rootfs = util_strdup_s(request->rootfs().c_str());
    }
    if (!request->image().empty()) {
        tmpreq->image = util_strdup_s(request->image().c_str());
    }
    if (!request->runtime().empty()) {
        tmpreq->runtime = util_strdup_s(request->runtime().c_str());
    }
    if (!request->hostconfig().empty()) {
        tmpreq->hostconfig = util_strdup_s(request->hostconfig().c_str());
    }
    if (!request->customconfig().empty()) {
        tmpreq->customconfig = util_strdup_s(request->customconfig().c_str());
    }

    *static_cast<container_create_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerCreateService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.create(static_cast<container_create_request *>(containerReq),
                               static_cast<container_create_response **>(containerRes));
}

void ContainerCreateService::FillResponseTogRPC(void *containerRes, CreateResponse *gresponse)
{
    const container_create_response *response = static_cast<const container_create_response *>(containerRes);
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return;
    }

    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }

    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }
}

void ContainerCreateService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_create_request(static_cast<container_create_request *>(containerReq));
    free_container_create_response(static_cast<container_create_response *>(containerRes));
}
