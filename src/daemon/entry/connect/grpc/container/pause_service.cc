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
 * Description: implement grpc container pause service functions
 ******************************************************************************/
#include "pause_service.h"

void ContainerPauseService::SetThreadName()
{
    SetOperationThreadName("ContPause");
}

Status ContainerPauseService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_pause");
}

bool ContainerPauseService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.pause != nullptr;
}

int ContainerPauseService::FillRequestFromgRPC(const containers::PauseRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_pause_request *>(util_common_calloc_s(sizeof(container_pause_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->id = util_strdup_s(request->id().c_str());
    }

    *static_cast<container_pause_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerPauseService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.pause(static_cast<container_pause_request *>(containerReq),
                              static_cast<container_pause_response **>(containerRes));
}

void ContainerPauseService::FillResponseTogRPC(void *containerRes, containers::PauseResponse *gresponse)
{
    const container_pause_response *response = static_cast<const container_pause_response *>(containerRes);

    ResponseToGrpc(response, gresponse);
}

void ContainerPauseService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_pause_request(static_cast<container_pause_request *>(containerReq));
    free_container_pause_response(static_cast<container_pause_response *>(containerRes));
}
