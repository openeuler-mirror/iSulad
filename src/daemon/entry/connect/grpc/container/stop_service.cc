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
 * Stop: 2022-06-24
 * Description: implement grpc container stop service functions
 ******************************************************************************/
#include "stop_service.h"

void ContainerStopService::SetThreadName()
{
    SetOperationThreadName("ContStop");
}

Status ContainerStopService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_stop");
}

bool ContainerStopService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.stop != nullptr;
}

int ContainerStopService::FillRequestFromgRPC(const containers::StopRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_stop_request *>(util_common_calloc_s(sizeof(container_stop_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->id = util_strdup_s(request->id().c_str());
    }
    tmpreq->force = request->force();
    tmpreq->timeout = request->timeout();

    *static_cast<container_stop_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerStopService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.stop(static_cast<container_stop_request *>(containerReq),
                             static_cast<container_stop_response **>(containerRes));
}

void ContainerStopService::FillResponseTogRPC(void *containerRes, containers::StopResponse *gresponse)
{
    const container_stop_response *response = static_cast<const container_stop_response *>(containerRes);

    ResponseToGrpc(response, gresponse);

    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }
}

void ContainerStopService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_stop_request(static_cast<container_stop_request *>(containerReq));
    free_container_stop_response(static_cast<container_stop_response *>(containerRes));
}
