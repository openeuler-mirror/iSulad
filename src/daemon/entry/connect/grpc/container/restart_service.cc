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
 * Description: implement grpc container restart service functions
 ******************************************************************************/
#include "restart_service.h"

void ContainerRestartService::SetThreadName()
{
    SetOperationThreadName("ContRestart");
}

Status ContainerRestartService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_restart");
}

bool ContainerRestartService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.restart != nullptr;
}

int ContainerRestartService::FillRequestFromgRPC(const containers::RestartRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_restart_request *>(util_common_calloc_s(sizeof(container_restart_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->id = util_strdup_s(request->id().c_str());
    }
    tmpreq->timeout = request->timeout();

    *static_cast<container_restart_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerRestartService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.restart(static_cast<container_restart_request *>(containerReq),
                                static_cast<container_restart_response **>(containerRes));
}

void ContainerRestartService::FillResponseTogRPC(void *containerRes, containers::RestartResponse *gresponse)
{
    const container_restart_response *response = static_cast<const container_restart_response *>(containerRes);

    ResponseToGrpc(response, gresponse);
}

void ContainerRestartService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_restart_request(static_cast<container_restart_request *>(containerReq));
    free_container_restart_response(static_cast<container_restart_response *>(containerRes));
}
