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
 * Description: implement grpc container kill service functions
 ******************************************************************************/
#include "kill_service.h"

void ContainerKillService::SetThreadName()
{
    SetOperationThreadName("ContKill");
}

Status ContainerKillService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_kill");
}

bool ContainerKillService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.kill != nullptr;
}

int ContainerKillService::FillRequestFromgRPC(const KillRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_kill_request *>(util_common_calloc_s(sizeof(container_kill_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->id = util_strdup_s(request->id().c_str());
    }

    tmpreq->signal = request->signal();

    *static_cast<container_kill_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerKillService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.kill(static_cast<container_kill_request *>(containerReq),
                             static_cast<container_kill_response **>(containerRes));
}

void ContainerKillService::FillResponseTogRPC(void *containerRes, KillResponse *gresponse)
{
    const container_kill_response *response = static_cast<const container_kill_response *>(containerRes);

    ResponseToGrpc(response, gresponse);

    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }
}

void ContainerKillService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_kill_request(static_cast<container_kill_request *>(containerReq));
    free_container_kill_response(static_cast<container_kill_response *>(containerRes));
}
