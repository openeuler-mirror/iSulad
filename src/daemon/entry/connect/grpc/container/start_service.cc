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
 * Description: implement grpc container start service functions
 ******************************************************************************/
#include "start_service.h"

void ContainerStartService::SetThreadName()
{
    SetOperationThreadName("ContStart");
}

Status ContainerStartService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_start");
}

bool ContainerStartService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.start != nullptr;
}

int ContainerStartService::FillRequestFromgRPC(const StartRequest *request, void *contReq)
{
    container_start_request *tmpreq = nullptr;

    tmpreq = static_cast<container_start_request *>(util_common_calloc_s(sizeof(container_start_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->id = util_strdup_s(request->id().c_str());
    }

    if (!request->stdin().empty()) {
        tmpreq->stdin = util_strdup_s(request->stdin().c_str());
    }
    if (!request->stdout().empty()) {
        tmpreq->stdout = util_strdup_s(request->stdout().c_str());
    }
    if (!request->stderr().empty()) {
        tmpreq->stderr = util_strdup_s(request->stderr().c_str());
    }
    tmpreq->attach_stdin = request->attach_stdin();
    tmpreq->attach_stdout = request->attach_stdout();
    tmpreq->attach_stderr = request->attach_stderr();

    *static_cast<container_start_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerStartService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.start(static_cast<container_start_request *>(containerReq),
                              static_cast<container_start_response **>(containerRes), -1, nullptr, nullptr);
}

void ContainerStartService::FillResponseTogRPC(void *containerRes, StartResponse *gresponse)
{
    const container_start_response *response = static_cast<const container_start_response *>(containerRes);

    ResponseToGrpc(response, gresponse);
}

void ContainerStartService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_start_request(static_cast<container_start_request *>(containerReq));
    free_container_start_response(static_cast<container_start_response *>(containerRes));
}