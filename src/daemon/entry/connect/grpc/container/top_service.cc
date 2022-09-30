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
 * Start: 2022-06-29
 * Description: implement grpc container top service functions
 ******************************************************************************/
#include "top_service.h"

void ContainerTopService::SetThreadName()
{
    SetOperationThreadName("ContTop");
}

Status ContainerTopService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_top");
}

bool ContainerTopService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.top != nullptr;
}

int ContainerTopService::FillRequestFromgRPC(const TopRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_top_request *>(util_common_calloc_s(sizeof(container_top_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->id = util_strdup_s(request->id().c_str());
    }

    if (request->args_size() > 0) {
        tmpreq->args = (char **)util_smart_calloc_s(sizeof(char *), request->args_size());
        if (tmpreq->args == nullptr) {
            ERROR("Out of memory");
            free_container_top_request(tmpreq);
            return -1;
        }
        for (int i = 0; i < request->args_size(); i++) {
            tmpreq->args[i] = util_strdup_s(request->args(i).c_str());
        }
        tmpreq->args_len = (size_t)request->args_size();
    }

    *static_cast<container_top_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerTopService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.top(static_cast<container_top_request *>(containerReq),
                            static_cast<container_top_response **>(containerRes));
}

void ContainerTopService::FillResponseTogRPC(void *containerRes, TopResponse *gresponse)
{
    const container_top_response *response = static_cast<const container_top_response *>(containerRes);

    ResponseToGrpc(response, gresponse);

    if (response->titles != nullptr) {
        gresponse->set_titles(response->titles);
    }

    for (size_t i = 0; i < response->processes_len; i++) {
        gresponse->add_processes(response->processes[i]);
    }
}

void ContainerTopService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_top_request(static_cast<container_top_request *>(containerReq));
    free_container_top_response(static_cast<container_top_response *>(containerRes));
}