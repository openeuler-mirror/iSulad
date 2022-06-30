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
 * Description: implement grpc container resume service functions
 ******************************************************************************/
#include "resume_service.h"

void ContainerResumeService::SetThreadName()
{
    SetOperationThreadName("ContResume");
}

Status ContainerResumeService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_unpause");
}

bool ContainerResumeService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.resume != nullptr;
}

int ContainerResumeService::FillRequestFromgRPC(const ResumeRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_resume_request *>(util_common_calloc_s(sizeof(container_resume_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->id = util_strdup_s(request->id().c_str());
    }

    *static_cast<container_resume_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerResumeService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.resume(static_cast<container_resume_request *>(containerReq),
                              static_cast<container_resume_response **>(containerRes));
}

void ContainerResumeService::FillResponseTogRPC(void *containerRes, ResumeResponse *gresponse)
{
    const container_resume_response *response = static_cast<const container_resume_response *>(containerRes);

    ResponseToGrpc(response, gresponse);
}

void ContainerResumeService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_resume_request(static_cast<container_resume_request *>(containerReq));
    free_container_resume_response(static_cast<container_resume_response *>(containerRes));
}
