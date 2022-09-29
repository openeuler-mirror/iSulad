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
 * Start: 2022-08-20
 * Description: implement grpc container resize service functions
 ******************************************************************************/
#include "resize_service.h"

void ContainerResizeService::SetThreadName()
{
    SetOperationThreadName("ContResize");
}

Status ContainerResizeService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_resize");
}

bool ContainerResizeService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.resize != nullptr;
}

int ContainerResizeService::FillRequestFromgRPC(const ResizeRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<isulad_container_resize_request *>(
                       util_common_calloc_s(sizeof(isulad_container_resize_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->id = util_strdup_s(request->id().c_str());
    }

    if (!request->suffix().empty()) {
        tmpreq->suffix = util_strdup_s(request->suffix().c_str());
    }

    tmpreq->height = request->height();

    tmpreq->width = request->width();

    *static_cast<isulad_container_resize_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerResizeService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.resize(static_cast<isulad_container_resize_request *>(containerReq),
                               static_cast<isulad_container_resize_response **>(containerRes));
}

void ContainerResizeService::FillResponseTogRPC(void *containerRes, ResizeResponse *gresponse)
{
    const isulad_container_resize_response *response =
        static_cast<const isulad_container_resize_response *>(containerRes);

    ResponseToGrpc(response, gresponse);
    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }
}

void ContainerResizeService::CleanUp(void *containerReq, void *containerRes)
{
    isulad_container_resize_request_free(static_cast<isulad_container_resize_request *>(containerReq));
    isulad_container_resize_response_free(static_cast<isulad_container_resize_response *>(containerRes));
}
