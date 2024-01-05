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
 * Description: implement grpc container export service functions
 ******************************************************************************/
#include "export_service.h"

void ContainerExportService::SetThreadName()
{
    SetOperationThreadName("ContExport");
}

Status ContainerExportService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_export");
}

bool ContainerExportService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.export_rootfs != nullptr;
}

int ContainerExportService::FillRequestFromgRPC(const containers::ExportRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_export_request *>(util_common_calloc_s(sizeof(container_export_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->id().empty()) {
        tmpreq->id = util_strdup_s(request->id().c_str());
    }

    if (!request->file().empty()) {
        tmpreq->file = util_strdup_s(request->file().c_str());
    }

    *static_cast<container_export_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerExportService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.export_rootfs(static_cast<container_export_request *>(containerReq),
                                      static_cast<container_export_response **>(containerRes));
}

void ContainerExportService::FillResponseTogRPC(void *containerRes, containers::ExportResponse *gresponse)
{
    const container_export_response *response = static_cast<const container_export_response *>(containerRes);

    ResponseToGrpc(response, gresponse);
}

void ContainerExportService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_export_request(static_cast<container_export_request *>(containerReq));
    free_container_export_response(static_cast<container_export_response *>(containerRes));
}