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
 * Description: provide container service base functions
 ******************************************************************************/
#ifndef DAEMON_ENTRY_CONNECT_GRPC_CONTAINER_SERVICE_BASE_H
#define DAEMON_ENTRY_CONNECT_GRPC_CONTAINER_SERVICE_BASE_H
#include <grpc++/grpc++.h>
#include <string>

#include "grpc_server_tls_auth.h"
#include "callback.h"
#include "error.h"
#include "isula_libutils/log.h"
#include "utils.h"

using grpc::Status;
using grpc::ServerContext;
using grpc::StatusCode;

template <class RQ, class RP>
class ContainerServiceBase {
public:
    ContainerServiceBase() = default;

    virtual ~ContainerServiceBase() = default;

    virtual auto Run(ServerContext *context, const RQ *request, RP *reply) -> Status
    {
        service_executor_t *cb = nullptr;
        container_create_response *containerRes = nullptr;
        container_create_request *containerReq = nullptr;

        SetThreadName();

        auto status = Authenticate(context);
        if (!status.ok()) {
            return status;
        }

        cb = get_service_executor();
        if (cb == nullptr || !WithServiceExecutorOperator(cb)) {
            return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
        }

        if (FillRequestFromgRPC(request, &containerReq) != 0) {
            ERROR("Failed to transform grpc request");
            reply->set_cc(ISULAD_ERR_INPUT);
            return Status::OK;
        }

        ServiceRun(cb, containerReq, &containerRes);

        FillResponseTogRPC(containerRes, reply);

        CleanUp(containerReq, containerRes);

        return Status::OK;
    }

    void SetOperationThreadName(const std::string &name)
    {
        pthread_setname_np(pthread_self(), name.c_str());
    }

    Status AuthenticateOperation(ServerContext *context, const std::string &name)
    {
        return GrpcServerTlsAuth::auth(context, name.c_str());
    }

protected:
    virtual void SetThreadName() = 0;
    virtual Status Authenticate(ServerContext *context) = 0;
    virtual bool WithServiceExecutorOperator(service_executor_t *cb) = 0;
    virtual int FillRequestFromgRPC(const RQ *request, void *containerReq) = 0;
    virtual void ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes) = 0;
    virtual void FillResponseTogRPC(void *containerRes, RP *reply) = 0;
    virtual void CleanUp(void *containerReq, void *containerRes) = 0;
};

template <class T1, class T2>
void ResponseToGrpc(const T1 *response, T2 *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return;
    }

    gresponse->set_cc(response->cc);

    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
}

template <class REQUEST, class RESPONSE>
auto SpecificServiceRun(ContainerServiceBase<REQUEST, RESPONSE> &service, ServerContext *context,
                        const REQUEST *request, RESPONSE *response) noexcept -> Status
{
    return service.Run(context, request, response);
}

#endif // DAEMON_ENTRY_CONNECT_GRPC_CONTAINER_SERVICE_BASE_H
