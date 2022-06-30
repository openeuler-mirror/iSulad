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
 * Description: define grpc container start service functions
 ******************************************************************************/
#ifndef DAEMON_ENTRY_CONNECT_GRPC_CONTAINER_START_SERVICE_H
#define DAEMON_ENTRY_CONNECT_GRPC_CONTAINER_START_SERVICE_H

#include "service_base.h"
#include <grpc++/grpc++.h>
#include "container.pb.h"
#include "callback.h"
#include "error.h"

using grpc::ServerContext;
// Implement of containers service
using namespace containers;

class ContainerStartService : public ContainerServiceBase<StartRequest, StartResponse> {
public:
    ContainerStartService() = default;
    ContainerStartService(const ContainerStartService &) = default;
    ContainerStartService &operator=(const ContainerStartService &) = delete;
    ~ContainerStartService() = default;

protected:
    void SetThreadName() override;
    Status Authenticate(ServerContext *context) override;
    bool WithServiceExecutorOperator(service_executor_t *cb) override;
    int FillRequestFromgRPC(const StartRequest *request, void *containerReq) override;
    void ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes) override;
    void FillResponseTogRPC(void *containerRes, StartResponse *reply) override;
    void CleanUp(void *containerReq, void *containerRes) override;
};

#endif // DAEMON_ENTRY_CONNECT_GRPC_CONTAINER_START_SERVICES_H
