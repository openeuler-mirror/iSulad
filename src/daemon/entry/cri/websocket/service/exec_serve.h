/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: Exec streaming service implementation.
 * Author: wujing
 * Create: 2019-01-02
 ******************************************************************************/

#ifndef DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_EXEC_SERVE_H
#define DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_EXEC_SERVE_H

#include <iostream>
#include <string>
#include <chrono>
#include <thread>

#include "route_callback_register.h"
#include "isula_libutils/container_exec_request.h"
#include "isula_libutils/container_exec_response.h"

class ExecServe : public StreamingServeInterface {
public:
    ExecServe() = default;
    ExecServe(const ExecServe &) = delete;
    ExecServe &operator=(const ExecServe &) = delete;
    virtual ~ExecServe() = default;

private:
    virtual void SetServeThreadName() override;
    virtual void *SetContainerStreamRequest(::google::protobuf::Message *grequest, const std::string &suffix) override;
    virtual int ExecuteStreamCommand(SessionData *lwsCtx, void *request) override;
    virtual void CloseConnect(SessionData *lwsCtx) override;
    virtual void FreeRequest(void *m_request);
};
#endif // DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_EXEC_SERVE_H
