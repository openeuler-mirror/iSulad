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
 * Description: Attach streaming service implementation.
 * Author: wujing
 * Create: 2019-01-02
 ******************************************************************************/

#ifndef DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_ATTACH_SERVE_H
#define DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_ATTACH_SERVE_H

#include "route_callback_register.h"
#include <string>
#include "isula_libutils/container_attach_request.h"
#include "isula_libutils/container_attach_response.h"

class AttachServe : public StreamingServeInterface {
public:
    AttachServe() = default;
    AttachServe(const AttachServe &) = delete;
    AttachServe &operator=(const AttachServe &) = delete;
    virtual ~AttachServe();

private:
    virtual void SetServeThreadName() override;
    virtual int SetContainerStreamRequest(::google::protobuf::Message *grequest, const std::string &suffix) override;
    virtual int ExecuteStreamCommand(SessionData *lwsCtx) override;
    virtual void ErrorHandler(int ret, SessionData *lwsCtx) override;
    virtual void CloseConnect(SessionData *lwsCtx) override;

private:
    container_attach_request *m_request { nullptr };
    container_attach_response *m_response { nullptr };
};
#endif // DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_ATTACH_SERVE_H

