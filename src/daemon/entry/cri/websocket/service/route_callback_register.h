/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: Streaming service function registration.
 * Author: wujing
 * Create: 2019-01-02
 ******************************************************************************/

#ifndef DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_ROUTE_CALLBACK_REGISTER_H
#define DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_ROUTE_CALLBACK_REGISTER_H
#include <iostream>
#include <string>
#include <memory>
#include <utility>
#include <map>
#include <unistd.h>
#include <semaphore.h>
#include "request_cache.h"

struct SessionData;

class StreamingServeInterface {
public:
    StreamingServeInterface() = default;
    StreamingServeInterface(const StreamingServeInterface &) = delete;
    StreamingServeInterface &operator=(const StreamingServeInterface &) = delete;
    virtual ~StreamingServeInterface() = default;
    int Execute(SessionData *lwsCtx, const std::string &token);

protected:
    virtual void SetServeThreadName() = 0;
    virtual void *SetContainerStreamRequest(::google::protobuf::Message *grequest, const std::string &suffix) = 0;
    virtual int ExecuteStreamCommand(SessionData *lwsCtx, void *request) = 0;
    virtual void CloseConnect(SessionData *lwsCtx) = 0;
    virtual void FreeRequest(void *m_request) = 0;
};

class RouteCallbackRegister {
public:
    RouteCallbackRegister() = default;
    RouteCallbackRegister(const RouteCallbackRegister &) = delete;
    RouteCallbackRegister &operator=(const RouteCallbackRegister &) = delete;
    virtual ~RouteCallbackRegister() = default;

    bool IsValidMethod(const std::string &method);
    int HandleCallback(SessionData *lwsCtx, const std::string &method, const std::string &token);
    void RegisterCallback(const std::string &path, std::shared_ptr<StreamingServeInterface> callback);

private:
    std::map<std::string, std::shared_ptr<StreamingServeInterface>> m_registeredcallbacks;
};

class StreamTask {
public:
    StreamTask(RouteCallbackRegister *invoker, SessionData *lwsCtx, const std::string &method,
               const std::string &token)
        : m_invoker(invoker)
        , m_lwsCtx(lwsCtx)
        , m_method(method)
        , m_token(token)
    {
    }
    StreamTask(const StreamTask &) = delete;
    StreamTask &operator=(const StreamTask &) = delete;
    virtual ~StreamTask() = default;
    int Run();

private:
    RouteCallbackRegister *m_invoker { nullptr };
    SessionData *m_lwsCtx;
    std::string m_method;
    std::string m_token;
};

#endif // DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_ROUTE_CALLBACK_REGISTER_H
