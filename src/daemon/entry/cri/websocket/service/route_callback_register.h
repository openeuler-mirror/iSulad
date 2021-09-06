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
#include "isula_libutils/log.h"

struct session_data;

class StreamingServeInterface {
public:
    StreamingServeInterface() = default;
    StreamingServeInterface(const StreamingServeInterface &) = delete;
    StreamingServeInterface &operator=(const StreamingServeInterface &) = delete;
    virtual ~StreamingServeInterface() = default;
    virtual int Execute(session_data *lws_ctx, const std::string &token) = 0;
};

class RouteCallbackRegister {
public:
    RouteCallbackRegister() = default;
    RouteCallbackRegister(const RouteCallbackRegister &) = delete;
    RouteCallbackRegister &operator=(const RouteCallbackRegister &) = delete;
    virtual ~RouteCallbackRegister() = default;
    bool IsValidMethod(const std::string &method)
    {
        return static_cast<bool>(m_registeredcallbacks.count(method));
    }

    int HandleCallback(session_data *lws_ctx, const std::string &method,
                       const std::string &token)
    {
        auto it = m_registeredcallbacks.find(method);
        if (it != m_registeredcallbacks.end()) {
            std::shared_ptr<StreamingServeInterface> callback = it->second;
            if (callback) {
                return callback->Execute(lws_ctx, token);
            }
        }
        ERROR("invalid method!");
        return -1;
    }
    void RegisterCallback(const std::string &path,
                          std::shared_ptr<StreamingServeInterface> callback)
    {
        m_registeredcallbacks.insert(std::pair<std::string,
                                     std::shared_ptr<StreamingServeInterface>>(path, callback));
    }

private:
    std::map<std::string, std::shared_ptr<StreamingServeInterface>> m_registeredcallbacks;
};

class StreamTask {
public:
    StreamTask(RouteCallbackRegister *invoker, session_data *lws_ctx,
               const std::string &method,
               const std::string &token)
        : m_invoker(invoker), m_lws_ctx(lws_ctx), m_method(method), m_token(token) {}
    StreamTask(const StreamTask &) = delete;
    StreamTask &operator=(const StreamTask &) = delete;
    virtual ~StreamTask() = default;
    int Run()
    {
        return m_invoker->HandleCallback(m_lws_ctx, m_method, m_token);
    }
private:
    RouteCallbackRegister *m_invoker{ nullptr };
    session_data *m_lws_ctx;
    std::string m_method;
    std::string m_token;
};

#endif // DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_ROUTE_CALLBACK_REGISTER_H


