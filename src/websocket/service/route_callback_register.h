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

#ifndef __ROUTE_CALLBACK_REGISTER_H_
#define __ROUTE_CALLBACK_REGISTER_H_
#include <iostream>
#include <string>
#include <memory>
#include <utility>
#include <map>
#include <unistd.h>
#include "isula_libutils/log.h"
class StreamingServeInterface {
public:
    StreamingServeInterface() = default;
    StreamingServeInterface(const StreamingServeInterface &) = delete;
    StreamingServeInterface &operator=(const StreamingServeInterface &) = delete;
    virtual ~StreamingServeInterface() = default;
    virtual int Execute(struct lws *wsi, const std::string &token, int read_pipe_fd) = 0;
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

    int HandleCallback(struct lws *wsi, const std::string &method,
                       const std::string &token,
                       int read_pipe_fd)
    {
        auto it = m_registeredcallbacks.find(method);
        if (it != m_registeredcallbacks.end()) {
            std::shared_ptr<StreamingServeInterface> callback = it->second;
            if (callback) {
                return callback->Execute(wsi, token, read_pipe_fd);
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
    StreamTask(RouteCallbackRegister *invoker, struct lws *wsi,
               const std::string &method,
               const std::string &token, int read_pipe_fd)
        : m_invoker(invoker), m_wsi(wsi), m_method(method), m_token(token),
          m_read_pipe_fd(read_pipe_fd) {}
    StreamTask(const StreamTask &) = delete;
    StreamTask &operator=(const StreamTask &) = delete;
    virtual ~StreamTask() = default;
    int Run()
    {
        return m_invoker->HandleCallback(m_wsi, m_method, m_token, m_read_pipe_fd);
    }
private:
    RouteCallbackRegister *m_invoker{ nullptr };
    struct lws *m_wsi;
    std::string m_method;
    std::string m_token;
    int m_read_pipe_fd;
};

#endif /* __ROUTE_CALLBACK_REGISTER_H_ */


