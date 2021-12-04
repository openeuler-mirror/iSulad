/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
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
 * Create: 2021-11-04
 ******************************************************************************/
#include "route_callback_register.h"
#include <isula_libutils/log.h>
#include "ws_server.h"

int StreamingServeInterface::Execute(SessionData *lwsCtx, const std::string &token)
{
    if (lwsCtx == nullptr) {
        return -1;
    }

    SetServeThreadName();

    auto *cache = RequestCache::GetInstance();
    auto request = cache->ConsumeRequest(token);
    if (request == nullptr) {
        ERROR("Failed to get cache request!");
        sem_post(lwsCtx->syncCloseSem);
        return -1;
    }

    if (SetContainerStreamRequest(request, lwsCtx->suffix) != 0) {
        ERROR("Failed to set container request");
        sem_post(lwsCtx->syncCloseSem);
        return -1;
    }

    // request is stored on the heap in the cache and needs to be released after use
    delete request;
    request = nullptr;

    int ret = ExecuteStreamCommand(lwsCtx);

    ErrorHandler(ret, lwsCtx);

    CloseConnect(lwsCtx);

    return ret;
}

bool RouteCallbackRegister::IsValidMethod(const std::string &method)
{
    return static_cast<bool>(m_registeredcallbacks.count(method));
}

int RouteCallbackRegister::HandleCallback(SessionData *lwsCtx, const std::string &method, const std::string &token)
{
    auto it = m_registeredcallbacks.find(method);
    if (it != m_registeredcallbacks.end()) {
        std::shared_ptr<StreamingServeInterface> callback = it->second;
        if (callback) {
            return callback->Execute(lwsCtx, token);
        }
    }
    ERROR("invalid method!");
    return -1;
}

void RouteCallbackRegister::RegisterCallback(const std::string &path, std::shared_ptr<StreamingServeInterface> callback)
{
    m_registeredcallbacks.insert(std::pair<std::string, std::shared_ptr<StreamingServeInterface>>(path, callback));
}

int StreamTask::Run()
{
    return m_invoker->HandleCallback(m_lwsCtx, m_method, m_token);
}