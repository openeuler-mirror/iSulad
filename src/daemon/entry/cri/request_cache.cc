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
 * Author: wujing
 * Create: 2019-01-02
 * Description: provide request cache function definition
 *********************************************************************************/
#include "request_cache.h"
#include <iostream>
#include <utility>
#include <chrono>
#include <thread>
#include <mutex>
#include <cmath>
#include <isula_libutils/log.h>
#include "utils.h"
#include "utils_base64.h"

std::atomic<RequestCache *> RequestCache::m_instance;
std::mutex RequestCache::m_mutex;

void CacheEntry::SetValue(const std::string &t, const std::string &id, ::google::protobuf::Message *request,
                          std::chrono::system_clock::time_point et)
{
    token = t;
    containerID = id;
    req = request;
    expireTime = et;
}

RequestCache *RequestCache::GetInstance() noexcept
{
    auto *cache = m_instance.load(std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_acquire);
    if (cache == nullptr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        cache = m_instance.load(std::memory_order_relaxed);
        if (cache == nullptr) {
            cache = new RequestCache;
            std::atomic_thread_fence(std::memory_order_release);
            m_instance.store(cache, std::memory_order_relaxed);
        }
    }
    return cache;
}

std::string RequestCache::InsertRequest(const std::string &containerID, ::google::protobuf::Message *req)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    // Remove expired entries.
    GarbageCollection();
    // If the cache is full, reject the request.
    if (m_ll.size() == MaxInFlight) {
        ERROR("too many cache in flight!");
        return "";
    }
    auto token = UniqueToken();
    CacheEntry tmp;
    tmp.SetValue(token, containerID, req, std::chrono::system_clock::now() + std::chrono::minutes(1));
    m_ll.push_front(tmp);
    m_tokens.insert(std::make_pair(token, tmp));
    return token;
}

void RequestCache::GarbageCollection()
{
    auto now = std::chrono::system_clock::now();
    while (!m_ll.empty()) {
        auto oldest = m_ll.back();
        if (now < oldest.expireTime) {
            return;
        }
        if (oldest.req != nullptr) {
            delete oldest.req;
            oldest.req = nullptr;
        }
        m_ll.pop_back();
        m_tokens.erase(oldest.token);
    }
}

std::string RequestCache::UniqueToken()
{
    const int maxTries { 50 };
    // Number of bytes to be TokenLen when base64 encoded.
    const int rawTokenSize = ceil(static_cast<double>(TokenLen) * 6 / 8);
    for (int i {}; i < maxTries; ++i) {
        char rawToken[rawTokenSize + 1];
        (void)memset(rawToken, 0, sizeof(rawToken));
        if (util_generate_random_str(rawToken, (size_t)rawTokenSize)) {
            ERROR("Generate rawToken failed");
            continue;
        }

        char *b64EncodeBuf = nullptr;
        if (util_base64_encode((unsigned char *)rawToken, strlen(rawToken), &b64EncodeBuf) < 0) {
            ERROR("Encode raw token to base64 failed");
            continue;
        }

        std::string token(b64EncodeBuf);
        free(b64EncodeBuf);
        b64EncodeBuf = nullptr;
        if (token.length() != TokenLen) {
            continue;
        }

        auto it = m_tokens.find(token);
        if (it == m_tokens.end()) {
            return token;
        }
    }
    ERROR("create unique token failed!");
    return "";
}

bool RequestCache::IsValidToken(const std::string &token)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    return static_cast<bool>(m_tokens.count(token));
}

// Consume the token (remove it from the cache) and return the cached request, if found.
::google::protobuf::Message *RequestCache::ConsumeRequest(const std::string &token)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_tokens.count(token) == 0) {
        ERROR("Invalid token");
        return nullptr;
    }

    CacheEntry ele = m_tokens[token];
    for (auto it = m_ll.begin(); it != m_ll.end(); it++) {
        if (it->token == token) {
            m_ll.erase(it);
            break;
        }
    }
    m_tokens.erase(token);
    if (std::chrono::system_clock::now() > ele.expireTime) {
        return nullptr;
    }

    return ele.req;
}

std::string RequestCache::GetContainerIDByToken(const std::string &token)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_tokens.count(token) == 0) {
        ERROR("Invalid token");
        return "";
    }

    return m_tokens[token].containerID;
}
