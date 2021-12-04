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
 * Description: store streaming requests and generates a single-use random token for retrieval.
 * Author: wujing
 * Create: 2019-01-02
 ******************************************************************************/

#ifndef DAEMON_ENTRY_CRI_REQUEST_CACHE_H
#define DAEMON_ENTRY_CRI_REQUEST_CACHE_H
#include <string>
#include <list>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <typeinfo>
#include <google/protobuf/message.h>

struct CacheEntry {
    std::string token;
    std::string containerID;
    ::google::protobuf::Message *req;
    std::chrono::system_clock::time_point expireTime;

    void SetValue(const std::string &t, const std::string &id, ::google::protobuf::Message *request,
                  std::chrono::system_clock::time_point et);
};

class RequestCache {
public:
    static RequestCache *GetInstance() noexcept;
    std::string InsertRequest(const std::string &containerID, ::google::protobuf::Message *req);
    ::google::protobuf::Message *ConsumeRequest(const std::string &token);
    std::string GetContainerIDByToken(const std::string &token);
    bool IsValidToken(const std::string &token);

private:
    void GarbageCollection();
    std::string UniqueToken();

private:
    RequestCache() = default;
    RequestCache(const RequestCache &) = delete;
    RequestCache &operator=(const RequestCache &) = delete;
    virtual ~RequestCache() = default;
    // tokens maps the generate token to the request for fast retrieval.
    std::unordered_map<std::string, CacheEntry> m_tokens;
    // ll maintains an age-ordered request list for faster garbage collection of expired requests.
    std::list<CacheEntry> m_ll;
    static std::mutex m_mutex;
    static std::atomic<RequestCache *> m_instance;
    const size_t MaxInFlight { 1000 };
    const size_t TokenLen { 64 };
};

#endif // DAEMON_ENTRY_CRI_REQUEST_CACHE_H
