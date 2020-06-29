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
 * Description: store streaming requests and generates a single-use random token for retrieval.
 * Author: wujing
 * Create: 2019-01-02
 ******************************************************************************/

#ifndef __REQUEST_CACHE_H_
#define __REQUEST_CACHE_H_
#include <string>
#include <list>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <google/protobuf/message.h>

typedef struct sCacheEntry {
    std::string token;
    ::google::protobuf::Message *req;
    std::chrono::system_clock::time_point expireTime;
} CacheEntry, *pCacheEntry;

class RequestCache {
public:
    static RequestCache *GetInstance() noexcept;
    std::string Insert(::google::protobuf::Message *req);
    ::google::protobuf::Message *Consume(const std::string &token, bool &found);
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
    const size_t TokenLen { 8 };
};

#endif /* __REQUEST_CACHE_H_ */
