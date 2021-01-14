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
#include "api.pb.h"

struct CacheEntry {
    std::string token;
    std::vector<runtime::v1alpha2::ExecRequest>  execRequest;
    std::vector<runtime::v1alpha2::AttachRequest>  attachRequest;
    std::chrono::system_clock::time_point expireTime;

    void SetValue(const std::string &t,
                  const runtime::v1alpha2::ExecRequest *execReq,
                  const runtime::v1alpha2::AttachRequest *attachReq,
                  std::chrono::system_clock::time_point et)
    {
        token = t;
        if (execReq != nullptr) {
            execRequest.push_back(*execReq);
        } else if (attachReq != nullptr) {
            attachRequest.push_back(*attachReq);
        }
        expireTime = et;
    }
};

class RequestCache {
public:
    static RequestCache *GetInstance() noexcept;
    std::string InsertExecRequest(const runtime::v1alpha2::ExecRequest &req);
    std::string InsertAttachRequest(const runtime::v1alpha2::AttachRequest &req);
    runtime::v1alpha2::ExecRequest ConsumeExecRequest(const std::string &token);
    runtime::v1alpha2::AttachRequest ConsumeAttachRequest(const std::string &token);
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
