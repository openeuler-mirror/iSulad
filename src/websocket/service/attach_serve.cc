/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide container attach functions
 ******************************************************************************/


#include "attach_serve.h"
#include "utils.h"

int AttachServe::Execute(struct lws *wsi, const std::string &token,
                         int read_pipe_fd)
{
    RequestCache *cache = RequestCache::GetInstance();
    bool found = false;
    auto cachedRequest = cache->Consume(token, found);
    if (!found) {
        ERROR("invalid token :%s", token.c_str());
        return -1;
    }
    runtime::v1alpha2::AttachRequest *request = dynamic_cast<runtime::v1alpha2::AttachRequest *>(cachedRequest);
    if (request == nullptr) {
        ERROR("failed to get exec request!");
        return -1;
    }

    container_attach_request *container_req = nullptr;
    container_attach_response *container_res = nullptr;

    service_callback_t *cb = get_service_callback();
    if (cb == nullptr || cb->container.attach == nullptr) {
        return -1;
    }
    int tret = 0;
    tret = RequestFromCri(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request!");
        return -1;
    }
    struct io_write_wrapper stringWriter = { 0 };
    stringWriter.context = (void *)wsi;
    stringWriter.write_func = WsWriteStdoutToClient;
    stringWriter.close_func = closeWsConnect;
    container_req->attach_stderr = false;
    int ret = cb->container.attach(container_req, &container_res,
                                   container_req->attach_stdin ? read_pipe_fd : -1, &stringWriter, nullptr);
    free_container_attach_request(container_req);
    free_container_attach_response(container_res);

    if (request != nullptr) {
        delete request;
        request = nullptr;
    }
    if (tret != 0) {
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }

    return ret;
}

int AttachServe::RequestFromCri(const runtime::v1alpha2::AttachRequest *grequest,
                                container_attach_request **request)
{
    container_attach_request *tmpreq = nullptr;

    tmpreq = (container_attach_request *)util_common_calloc_s(sizeof(container_attach_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->container_id().empty()) {
        tmpreq->container_id = util_strdup_s(grequest->container_id().c_str());
    }
    tmpreq->attach_stdin = grequest->stdin();
    tmpreq->attach_stdout = grequest->stdout();
    tmpreq->attach_stderr = grequest->stderr();

    *request = tmpreq;

    return 0;
}


