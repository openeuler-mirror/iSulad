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

int AttachServe::Execute(session_data *lws_ctx, const std::string &token)
{
    if (lws_ctx == nullptr) {
        return -1;
    }

    prctl(PR_SET_NAME, "AttachServe");

    service_executor_t *cb = get_service_executor();
    if (cb == nullptr || cb->container.attach == nullptr) {
        sem_post(lws_ctx->sync_close_sem);
        return -1;
    }

    container_attach_request *container_req = nullptr;
    if (GetContainerRequest(token, &container_req) != 0) {
        ERROR("Failed to get contaner request");
        sem_post(lws_ctx->sync_close_sem);
        return -1;
    }

    struct io_write_wrapper stringWriter = { 0 };
    stringWriter.context = (void *)(lws_ctx);
    stringWriter.write_func = WsWriteStdoutToClient;
    stringWriter.close_func = closeWsConnect;
    container_req->attach_stderr = false;

    container_attach_response *container_res = nullptr;
    int ret = cb->container.attach(container_req, &container_res, container_req->attach_stdin ? lws_ctx->pipes.at(0) : -1,
                                   container_req->attach_stdout ? &stringWriter : nullptr, nullptr);
    if (ret != 0) {
        ERROR("Failed to attach container: %s", container_req->container_id);
        sem_post(lws_ctx->sync_close_sem);
    }

    free_container_attach_request(container_req);
    free_container_attach_response(container_res);

    return ret;
}

int AttachServe::GetContainerRequest(const std::string &token, container_attach_request **container_req)
{
    RequestCache *cache = RequestCache::GetInstance();
    auto request = cache->ConsumeAttachRequest(token);

    int ret = RequestFromCri(request, container_req);
    if (ret != 0) {
        ERROR("Failed to transform grpc request!");
    }

    return ret;
}

int AttachServe::RequestFromCri(const runtime::v1alpha2::AttachRequest &grequest, container_attach_request **request)
{
    container_attach_request *tmpreq = nullptr;

    tmpreq = (container_attach_request *)util_common_calloc_s(sizeof(container_attach_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest.container_id().empty()) {
        tmpreq->container_id = util_strdup_s(grequest.container_id().c_str());
    }
    tmpreq->attach_stdin = grequest.stdin();
    tmpreq->attach_stdout = grequest.stdout();
    tmpreq->attach_stderr = grequest.stderr();

    *request = tmpreq;

    return 0;
}
