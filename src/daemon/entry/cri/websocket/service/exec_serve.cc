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
 * Description: provide ExecServe functions
 ******************************************************************************/

#include "exec_serve.h"
#include "io_wrapper.h"
#include "utils.h"
#include "cri_helpers.h"

int ExecServe::Execute(session_data *lws_ctx, const std::string &token)
{
    if (lws_ctx == nullptr) {
        return -1;
    }

    service_executor_t *cb = get_service_executor();
    if (cb == nullptr || cb->container.exec == nullptr) {
        sem_post(lws_ctx->sync_close_sem);
        return -1;
    }

    container_exec_request *container_req = nullptr;
    if (GetContainerRequest(token, lws_ctx->suffix, &container_req) != 0) {
        ERROR("Failed to get contaner request");
        sem_post(lws_ctx->sync_close_sem);
        return -1;
    }

    struct io_write_wrapper StdoutstringWriter = { 0 };
    StdoutstringWriter.context = (void *)lws_ctx;
    StdoutstringWriter.write_func = WsWriteStdoutToClient;
    // the close function of StderrstringWriter is preferred unless StderrstringWriter is nullptr
    StdoutstringWriter.close_func = nullptr;
    struct io_write_wrapper StderrstringWriter = { 0 };
    StderrstringWriter.context = (void *)lws_ctx;
    StderrstringWriter.write_func = WsWriteStderrToClient;
    StderrstringWriter.close_func = nullptr;

    container_exec_response *container_res = nullptr;
    int ret = cb->container.exec(container_req, &container_res, container_req->attach_stdin ? lws_ctx->pipes.at(0) : -1,
                                 container_req->attach_stdout ? &StdoutstringWriter : nullptr,
                                 container_req->attach_stderr ? &StderrstringWriter : nullptr);
    if (ret != 0) {
        std::string message;
        if (container_res != nullptr && container_res->errmsg != nullptr) {
            message = container_res->errmsg;
        } else {
            message = "Failed to call exec container callback. ";
        }
        WsWriteStdoutToClient(lws_ctx, message.c_str(), message.length());
    }
    if (container_res != nullptr && container_res->exit_code != 0) {
        std::string exit_info = "Exit code :" + std::to_string((int)container_res->exit_code) + "\n";
        WsWriteStdoutToClient(lws_ctx, exit_info.c_str(), exit_info.length());
    }

    free_container_exec_request(container_req);
    free_container_exec_response(container_res);

    closeWsConnect((void*)lws_ctx, nullptr);

    return ret;
}

int ExecServe::GetContainerRequest(const std::string &token, const std::string &suffix,
                                   container_exec_request **container_req)
{
    RequestCache *cache = RequestCache::GetInstance();
    auto request = cache->ConsumeExecRequest(token);

    int ret = RequestFromCri(request, suffix, container_req);
    if (ret != 0) {
        ERROR("Failed to transform grpc request!");
    }

    return ret;
}

int ExecServe::RequestFromCri(const runtime::v1alpha2::ExecRequest &grequest, const std::string &suffix,
                              container_exec_request **request)
{
    container_exec_request *tmpreq = nullptr;

    tmpreq = (container_exec_request *)util_common_calloc_s(sizeof(container_exec_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    tmpreq->tty = grequest.tty();
    tmpreq->attach_stdin = grequest.stdin();
    tmpreq->attach_stdout = grequest.stdout();
    tmpreq->attach_stderr = grequest.stderr();

    if (!grequest.container_id().empty()) {
        tmpreq->container_id = util_strdup_s(grequest.container_id().c_str());
    }

    if (grequest.cmd_size() > 0) {
        if ((size_t)grequest.cmd_size() > SIZE_MAX / sizeof(char *)) {
            ERROR("Too many arguments!");
            free_container_exec_request(tmpreq);
            return -1;
        }
        tmpreq->argv = (char **)util_common_calloc_s(sizeof(char *) * grequest.cmd_size());
        if (tmpreq->argv == nullptr) {
            ERROR("Out of memory!");
            free_container_exec_request(tmpreq);
            return -1;
        }
        for (int i = 0; i < grequest.cmd_size(); i++) {
            tmpreq->argv[i] = util_strdup_s(grequest.cmd(i).c_str());
        }
        tmpreq->argv_len = (size_t)grequest.cmd_size();
    }

    tmpreq->suffix = util_strdup_s(suffix.c_str());

    *request = tmpreq;
    return 0;
}
