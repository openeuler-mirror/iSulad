/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2018-11-08
 * Description: provide container attach functions
 ******************************************************************************/

#include "attach_serve.h"
#include "api.pb.h"
#include "ws_server.h"
#include "isula_libutils/log.h"
#include "callback.h"
#include "utils.h"

void AttachServe::SetServeThreadName()
{
    prctl(PR_SET_NAME, "AttachServe");
}

void *AttachServe::SetContainerStreamRequest(::google::protobuf::Message *request, const std::string &suffix)
{
    auto *grequest = dynamic_cast<runtime::v1alpha2::AttachRequest *>(request);

    auto *m_request = static_cast<container_attach_request *>(util_common_calloc_s(sizeof(container_attach_request)));
    if (m_request == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }

    if (!grequest->container_id().empty()) {
        m_request->container_id = util_strdup_s(grequest->container_id().c_str());
    }
    m_request->attach_stdin = grequest->stdin();
    m_request->attach_stdout = grequest->stdout();
    m_request->attach_stderr = grequest->stderr();

    return m_request;
}

int AttachServe::ExecuteStreamCommand(SessionData *lwsCtx, void *request)
{
    auto *cb = get_service_executor();
    if (cb == nullptr || cb->container.attach == nullptr) {
        ERROR("Failed to get attach service executor");
        sem_post(lwsCtx->syncCloseSem);
        return -1;
    }

    struct io_write_wrapper stringWriter = { 0 };
    stringWriter.context = (void *)(lwsCtx);
    stringWriter.write_func = WsWriteStdoutToClient;
    stringWriter.close_func = closeWsConnect;

    auto *m_request = static_cast<container_attach_request *>(request);
    m_request->attach_stderr = false;

    container_attach_response *m_response { nullptr };
    int ret = cb->container.attach(m_request, &m_response, m_request->attach_stdin ? lwsCtx->pipes.at(0) : -1,
                                   m_request->attach_stdout ? &stringWriter : nullptr, nullptr);

    if (ret != 0) {
        ERROR("Failed to attach container: %s", m_request->container_id);
        sem_post(lwsCtx->syncCloseSem);
    }

    free_container_attach_response(m_response);
    return ret;
}

void AttachServe::CloseConnect(SessionData *lwsCtx)
{
    (void)lwsCtx;
}

void AttachServe::FreeRequest(void *m_request)
{
    free_container_attach_request(static_cast<container_attach_request *>(m_request));
}
