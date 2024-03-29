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
 * Description: provide ExecServe functions
 ******************************************************************************/

#include "exec_serve.h"
#include <isula_libutils/log.h>
#include "io_wrapper.h"
#include "session.h"
#include "utils.h"
#include "callback.h"
#include "cri_helpers.h"

void ExecServe::SetServeThreadName()
{
    prctl(PR_SET_NAME, "ExecServe");
}

void *ExecServe::SetContainerStreamRequest(StreamRequest *grequest, const std::string &suffix)
{
    auto *m_request = static_cast<container_exec_request *>(util_common_calloc_s(sizeof(container_exec_request)));
    if (m_request == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }

    m_request->tty = grequest->streamTty;
    m_request->attach_stdin = grequest->streamStdin;
    m_request->attach_stdout = grequest->streamStdout;
    m_request->attach_stderr = grequest->streamStderr;

    if (!grequest->containerID.empty()) {
        m_request->container_id = util_strdup_s(grequest->containerID.c_str());
    }

    if (grequest->streamCmds.size() > 0) {
        m_request->argv = (char **)util_smart_calloc_s(sizeof(char *), grequest->streamCmds.size());
        if (m_request->argv == nullptr) {
            ERROR("Out of memory!");
            return nullptr;
        }
        size_t i;
        for (i = 0; i < grequest->streamCmds.size(); i++) {
            m_request->argv[i] = util_strdup_s(grequest->streamCmds.at(i).c_str());
        }
        m_request->argv_len = static_cast<size_t>(grequest->streamCmds.size());
    }

    m_request->suffix = util_strdup_s(suffix.c_str());

    return m_request;
}

int ExecServe::ExecuteStreamCommand(SessionData *lwsCtx, void *request)
{
    auto *cb = get_service_executor();
    if (cb == nullptr || cb->container.exec == nullptr) {
        ERROR("Failed to get exec service executor");
        return -1;
    }

    struct io_write_wrapper StdoutstringWriter = { 0 };
    StdoutstringWriter.context = (void *)lwsCtx;
    StdoutstringWriter.write_func = WsWriteStdoutToClient;
    // the close function of StderrstringWriter is preferred unless StderrstringWriter is nullptr
    StdoutstringWriter.close_func = nullptr;
    struct io_write_wrapper StderrstringWriter = { 0 };
    StderrstringWriter.context = (void *)lwsCtx;
    StderrstringWriter.write_func = WsWriteStderrToClient;
    StderrstringWriter.close_func = nullptr;

    auto *m_request = static_cast<container_exec_request *>(request);
    container_exec_response *m_response { nullptr };
    int ret = cb->container.exec(m_request, &m_response, m_request->attach_stdin ? lwsCtx->pipes.at(0) : -1,
                                 m_request->attach_stdout ? &StdoutstringWriter : nullptr,
                                 m_request->attach_stderr ? &StderrstringWriter : nullptr);

    if (ret != 0) {
        std::string message;
        if (m_response != nullptr && m_response->errmsg != nullptr) {
            message = m_response->errmsg;
        } else {
            message = "Failed to call exec container callback. ";
        }
        WsWriteStdoutToClient(lwsCtx, message.c_str(), message.length());
    }
    if (m_response != nullptr && m_response->exit_code != 0) {
        std::string exit_info = "Exit code :" + std::to_string((int)m_response->exit_code) + "\n";
        WsWriteStdoutToClient(lwsCtx, exit_info.c_str(), exit_info.length());
    }

    free_container_exec_response(m_response);
    return ret;
}

void ExecServe::CloseConnect(SessionData *lwsCtx)
{
    closeWsConnect((void *)lwsCtx, nullptr);
}

void ExecServe::FreeRequest(void *m_request)
{
    free_container_exec_request(static_cast<container_exec_request *>(m_request));
}
