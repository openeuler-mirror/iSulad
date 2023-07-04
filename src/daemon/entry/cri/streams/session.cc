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
#include "session.h"

#include <isula_libutils/log.h>
#include "ws_server.h"
#include "utils.h"

namespace {
// io copy maximum single transfer 4K, let max total buffer size: 1GB
const int FIFO_LIST_BUFFER_MAX_LEN = 262144;
}; // namespace

unsigned char *SessionData::FrontMessage()
{
    unsigned char *message = nullptr;

    if (sessionMutex == nullptr) {
        return nullptr;
    }

    sessionMutex->lock();
    message = buffer.front();
    sessionMutex->unlock();

    return message;
}

void SessionData::PopMessage()
{
    if (sessionMutex == nullptr) {
        return;
    }

    sessionMutex->lock();
    buffer.pop_front();
    sessionMutex->unlock();
}

int SessionData::PushMessage(unsigned char *message)
{
    if (sessionMutex == nullptr) {
        return -1;
    }

    sessionMutex->lock();

    if (!close && buffer.size() < FIFO_LIST_BUFFER_MAX_LEN) {
        buffer.push_back(message);
        sessionMutex->unlock();
        return 0;
    }

    // In extreme scenarios, websocket data cannot be processed,
    // ignore the data coming in later to prevent iSulad from getting stuck
    free(message);
    sessionMutex->unlock();

    if (close) {
        DEBUG("Closed session");
    }
    if (buffer.size() >= FIFO_LIST_BUFFER_MAX_LEN) {
        ERROR("Too large: %zu message!", buffer.size());
    }

    return -1;
}

bool SessionData::IsClosed()
{
    bool c = false;

    if (sessionMutex == nullptr) {
        return true;
    }

    sessionMutex->lock();
    c = close;
    sessionMutex->unlock();

    return c;
}

void SessionData::CloseSession()
{
    if (sessionMutex == nullptr) {
        return;
    }

    sessionMutex->lock();
    close = true;
    sessionMutex->unlock();
}

bool SessionData::IsStdinComplete()
{
    bool c = true;

    if (sessionMutex == nullptr) {
        return true;
    }

    sessionMutex->lock();
    c = completeStdin;
    sessionMutex->unlock();

    return c;
}

void SessionData::SetStdinComplete(bool complete)
{
    if (sessionMutex == nullptr) {
        return;
    }

    sessionMutex->lock();
    completeStdin = complete;
    sessionMutex->unlock();
}

void SessionData::EraseAllMessage()
{
    if (sessionMutex == nullptr) {
        return;
    }

    sessionMutex->lock();
    for (auto iter = buffer.begin(); iter != buffer.end();) {
        free(*iter);
        *iter = NULL;
        iter = buffer.erase(iter);
    }
    sessionMutex->unlock();
}


namespace {
// TODO: we should change WebsocketChannel to common type
void DoWriteToClient(SessionData *session, const void *data, size_t len, WebsocketChannel channel)
{
    auto *buf = static_cast<unsigned char *>(util_common_calloc_s(LWS_PRE + MAX_BUFFER_SIZE + 1));
    if (buf == nullptr) {
        ERROR("Out of memory");
        return;
    }
    // Determine if it is standard output channel or error channel
    buf[LWS_PRE] = static_cast<int>(channel);

    (void)memcpy(&buf[LWS_PRE + 1], const_cast<void *>(data), len);

    // push back to message list
    if (session->PushMessage(buf) != 0) {
        ERROR("Abnormal, websocket data cannot be processed, ignore the data"
              "coming in later to prevent daemon from getting stuck");
    }
}

ssize_t WsWriteToClient(void *context, const void *data, size_t len, WebsocketChannel channel)
{
    auto *lwsCtx = static_cast<SessionData *>(context);

    // CloseWsSession wait IOCopy finished, and then delete session in m_wsis
    // So don't need rdlock m_wsis here
    if (lwsCtx->IsClosed()) {
        return 0;
    }

    DoWriteToClient(lwsCtx, data, len, channel);
    return static_cast<ssize_t>(len);
}
}; // namespace

ssize_t WsWriteStdoutToClient(void *context, const void *data, size_t len)
{
    if (context == nullptr) {
        ERROR("websocket session context empty");
        return -1;
    }

    return WsWriteToClient(context, data, len, STDOUTCHANNEL);
}

ssize_t WsWriteStderrToClient(void *context, const void *data, size_t len)
{
    if (context == nullptr) {
        ERROR("websocket session context empty");
        return -1;
    }

    return WsWriteToClient(context, data, len, STDERRCHANNEL);
}

ssize_t WsDoNotWriteStdoutToClient(void *context, const void *data, size_t len)
{
    if (context == nullptr) {
        ERROR("websocket session context empty");
        return -1;
    }

    TRACE("Ws do not write stdout to client");
    return len;
}

ssize_t WsDoNotWriteStderrToClient(void *context, const void *data, size_t len)
{
    if (context == nullptr) {
        ERROR("websocket session context empty");
        return -1;
    }

    TRACE("Ws do not write stderr to client");
    return len;
}

int closeWsConnect(void *context, char **err)
{
    (void)err;

    if (context == nullptr) {
        ERROR("websocket session context empty");
        return -1;
    }

    auto *lwsCtx = static_cast<SessionData *>(context);

    lwsCtx->CloseSession();

    if (lwsCtx->syncCloseSem != nullptr) {
        (void)sem_post(lwsCtx->syncCloseSem);
    }

    return 0;
}