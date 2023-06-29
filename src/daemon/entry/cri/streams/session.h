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
 * Description: Streaming service function registration.
 * Author: wujing
 * Create: 2019-01-02
 ******************************************************************************/

#ifndef DAEMON_ENTRY_CRI_STREAM_SERVICE_SESSION_H
#define DAEMON_ENTRY_CRI_STREAM_SERVICE_SESSION_H
#include <iostream>
#include <string>
#include <memory>
#include <utility>
#include <map>
#include <unistd.h>
#include <semaphore.h>
#include "request_cache.h"

namespace {
const int MAX_ARRAY_LEN = 2;
}

struct SessionData {
    std::array<int, MAX_ARRAY_LEN> pipes;
    volatile bool close;
    std::mutex *sessionMutex;
    sem_t *syncCloseSem;
    std::list<unsigned char *> buffer;
    std::string containerID;
    std::string suffix;
    volatile bool completeStdin;

    unsigned char *FrontMessage();
    void PopMessage();
    int PushMessage(unsigned char *message);
    bool IsClosed();
    void CloseSession();
    void EraseAllMessage();
    bool IsStdinComplete();
    void SetStdinComplete(bool complete);
};

ssize_t WsWriteStdoutToClient(void *context, const void *data, size_t len);
ssize_t WsWriteStderrToClient(void *context, const void *data, size_t len);
ssize_t WsDoNotWriteStdoutToClient(void *context, const void *data, size_t len);
ssize_t WsDoNotWriteStderrToClient(void *context, const void *data, size_t len);
int closeWsConnect(void *context, char **err);

#endif // DAEMON_ENTRY_CRI_STREAM_SERVICE_SESSION_H
