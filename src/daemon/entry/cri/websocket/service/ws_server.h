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
 * Description: websockets server implementation
 * Author: wujing
 * Create: 2019-01-02
 ******************************************************************************/

#ifndef DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_WS_SERVER_H
#define DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_WS_SERVER_H
#include <vector>
#include <unordered_map>
#include <string>
#include <mutex>
#include <atomic>
#include <memory>
#include <list>
#include <thread>
#include <libwebsockets.h>
#include "route_callback_register.h"
#include "url.h"
#include "errors.h"
#include "read_write_lock.h"

namespace {
const int MAX_ECHO_PAYLOAD = 4096;
const int MAX_ARRAY_LEN = 2;
const int MAX_PROTOCOL_NUM = 2;
};

struct SessionData {
    std::array<int, MAX_ARRAY_LEN> pipes;
    volatile bool close;
    std::mutex *sessionMutex;
    sem_t *syncCloseSem;
    std::list<unsigned char *> buffer;
    std::string containerID;
    std::string suffix;

    unsigned char *FrontMessage();
    void PopMessage();
    int PushMessage(unsigned char *message);
    bool IsClosed();
    void CloseSession();
    void EraseAllMessage();
};

class WebsocketServer {
public:
    static WebsocketServer *GetInstance() noexcept;
    void Start(Errors &err);
    void Wait();
    void Shutdown();
    void RegisterCallback(const std::string &path, std::shared_ptr<StreamingServeInterface> callback);
    url::URLDatum GetWebsocketUrl();
    void SetLwsSendedFlag(int socketID, bool sended);

private:
    WebsocketServer();
    WebsocketServer(const WebsocketServer &) = delete;
    WebsocketServer &operator=(const WebsocketServer &) = delete;
    virtual ~WebsocketServer();
    int InitRWPipe(int read_fifo[]);
    std::vector<std::string> split(std::string str, char r);

    int CreateContext();
    inline void Receive(int socketID, void *in, size_t len);
    int  Wswrite(struct lws *wsi, const unsigned char *message);
    inline void DumpHandshakeInfo(struct lws *wsi) noexcept;
    int RegisterStreamTask(struct lws *wsi) noexcept;
    int GenerateSessionData(SessionData *session, const std::string containerID) noexcept;
    void ServiceWorkThread(int threadid);
    void CloseWsSession(int socketID);
    void CloseAllWsSession();
    int ResizeTerminal(int socketID, const char *jsonData, size_t len,
                       const std::string &containerID, const std::string &suffix);
    int ParseTerminalSize(const char *jsonData, size_t len, uint16_t &width, uint16_t &height);

private:
    // redirect libwebsockets logs to iSulad
    static void EmitLog(int level, const char *line);
    // libwebsockets Callback function
    static int Callback(struct lws *wsi, enum lws_callback_reasons reason,
                        void *user, void *in, size_t len);

private:
    static std::atomic<WebsocketServer *> m_instance;
    static RWMutex m_mutex;
    static struct lws_context *m_context;
    volatile int m_forceExit = 0;
    std::thread m_pthreadService;
    const struct lws_protocols m_protocols[MAX_PROTOCOL_NUM] = {
        { "channel.k8s.io", Callback, 0, MAX_ECHO_PAYLOAD, },
        { nullptr, nullptr, 0, 0 }
    };
    RouteCallbackRegister m_handler;
    static std::unordered_map<int, SessionData *> m_wsis;
    url::URLDatum m_url;
    int m_listenPort;
};

ssize_t WsWriteStdoutToClient(void *context, const void *data, size_t len);
ssize_t WsWriteStderrToClient(void *context, const void *data, size_t len);
int closeWsConnect(void *context, char **err);

#endif // DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_WS_SERVER_H

