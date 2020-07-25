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
#include <thread>
#include <libwebsockets.h>
#include "route_callback_register.h"
#include "url.h"
#include "errors.h"

#define MAX_ECHO_PAYLOAD 4096
#define MAX_ARRAY_LEN 2
#define MAX_BUF_LEN 256
#define MAX_PROTOCOL_NUM 2
#define MAX_HTTP_HEADER_POOL 8
#define MIN_VEC_SIZE 3
#define PIPE_FD_NUM 2
#define BUF_BASE_SIZE 1024
#define LWS_TIMEOUT 50

enum WebsocketChannel {
    STDINCHANNEL = 0,
    STDOUTCHANNEL,
    STDERRCHANNEL
};

struct session_data {
    std::array<int, MAX_ARRAY_LEN> pipes;
    unsigned char *buf;
    volatile bool sended { false };
    volatile bool close { false };
    volatile bool in_processing { false };
    std::mutex *buf_mutex;
    std::mutex *sended_mutex;

    void SetProcessingStatus(bool status)
    {
        in_processing = status;
    }
    bool GetProcessingStatus() const
    {
        return in_processing;
    }
};

class WebsocketServer {
public:
    static WebsocketServer *GetInstance() noexcept;
    static std::atomic<WebsocketServer *> m_instance;
    void Start(Errors &err);
    void Wait();
    void Shutdown();
    void RegisterCallback(const std::string &path, std::shared_ptr<StreamingServeInterface> callback);
    url::URLDatum GetWebsocketUrl();
    std::unordered_map<struct lws *, session_data> &GetWsisData();
    void SetLwsSendedFlag(struct lws *wsi, bool sended);
    void LockAllWsSession();
    void UnlockAllWsSession();

private:
    WebsocketServer();
    WebsocketServer(const WebsocketServer &) = delete;
    WebsocketServer &operator=(const WebsocketServer &) = delete;
    virtual ~WebsocketServer();
    int InitRWPipe(int read_fifo[]);
    std::vector<std::string> split(std::string str, char r);
    static void EmitLog(int level, const char *line);
    int CreateContext();
    inline void Receive(struct lws *client, void *in, size_t len);
    int  Wswrite(struct lws *wsi, void *in, size_t len);
    inline int DumpHandshakeInfo(struct lws *wsi) noexcept;
    static int Callback(struct lws *wsi, enum lws_callback_reasons reason,
                        void *user, void *in, size_t len);
    void ServiceWorkThread(int threadid);
    void CloseWsSession(struct lws *wsi);
    void CloseAllWsSession();

private:
    static std::mutex m_mutex;
    static struct lws_context *m_context;
    volatile int m_force_exit = 0;
    std::thread m_pthread_service;
    const struct lws_protocols m_protocols[MAX_PROTOCOL_NUM] = {
        {  "channel.k8s.io", Callback, 0, MAX_ECHO_PAYLOAD, },
        { NULL, NULL, 0, 0 }
    };
    RouteCallbackRegister m_handler;
    static std::unordered_map<struct lws *, session_data> m_wsis;
    url::URLDatum m_url;
    int m_listenPort;
};

ssize_t WsWriteStdoutToClient(void *context, const void *data, size_t len);
ssize_t WsWriteStderrToClient(void *context, const void *data, size_t len);
int closeWsConnect(void *context, char **err);

#endif // DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_WS_SERVER_H

