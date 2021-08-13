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
#include <unordered_set>
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
#include "isula_libutils/cri_terminal_size.h"

#define MAX_ECHO_PAYLOAD 4096
#define MAX_ARRAY_LEN 2
#define MAX_BUF_LEN 256
#define MAX_PROTOCOL_NUM 2
#define MAX_HTTP_HEADER_POOL 8
#define MIN_VEC_SIZE 3
#define PIPE_FD_NUM 2
#define BUF_BASE_SIZE 1024
#define LWS_TIMEOUT 50
// io copy maximum single transfer 4K, let max total buffer size: 1GB
#define FIFO_LIST_BUFFER_MAX_LEN 262144

enum WebsocketChannel {
    STDINCHANNEL = 0,
    STDOUTCHANNEL,
    STDERRCHANNEL,
    ERRORCHANNEL,
    RESIZECHANNEL
};

struct session_data {
    std::array<int, MAX_ARRAY_LEN> pipes;
    bool *close;
    std::mutex *buf_mutex;
    sem_t *sync_close_sem;
    std::list<unsigned char *> buffer;
    std::string container_id;
    std::string suffix;

    unsigned char *FrontMessage()
    {
        unsigned char *message = nullptr;

        buf_mutex->lock();
        message = buffer.front();
        buf_mutex->unlock();

        return message;
    }

    void PopMessage()
    {
        buf_mutex->lock();
        buffer.pop_front();
        buf_mutex->unlock();
    }

    int PushMessage(unsigned char *message)
    {
        // In extreme scenarios, websocket data cannot be processed,
        // ignore the data coming in later to prevent iSulad from getting stuck
        if (*close || buffer.size() >= FIFO_LIST_BUFFER_MAX_LEN) {
            free(message);
            return -1;
        }
        buf_mutex->lock();
        buffer.push_back(message);
        buf_mutex->unlock();

        return 0;
    }

    void EraseAllMessage()
    {
        buf_mutex->lock();
        for (auto iter = buffer.begin(); iter != buffer.end();) {
            free(*iter);
            *iter = NULL;
            iter = buffer.erase(iter);
        }
        buf_mutex->unlock();
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
    std::unordered_map<int, session_data> &GetWsisData();
    void SetLwsSendedFlag(int socketID, bool sended);
    void ReadLockAllWsSession();
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
    inline void Receive(int socketID, void *in, size_t len);
    int  Wswrite(struct lws *wsi, const unsigned char *message);
    inline void DumpHandshakeInfo(struct lws *wsi) noexcept;
    int RegisterStreamTask(struct lws *wsi) noexcept;
    int GenerateSessionData(session_data &session, const std::string containerID) noexcept;
    static int Callback(struct lws *wsi, enum lws_callback_reasons reason,
                        void *user, void *in, size_t len);
    void ServiceWorkThread(int threadid);
    void CloseWsSession(int socketID);
    void CloseAllWsSession();
    int ResizeTerminal(int socketID, const char *jsonData, const std::string &containerID, const std::string &suffix);
    int parseTerminalSize(const char *jsonData, uint16_t &width, uint16_t &height);

private:
    static RWMutex m_mutex;
    static struct lws_context *m_context;
    volatile int m_force_exit = 0;
    std::thread m_pthread_service;
    const struct lws_protocols m_protocols[MAX_PROTOCOL_NUM] = {
        { "channel.k8s.io", Callback, 0, MAX_ECHO_PAYLOAD, },
        { nullptr, nullptr, 0, 0 }
    };
    RouteCallbackRegister m_handler;
    static std::unordered_map<int, session_data> m_wsis;
    url::URLDatum m_url;
    int m_listenPort;
};

ssize_t WsWriteStdoutToClient(void *context, const void *data, size_t len);
ssize_t WsWriteStderrToClient(void *context, const void *data, size_t len);
int closeWsConnect(void *context, char **err);
int closeWsStream(void *context, char **err);

#endif // DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_WS_SERVER_H

