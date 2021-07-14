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
 * Description: provide websocket server functions
 ******************************************************************************/

#include "ws_server.h"
#include <iostream>
#include <chrono>
#include <future>
#include <utility>
#include <sys/resource.h>
#include "cxxutils.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "request_cache.h"
#include "constants.h"
#include "isulad_config.h"

struct lws_context *WebsocketServer::m_context = nullptr;
std::atomic<WebsocketServer *> WebsocketServer::m_instance;
RWMutex WebsocketServer::m_mutex;
std::unordered_map<int, session_data> WebsocketServer::m_wsis;

WebsocketServer *WebsocketServer::GetInstance() noexcept
{
    static std::once_flag flag;

    std::call_once(flag, [] {
        m_instance = new WebsocketServer;
    });

    return m_instance;
}

WebsocketServer::WebsocketServer()
{
    m_force_exit = 0;
    m_wsis.clear();
}

WebsocketServer::~WebsocketServer()
{
    Shutdown();
}

url::URLDatum WebsocketServer::GetWebsocketUrl()
{
    return m_url;
}

std::unordered_map<int, session_data> &WebsocketServer::GetWsisData()
{
    return m_wsis;
}

void WebsocketServer::ReadLockAllWsSession()
{
    m_mutex.rdlock();
}

void WebsocketServer::UnlockAllWsSession()
{
    m_mutex.unlock();
}

void WebsocketServer::Shutdown()
{
    m_force_exit = 1;
    lws_cancel_service(m_context);
}

int WebsocketServer::InitRWPipe(int read_fifo[])
{
    if ((pipe2(read_fifo, O_NONBLOCK | O_CLOEXEC)) < 0) {
        ERROR("create read pipe(websocket server to lxc pipe) fail!");
        return -1;
    }
    return 0;
}

void WebsocketServer::EmitLog(int level, const char *line)
{
    switch (level) {
        case LLL_ERR:
            ERROR("ws:%s", line);
            break;
        default:
            DEBUG("ws:%s", line);
            break;
    }
}

int WebsocketServer::CreateContext()
{
    int limited;
    struct lws_context_creation_info info;
    struct rlimit oldLimit, newLimit;
    const size_t WS_ULIMIT_FDS = 1024;

    m_url.SetScheme("ws");
    m_url.SetHost("localhost:" + std::to_string(m_listenPort));

    (void)memset(&info, 0, sizeof(info));
    lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO | LLL_DEBUG, WebsocketServer::EmitLog);

    info.port = m_listenPort;
    info.iface = "127.0.0.1";
    info.protocols = m_protocols;
    info.ssl_cert_filepath = nullptr;
    info.ssl_private_key_filepath = nullptr;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_VALIDATE_UTF8 | LWS_SERVER_OPTION_DISABLE_IPV6;
    info.max_http_header_pool = MAX_HTTP_HEADER_POOL;
    info.extensions = nullptr;

    /* daemon set RLIMIT_NOFILE to a large value at main.c,
     * belowing lws_create_context limit the fds of websocket to RLIMIT_NOFILE,
     * and malloced memory according to it. To reduce memory, we recover it to 1024 before create m_context.
    */
    newLimit.rlim_cur = WS_ULIMIT_FDS;
    newLimit.rlim_max = WS_ULIMIT_FDS;
    limited = prlimit(0, RLIMIT_NOFILE, &newLimit, &oldLimit);
    if (limited != 0) {
        WARN("Can not set ulimit of RLIMIT_NOFILE: %s", strerror(errno));
    }
    m_context = lws_create_context(&info);
    if (m_context == nullptr) {
        ERROR("libwebsocket create m_context failed!");
        return -1;
    }
    if (limited == 0) {
        if (setrlimit(static_cast<int>(RLIMIT_NOFILE), &oldLimit) != 0) {
            WARN("Can not set ulimit of RLIMIT_NOFILE: %s", strerror(errno));
        }
    }

    return 0;
}

void WebsocketServer::RegisterCallback(const std::string &path,
                                       std::shared_ptr<StreamingServeInterface> callback)
{
    m_handler.RegisterCallback(path, callback);
}

void WebsocketServer::CloseAllWsSession()
{
    WriteGuard<RWMutex> lock(m_mutex);
    for (auto it = m_wsis.begin(); it != m_wsis.end(); ++it) {
        it->second.EraseAllMessage();
        close(it->second.pipes.at(0));
        close(it->second.pipes.at(1));
        delete it->second.buf_mutex;
        delete it->second.close;
    }
    m_wsis.clear();
}

void WebsocketServer::CloseWsSession(int socketID)
{
    auto it = m_wsis.find(socketID);
    if (it != m_wsis.end()) {
        *(it->second.close) = true;
        it->second.EraseAllMessage();
        // close the pipe write endpoint first, make sure io copy thread exit,
        // otherwise epoll will trigger EOF
        if (it->second.pipes.at(1) >= 0) {
            close(it->second.pipes.at(1));
            it->second.pipes.at(1) = -1;
        }
        (void)sem_wait(it->second.sync_close_sem);
        (void)sem_destroy(it->second.sync_close_sem);
        close(it->second.pipes.at(0));
        delete it->second.buf_mutex;
        it->second.buf_mutex = nullptr;
        delete it->second.close;
        it->second.close = nullptr;
        m_wsis.erase(it);
    }
}

int WebsocketServer::GenerateSessionData(session_data &session) noexcept
{
    int read_pipe_fd[PIPE_FD_NUM];
    if (InitRWPipe(read_pipe_fd) < 0) {
        ERROR("failed to init read/write pipe!");
        return -1;
    }

    std::mutex *buf_mutex = new std::mutex;
    sem_t *sync_close_sem = new sem_t;

    if (sem_init(sync_close_sem, 0, 0) != 0) {
        ERROR("Semaphore initialization failed");
        close(read_pipe_fd[1]);
        close(read_pipe_fd[0]);
        delete buf_mutex;
        delete sync_close_sem;
        return -1;
    }

    session.pipes = std::array<int, MAX_ARRAY_LEN> { read_pipe_fd[0], read_pipe_fd[1] };
    session.buf_mutex = buf_mutex;
    session.sync_close_sem = sync_close_sem;
    session.close = new bool(false);

    return 0;
}

int WebsocketServer::RegisterStreamTask(struct lws *wsi) noexcept
{
    char buf[MAX_BUF_LEN] { 0 };
    lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_GET_URI);
    if (strlen(buf) == 0) {
        ERROR("invalid url");
        return -1;
    }

    buf[sizeof(buf) - 1] = '\0';
    // format: "/cri/" + method + "/" + token + "/" + arg(container=cmd)
    auto vec = CXXUtils::Split(buf + 1, '/');
    RequestCache *cache = RequestCache::GetInstance();
    if (vec.size() < MIN_VEC_SIZE ||
        !m_handler.IsValidMethod(vec.at(1)) ||
        !cache->IsValidToken(vec.at(2))) {
        ERROR("invalid url(%s): incorrect format!", buf);
        return -1;
    }

    session_data session;
    if (GenerateSessionData(session) != 0) {
        ERROR("failed to fill generate session data");
        return -1;
    }

    int socketID = lws_get_socket_fd(wsi);
    m_wsis.insert(std::make_pair(socketID, std::move(session)));

    lwsContext lwsCtx = {
        .fd = socketID,
        .sync_close_sem = m_wsis[socketID].sync_close_sem,
        .close = m_wsis[socketID].close,
    };
    std::thread streamTh([ = ]() {
        StreamTask(&m_handler, lwsCtx, vec.at(1), vec.at(2), m_wsis[socketID].pipes.at(0)).Run();
    });
    streamTh.detach();

    return 0;
}

void WebsocketServer::DumpHandshakeInfo(struct lws *wsi) noexcept
{
    int n = 0;
    const unsigned char *c = nullptr;
    char buf[MAX_BUF_LEN] { 0 };

    do {
        c = lws_token_to_string((lws_token_indexes)n);
        if (c == nullptr) {
            n++;
            continue;
        }
        int len = lws_hdr_total_length(wsi, (lws_token_indexes)n);
        if (len == 0 || (static_cast<size_t>(len) > sizeof(buf) - 1)) {
            n++;
            continue;
        }

        lws_hdr_copy(wsi, buf, sizeof(buf), (lws_token_indexes)n);
        buf[sizeof(buf) - 1] = '\0';
        DEBUG("    %s = %s", (char *)c, buf);
        n++;
    } while (c != nullptr);
}

int WebsocketServer::Wswrite(struct lws *wsi, const unsigned char *message)
{
    auto it = m_wsis.find(lws_get_socket_fd(wsi));
    if (it != m_wsis.end()) {
        if (strlen((const char *)(&message[LWS_PRE + 1])) == 0) {
            return 0;
        }
        int n = lws_write(wsi, (unsigned char *)(&message[LWS_PRE]),
                          strlen((const char *)(&message[LWS_PRE + 1])) + 1, LWS_WRITE_TEXT);
        if (n < 0) {
            ERROR("ERROR %d writing to socket, hanging up", n);
            return -1;
        }
    }

    return 0;
}

void WebsocketServer::Receive(int socketID, void *in, size_t len)
{
    if (m_wsis.find(socketID) == m_wsis.end()) {
        ERROR("invailed websocket session!");
        return;
    }

    if (*static_cast<char *>(in) != WebsocketChannel::STDINCHANNEL) {
        ERROR("recevice date from client: %s", (char *)in + 1);
        return;
    }

    if (write(m_wsis[socketID].pipes.at(1), (void *)((char *)in + 1), len - 1) < 0) {
        ERROR("sub write over!");
        return;
    }
}

int WebsocketServer::Callback(struct lws *wsi, enum lws_callback_reasons reason,
                              void *user, void *in, size_t len)
{
    switch (reason) {
        case LWS_CALLBACK_HTTP:
            // disable an http request which has come from a client that is not
            // asking to upgrade the connection to a websocket one.
            return -1;
        case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: {
                WriteGuard<RWMutex> lock(m_mutex);
                WebsocketServer::GetInstance()->DumpHandshakeInfo(wsi);
                if (WebsocketServer::GetInstance()->RegisterStreamTask(wsi) != 0) {
                    // return non-zero here and kill the connection
                    return -1;
                }
                // Trigger polling in LWS_CALLBACK_SERVER_WRITEABLE
                lws_callback_on_writable(wsi);
            }
            break;
        case LWS_CALLBACK_ESTABLISHED: {
                DEBUG("new connection has been established");
            }
            break;
        case LWS_CALLBACK_SERVER_WRITEABLE: {
                ReadGuard<RWMutex> lock(m_mutex);
                int socketID = lws_get_socket_fd(wsi);
                auto it = m_wsis.find(socketID);
                if (it == m_wsis.end()) {
                    DEBUG("invalid session!");
                    // return nonzero from the user callback to close the connection
                    // and callback with the reason of LWS_CALLBACK_CLOSED
                    return -1;
                }

                while (!it->second.buffer.empty()) {
                    unsigned char *message = it->second.FrontMessage();
                    // send success! free it and erase for list
                    if (WebsocketServer::GetInstance()->Wswrite(wsi, (const unsigned char *)message) == 0) {
                        free(message);
                        it->second.PopMessage();
                    } else {
                        // Another case ret > 0, send fail! keep message and send it again!
                        // Or maybe the client was shut down abnormally
                        break;
                    }
                }

                if (*(it->second.close)) {
                    DEBUG("websocket session disconnected");
                    return -1;
                }
                lws_callback_on_writable(wsi);
            }
            break;
        case LWS_CALLBACK_RECEIVE: {
                ReadGuard<RWMutex> lock(m_mutex);
                WebsocketServer::GetInstance()->Receive(lws_get_socket_fd(wsi), (char *)in, len);
            }
            break;
        case LWS_CALLBACK_CLOSED: {
                WriteGuard<RWMutex> lock(m_mutex);
                DEBUG("connection has been closed");
                int socketID = lws_get_socket_fd(wsi);
                WebsocketServer::GetInstance()->CloseWsSession(socketID);
            }
            break;
        default:
            break;
    }
    return 0;
}

void WebsocketServer::ServiceWorkThread(int threadid)
{
    int n = 0;

    prctl(PR_SET_NAME, "WebsocketServer");

    while (n >= 0 && !m_force_exit) {
        n = lws_service(m_context, 0);
    }
}

void WebsocketServer::Start(Errors &err)
{
    m_listenPort = conf_get_websocket_server_listening_port();
    if (m_listenPort == 0) {
        err.SetError("Failed to get websocket server listening port from daemon config");
        return;
    }

    if (CreateContext() < 0) {
        err.SetError("Websocket server start failed! please check your network status"
                     "(eg: port " + std::to_string(m_listenPort) + " is occupied)");
        return;
    }
    m_pthread_service = std::thread(&WebsocketServer::ServiceWorkThread, this, 0);
}

void WebsocketServer::Wait()
{
    if (m_pthread_service.joinable()) {
        m_pthread_service.join();
    }

    CloseAllWsSession();

    lws_context_destroy(m_context);
}

namespace {

void DoWriteToClient(int fd, session_data *session,
                     const void *data, size_t len, WebsocketChannel channel)
{
    unsigned char *buf = (unsigned char *)util_common_calloc_s(LWS_PRE + MAX_BUFFER_SIZE + 1);
    if (buf == nullptr) {
        ERROR("Out of memory");
        return;
    }
    // Determine if it is standard output channel or error channel
    buf[LWS_PRE] = channel;

    (void)memcpy(&buf[LWS_PRE + 1], (void *)data, len);

    // push back to message list
    if (session->PushMessage(buf) != 0) {
        ERROR("Abnormal, websocket data cannot be processed, ignore the data"
              "coming in later to prevent daemon from getting stuck");
    }
}

ssize_t WsWriteToClient(void *context, const void *data, size_t len, WebsocketChannel channel)
{
    auto *lwsCtx = static_cast<lwsContext *>(context);
    int fd = lwsCtx->fd;
    if (lwsCtx->close == nullptr || *(lwsCtx->close)) {
        return 0;
    }
    WebsocketServer *server = WebsocketServer::GetInstance();
    auto itor = server->GetWsisData().find(fd);
    if (itor == server->GetWsisData().end()) {
        ERROR("invalid session!");
        return 0;
    }

    DoWriteToClient(fd, &itor->second, data, len, channel);

    return static_cast<ssize_t>(len);
}
};

ssize_t WsWriteStdoutToClient(void *context, const void *data, size_t len)
{
    return WsWriteToClient(context, data, len, STDOUTCHANNEL);
}

ssize_t WsWriteStderrToClient(void *context, const void *data, size_t len)
{
    return WsWriteToClient(context, data, len, STDERRCHANNEL);
}

int closeWsConnect(void *context, char **err)
{
    (void)err;
    auto *lwsCtx = static_cast<lwsContext *>(context);

    if (lwsCtx->sync_close_sem != nullptr) {
        (void)sem_post(lwsCtx->sync_close_sem);
    }

    WebsocketServer *server = WebsocketServer::GetInstance();
    server->ReadLockAllWsSession();
    auto it = server->GetWsisData().find(lwsCtx->fd);
    if (it == server->GetWsisData().end()) {
        server->UnlockAllWsSession();
        ERROR("websocket session not exist");
        delete lwsCtx;
        return -1;
    }
    // will close websocket session on LWS_CALLBACK_SERVER_WRITEABLE polling
    *(it->second.close) = true;
    server->UnlockAllWsSession();

    delete lwsCtx;
    return 0;
}

int closeWsStream(void *context, char **err)
{
    (void)err;
    auto *lwsCtx = static_cast<lwsContext *>(context);

    if (lwsCtx->sync_close_sem != nullptr) {
        (void)sem_post(lwsCtx->sync_close_sem);
    }

    return 0;
}
