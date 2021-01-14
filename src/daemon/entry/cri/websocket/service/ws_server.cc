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
std::unordered_set<struct lws *> WebsocketServer::m_activeSession;

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
        free(it->second.buf);
        close(it->second.pipes.at(0));
        close(it->second.pipes.at(1));
        it->second.sended = true;
        delete it->second.buf_mutex;
        delete it->second.sended_mutex;
    }
    m_wsis.clear();
}

void WebsocketServer::CloseWsSession(int socketID)
{
    auto it = m_wsis.find(socketID);
    if (it != m_wsis.end()) {
        free(it->second.buf);
        close(it->second.pipes.at(0));
        close(it->second.pipes.at(1));
        it->second.sended = true;
        delete it->second.buf_mutex;
        delete it->second.sended_mutex;
        m_wsis.erase(it);
    }
}

void WebsocketServer::RecordSession(struct lws *wsi)
{
    m_activeSession.insert(wsi);
}

void WebsocketServer::RemoveSession(struct lws *wsi)
{
    m_activeSession.erase(wsi);
}

bool WebsocketServer::IsValidSession(struct lws *wsi)
{
    return m_activeSession.count(wsi) != 0;
}

int WebsocketServer::DumpHandshakeInfo(struct lws *wsi) noexcept
{
    int read_pipe_fd[PIPE_FD_NUM];
    if (InitRWPipe(read_pipe_fd) < 0) {
        ERROR("failed to init read/write pipe!");
    }

    session_data session;
    session.pipes = std::array<int, MAX_ARRAY_LEN> { read_pipe_fd[0], read_pipe_fd[1] };

    int socketID = lws_get_socket_fd(wsi);
    m_wsis.insert(std::make_pair(socketID, std::move(session)));
    m_wsis[socketID].buf = (unsigned char *)util_common_calloc_s(LWS_PRE + MAX_MSG_BUFFER_SIZE + 1);
    if (m_wsis[socketID].buf == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    m_wsis[socketID].buf_mutex = new std::mutex;
    m_wsis[socketID].sended_mutex = new std::mutex;
    m_wsis[socketID].SetProcessingStatus(false);

    int len;
    char buf[MAX_BUF_LEN] { 0 };

    lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_GET_URI);
    if (strlen(buf) == 0) {
        ERROR("invalid url");
        CloseWsSession(socketID);
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
        CloseWsSession(socketID);
        return -1;
    }

    std::thread streamTh([ = ]() {
        StreamTask(&m_handler, wsi, vec.at(1), vec.at(2), m_wsis[socketID].pipes.at(0)).Run();
    });
    streamTh.detach();
    RecordSession(wsi);
    int n = 0;
    const unsigned char *c = nullptr;
    do {
        c = lws_token_to_string((lws_token_indexes)n);
        if (c == nullptr) {
            n++;
            continue;
        }
        len = lws_hdr_total_length(wsi, (lws_token_indexes)n);
        if (len == 0 || (static_cast<size_t>(len) > sizeof(buf) - 1)) {
            n++;
            continue;
        }
        lws_hdr_copy(wsi, buf, sizeof(buf), (lws_token_indexes)n);
        buf[sizeof(buf) - 1] = '\0';
        DEBUG("    %s = %s", (char *)c, buf);
        n++;
    } while (c != nullptr);

    return 0;
}

int WebsocketServer::Wswrite(struct lws *wsi, void *in, size_t len)
{
    auto it = m_wsis.find(lws_get_socket_fd(wsi));
    if (it != m_wsis.end()) {
        if (it->second.close) {
            DEBUG("websocket session disconnected");
            return -1;
        }
        it->second.buf_mutex->lock();
        auto &buf = it->second.buf;
        if (strlen((const char *)(&buf[LWS_PRE + 1])) == 0) {
            it->second.buf_mutex->unlock();
            return 0;
        }
        int n = lws_write(wsi, (unsigned char *)(&buf[LWS_PRE]),
                          strlen((const char *)(&buf[LWS_PRE + 1])) + 1, LWS_WRITE_TEXT);
        if (n < 0) {
            it->second.buf_mutex->unlock();
            ERROR("ERROR %d writing to socket, hanging up", n);
            return -1;
        }
        (void)memset(buf, 0, LWS_PRE + MAX_MSG_BUFFER_SIZE + 1);
        it->second.buf_mutex->unlock();
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

void WebsocketServer::SetLwsSendedFlag(int socketID, bool sended)
{
    if (m_wsis.count(socketID) == 0) {
        return;
    }
    m_wsis[socketID].sended_mutex->lock();
    m_wsis[socketID].sended = sended;
    m_wsis[socketID].sended_mutex->unlock();
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
                if (WebsocketServer::GetInstance()->DumpHandshakeInfo(wsi)) {
                    // return non-zero here and kill the connection
                    return -1;
                }
            }
            break;
        case LWS_CALLBACK_ESTABLISHED: {
                DEBUG("new connection has been established");
            }
            break;
        case LWS_CALLBACK_SERVER_WRITEABLE: {
                ReadGuard<RWMutex> lock(m_mutex);
                int socketID = lws_get_socket_fd(wsi);
                if (WebsocketServer::GetInstance()->Wswrite(wsi, in, len)) {
                    WebsocketServer::GetInstance()->SetLwsSendedFlag(socketID, true);
                    // return nonzero from the user callback to close the connection
                    // and callback with the reason of LWS_CALLBACK_CLOSED
                    return -1;
                }
                WebsocketServer::GetInstance()->SetLwsSendedFlag(socketID, true);
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
                WebsocketServer::GetInstance()->RemoveSession(wsi);
                WebsocketServer::GetInstance()->CloseWsSession(lws_get_socket_fd(wsi));
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
auto PrepareWsiSession(int socketID) -> session_data *
{
    WebsocketServer *server = WebsocketServer::GetInstance();
    server->ReadLockAllWsSession();

    auto itor = server->GetWsisData().find(socketID);
    if (itor == server->GetWsisData().end()) {
        ERROR("invalid session!");
        server->UnlockAllWsSession();
        return nullptr;
    }
    server->SetLwsSendedFlag(socketID, false);
    server->UnlockAllWsSession();

    return &itor->second;
}

void DoWriteToClient(struct lws *wsi, session_data *session,
                     const void *data, size_t len, WebsocketChannel channel)
{
    session->buf_mutex->lock();
    // Determine if it is standard output channel or error channel
    (void)memset(session->buf, 0, LWS_PRE + MAX_MSG_BUFFER_SIZE + 1);
    session->buf[LWS_PRE] = channel;

    (void)memcpy(&session->buf[LWS_PRE + 1], (void *)data, len);

    lws_callback_on_writable(wsi);

    session->buf_mutex->unlock();
}

void EnsureWrited(struct lws *wsi, session_data *session)
{
    const int RETRIES = 10;
    const int CHECK_PERIOD_SECOND = 1;
    const int TRIGGER_PERIOD_MS = 1;
    auto start = std::chrono::system_clock::now();
    int count = 0;

    while (!session->sended && count < RETRIES) {
        auto end = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double spend_time = static_cast<double>(duration.count()) * std::chrono::microseconds::period::num /
                            std::chrono::microseconds::period::den;
        if (spend_time > CHECK_PERIOD_SECOND) {
            lws_callback_on_writable(wsi);
            std::this_thread::sleep_for(std::chrono::milliseconds(TRIGGER_PERIOD_MS));
            start = std::chrono::system_clock::now();
            count++;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TRIGGER_PERIOD_MS));
    }
}

ssize_t WsWriteToClient(void *context, const void *data, size_t len, WebsocketChannel channel)
{
    struct lws *wsi = static_cast<struct lws *>(context);

    session_data *session = PrepareWsiSession(lws_get_socket_fd(wsi));
    if (session == nullptr) {
        return 0;
    }

    DoWriteToClient(wsi, session, data, len, channel);

    EnsureWrited(wsi, session);

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
    struct lws *wsi = static_cast<struct lws *>(context);

    WebsocketServer *server = WebsocketServer::GetInstance();
    server->ReadLockAllWsSession();
    auto it = server->GetWsisData().find(lws_get_socket_fd(wsi));
    if (it == server->GetWsisData().end()) {
        server->UnlockAllWsSession();
        ERROR("websocket session not exist");
        return -1;
    }

    it->second.close = true;
    // close websocket session
    if (server->IsValidSession(wsi)) {
        lws_callback_on_writable(wsi);
    }
    server->UnlockAllWsSession();

    return 0;
}
