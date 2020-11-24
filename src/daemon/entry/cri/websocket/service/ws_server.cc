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
std::mutex WebsocketServer::m_mutex;
std::unordered_map<struct lws *, session_data> WebsocketServer::m_wsis;
WebsocketServer *WebsocketServer::GetInstance() noexcept
{
    WebsocketServer *server = m_instance.load(std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_acquire);
    if (server == nullptr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        server = m_instance.load(std::memory_order_relaxed);
        if (server == nullptr) {
            server = new WebsocketServer;
            std::atomic_thread_fence(std::memory_order_release);
            m_instance.store(server, std::memory_order_relaxed);
        }
    }
    return server;
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

std::unordered_map<struct lws *, session_data> &WebsocketServer::GetWsisData()
{
    return m_wsis;
}

void WebsocketServer::LockAllWsSession()
{
    m_mutex.lock();
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
        if (setrlimit((int)RLIMIT_NOFILE, &oldLimit) != 0) {
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
    std::lock_guard<std::mutex> lock(m_mutex);
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

void WebsocketServer::CloseWsSession(struct lws *wsi)
{
    const int WAIT_PERIOD_MS = 50;

    auto it = m_wsis.find(wsi);
    if (it != m_wsis.end()) {
        while (it->second.GetProcessingStatus()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_PERIOD_MS));
        }
        free(it->second.buf);
        close(it->second.pipes.at(0));
        close(it->second.pipes.at(1));
        it->second.sended = true;
        delete it->second.buf_mutex;
        delete it->second.sended_mutex;
        m_wsis.erase(it);
    }
}

int WebsocketServer::DumpHandshakeInfo(struct lws *wsi) noexcept
{
    int read_pipe_fd[PIPE_FD_NUM];
    if (InitRWPipe(read_pipe_fd) < 0) {
        ERROR("failed to init read/write pipe!");
    }

    session_data session;
    session.pipes = std::array<int, MAX_ARRAY_LEN> { read_pipe_fd[0], read_pipe_fd[1] };
    m_wsis.insert(std::make_pair(wsi, session));
    m_wsis[wsi].buf = (unsigned char *)util_common_calloc_s(LWS_PRE + MAX_MSG_BUFFER_SIZE + 1);
    if (m_wsis[wsi].buf == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    m_wsis[wsi].buf_mutex = new std::mutex;
    m_wsis[wsi].sended_mutex = new std::mutex;
    m_wsis[wsi].SetProcessingStatus(false);

    int len;
    char buf[MAX_BUF_LEN] { 0 };

    lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_GET_URI);
    if (strlen(buf) == 0) {
        ERROR("invalid url");
        CloseWsSession(wsi);
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
        CloseWsSession(wsi);
        return -1;
    }

    std::thread streamTh([ = ]() {
        StreamTask(&m_handler, wsi, vec.at(1), vec.at(2), m_wsis[wsi].pipes.at(0)).Run();
    });
    streamTh.detach();
    int n = 0;
    const unsigned char *c = nullptr;
    do {
        c = lws_token_to_string((lws_token_indexes)n);
        if (c == nullptr) {
            n++;
            continue;
        }
        len = lws_hdr_total_length(wsi, (lws_token_indexes)n);
        if (len == 0 || ((size_t)len > sizeof(buf) - 1)) {
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
    auto it = m_wsis.find(wsi);
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

void WebsocketServer::Receive(struct lws *wsi, void *in, size_t len)
{
    if (m_wsis.find(wsi) == m_wsis.end()) {
        ERROR("invailed websocket session!");
        return;
    }

    if (*static_cast<char *>(in) != WebsocketChannel::STDINCHANNEL) {
        ERROR("recevice date from client: %s", (char *)in + 1);
        return;
    }

    if (write(m_wsis[wsi].pipes.at(1), (void *)((char *)in + 1), len - 1) < 0) {
        ERROR("sub write over!");
        return;
    }
}

void WebsocketServer::SetLwsSendedFlag(struct lws *wsi, bool sended)
{
    auto it = m_wsis.find(wsi);
    if (it != m_wsis.end()) {
        it->second.sended_mutex->lock();
        it->second.sended = sended;
        it->second.sended_mutex->unlock();
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
                std::lock_guard<std::mutex> lock(m_mutex);
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
                std::lock_guard<std::mutex> lock(m_mutex);
                if (WebsocketServer::GetInstance()->Wswrite(wsi, in, len)) {
                    WebsocketServer::GetInstance()->SetLwsSendedFlag(wsi, true);
                    return -1;
                }
                WebsocketServer::GetInstance()->SetLwsSendedFlag(wsi, true);
            }
            break;
        case LWS_CALLBACK_RECEIVE: {
                std::lock_guard<std::mutex> lock(m_mutex);
                WebsocketServer::GetInstance()->Receive(wsi, (char *)in, len);
            }
            break;
        case LWS_CALLBACK_CLOSED: {
                std::lock_guard<std::mutex> lock(m_mutex);
                WebsocketServer::GetInstance()->CloseWsSession(wsi);
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
        n = lws_service(m_context, 50);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
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


ssize_t WsWriteStdoutToClient(void *context, const void *data, size_t len)
{
    const int RETRIES = 10;
    const int CHECK_PERIOD_SECOND = 1;
    const int TRIGGER_PERIOD_MS = 100;

    struct lws *wsi = static_cast<struct lws *>(context);
    WebsocketServer *server = WebsocketServer::GetInstance();
    server->LockAllWsSession();
    auto it = server->GetWsisData().find(wsi);
    if (it == server->GetWsisData().end()) {
        ERROR("invalid session!");
        server->UnlockAllWsSession();
        return 0;
    }
    it->second.SetProcessingStatus(true);
    server->UnlockAllWsSession();
    server->SetLwsSendedFlag(wsi, false);
    it->second.buf_mutex->lock();
    auto &buf = it->second.buf;
    // Determine if it is standard output channel or error channel?
    (void)memset(buf, 0, LWS_PRE + MAX_MSG_BUFFER_SIZE + 1);
    buf[LWS_PRE] = STDOUTCHANNEL;

    (void)memcpy(&buf[LWS_PRE + 1], (void *)data, len);
    auto start = std::chrono::system_clock::now();
    lws_callback_on_writable(wsi);
    it->second.buf_mutex->unlock();
    int count = 0;
    while (!it->second.sended && count < RETRIES) {
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
    it->second.SetProcessingStatus(false);
    return (ssize_t)len;
}

ssize_t WsWriteStderrToClient(void *context, const void *data, size_t len)
{
    const int RETRIES = 10;
    const int CHECK_PERIOD_SECOND = 1;
    const int TRIGGER_PERIOD_MS = 100;

    struct lws *wsi = static_cast<struct lws *>(context);
    WebsocketServer *server = WebsocketServer::GetInstance();
    server->LockAllWsSession();
    auto it = server->GetWsisData().find(wsi);
    if (it == server->GetWsisData().end()) {
        ERROR("invalid session!");
        server->UnlockAllWsSession();
        return 0;
    }
    it->second.SetProcessingStatus(true);
    server->UnlockAllWsSession();
    server->SetLwsSendedFlag(wsi, false);
    it->second.buf_mutex->lock();
    auto &buf = it->second.buf;
    // Determine if it is standard output channel or error channel?
    (void)memset(buf, 0, LWS_PRE + MAX_MSG_BUFFER_SIZE + 1);
    buf[LWS_PRE] = STDERRCHANNEL;

    (void)memcpy(&buf[LWS_PRE + 1], (void *)data, len);
    auto start = std::chrono::system_clock::now();
    lws_callback_on_writable(wsi);
    it->second.buf_mutex->unlock();
    int count = 0;
    while (!it->second.sended && count < RETRIES) {
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
    it->second.SetProcessingStatus(false);
    return (ssize_t)len;
}

int closeWsConnect(void *context, char **err)
{
    (void)err;
    struct lws *wsi = static_cast<struct lws *>(context);

    WebsocketServer *server = WebsocketServer::GetInstance();
    auto it = server->GetWsisData().find(wsi);
    if (it == server->GetWsisData().end()) {
        ERROR("websocket session not exist");
        return -1;
    }
    it->second.close = true;
    // close websocket session
    lws_callback_on_writable(wsi);
    return 0;
}


