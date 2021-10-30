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
#include "callback.h"
#include "cri_helpers.h"

struct lws_context *WebsocketServer::m_context = nullptr;
std::atomic<WebsocketServer *> WebsocketServer::m_instance;
RWMutex WebsocketServer::m_mutex;
std::unordered_map<int, session_data *> WebsocketServer::m_wsis;

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
    m_wsis.reserve(SESSION_CAPABILITY);
}

WebsocketServer::~WebsocketServer()
{
    Shutdown();
}

url::URLDatum WebsocketServer::GetWebsocketUrl()
{
    return m_url;
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
        it->second->EraseAllMessage();
        close(it->second->pipes.at(0));
        close(it->second->pipes.at(1));
        (void)sem_destroy(it->second->sync_close_sem);
        delete it->second->session_mutex;
        delete it->second;
    }
    m_wsis.clear();
}

void WebsocketServer::CloseWsSession(int socketID)
{
    m_mutex.wrlock();
    auto it = m_wsis.find(socketID);
    if (it == m_wsis.end()) {
        m_mutex.unlock();
        return;
    }

    auto session = it->second;
    it->second = nullptr;
    m_wsis.erase(it);
    m_mutex.unlock();

    std::thread([session]() {
        prctl(PR_SET_NAME, "WSSessionGC");
        session->CloseSession();
        session->EraseAllMessage();
        // close the pipe write endpoint first, make sure io copy thread exit,
        // otherwise epoll will trigger EOF
        if (session->pipes.at(1) >= 0) {
            close(session->pipes.at(1));
            session->pipes.at(1) = -1;
        }
        (void)sem_wait(session->sync_close_sem);
        (void)sem_destroy(session->sync_close_sem);
        close(session->pipes.at(0));
        delete session->session_mutex;
        session->session_mutex = nullptr;
        delete session;
    }).detach();
}

int WebsocketServer::GenerateSessionData(session_data *session, const std::string containerID) noexcept
{
    char *suffix = nullptr;
    int read_pipe_fd[PIPE_FD_NUM] = {-1, -1};
    std::mutex *buf_mutex = nullptr;
    sem_t *sync_close_sem = nullptr;

    suffix = CRIHelpers::GenerateExecSuffix();
    if (suffix == nullptr) {
        ERROR("Failed to generate suffix(id)");
        return -1;
    }

    if (InitRWPipe(read_pipe_fd) < 0) {
        ERROR("failed to init read/write pipe!");
        goto out;
    }

    buf_mutex = new std::mutex;
    sync_close_sem = new sem_t;

    if (sem_init(sync_close_sem, 0, 0) != 0) {
        ERROR("Semaphore initialization failed");
        goto out;
    }

    session->pipes = std::array<int, MAX_ARRAY_LEN> { read_pipe_fd[0], read_pipe_fd[1] };
    session->session_mutex = buf_mutex;
    session->sync_close_sem = sync_close_sem;
    session->close = false;
    session->container_id = containerID;
    session->suffix = std::string(suffix);

    free(suffix);

    return 0;

out:
    if (suffix != nullptr) {
        free(suffix);
    }
    if (read_pipe_fd[1] >= 0) {
        close(read_pipe_fd[1]);
    }
    if (read_pipe_fd[0] >= 0) {
        close(read_pipe_fd[0]);
    }
    if (buf_mutex != nullptr) {
        delete buf_mutex;
    }
    if (sync_close_sem) {
        delete sync_close_sem;
    }

    return -1;
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

    int socketID = lws_get_socket_fd(wsi);
    if (m_wsis.count(socketID) != 0) {
        ERROR("socketID already exist!");
        return -1;
    }

    if (m_wsis.size() > MAX_SESSION_NUM) {
        ERROR("too many connection sessions");
        return -1;
    }

    std::string containerID = cache->GetContainerIDByToken(vec.at(1), vec.at(2));
    if (containerID.empty()) {
        ERROR("Failed to get container id from %s request", vec.at(1).c_str());
        return -1;
    }

    session_data *session = new (std::nothrow) session_data;
    if (session == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    if (GenerateSessionData(session, containerID) != 0) {
        ERROR("failed to fill generate session data");
        return -1;
    }

    std::string suffixID = session->suffix;
    auto insertRet = m_wsis.insert(std::make_pair(socketID, session));
    if (!insertRet.second) {
        ERROR("failed to insert session data to map");
        return -1;
    }

    std::thread streamTh([ = ]() {
        StreamTask(&m_handler, session, vec.at(1), vec.at(2)).Run();
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

int WebsocketServer::parseTerminalSize(const char *jsonData, size_t len, uint16_t &width, uint16_t &height)
{
    int ret = 0;
    parser_error err = nullptr;
    cri_terminal_size *terminalSize = nullptr;

    if (jsonData == nullptr || len == 0) {
        return -1;
    }

    // No terminator is included in json data, and len contains a character occupied by channal
    std::string jsonDataStr { jsonData, len - 1 };

    // parse json data. eg: {"Width":xx,"Height":xx}
    terminalSize = cri_terminal_size_parse_data(jsonDataStr.c_str(), nullptr, &err);
    if (terminalSize == nullptr) {
        ERROR("Failed to parse json: %s", err);
        ret = -1;
    } else {
        width = terminalSize->width;
        height = terminalSize->height;
    }

    free(err);
    free_cri_terminal_size(terminalSize);

    return ret;
}

int WebsocketServer::ResizeTerminal(
    int socketID, const char *jsonData, size_t len,
    const std::string &containerID,
    const std::string &suffix)
{
    int ret;
    service_executor_t *cb = nullptr;
    struct isulad_container_resize_request *req = nullptr;
    struct isulad_container_resize_response *res = nullptr;
    uint16_t width = 0;
    uint16_t height = 0;

    cb = get_service_executor();
    if (cb == nullptr || cb->container.resize == nullptr) {
        return -1;
    }

    if (parseTerminalSize(jsonData, len, width, height) != 0) {
        return -1;
    }

    req = (struct isulad_container_resize_request *)util_common_calloc_s(
              sizeof(struct isulad_container_resize_request));
    if (req == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    req->id = util_strdup_s(containerID.c_str());
    req->suffix = util_strdup_s(suffix.c_str());
    req->height = height;
    req->width = width;

    ret = cb->container.resize(req, &res);

    isulad_container_resize_request_free(req);
    isulad_container_resize_response_free(res);


    return ret;
}

void WebsocketServer::Receive(int socketID, void *in, size_t len)
{
    auto it = m_wsis.find(socketID);
    if (it == m_wsis.end()) {
        ERROR("invailed websocket session!");
        return;
    }

    if (*static_cast<char *>(in) == WebsocketChannel::RESIZECHANNEL) {
        std::string containerID = it->second->container_id;
        std::string suffix = it->second->suffix;
        if (ResizeTerminal(socketID, (char *)in + 1, len, containerID, suffix) != 0) {
            ERROR("Failed to resize terminal tty");
            return;
        }
    } else if (*static_cast<char *>(in) == WebsocketChannel::STDINCHANNEL) {
        if (write(m_wsis[socketID]->pipes.at(1), (void *)((char *)in + 1), len - 1) < 0) {
            ERROR("sub write over!");
            return;
        }
    } else {
        ERROR("invalid data: %s", (char *)in);
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

                auto isSessionClosed = it->second->IsClosed();
                while (!it->second->buffer.empty()) {
                    unsigned char *message = it->second->FrontMessage();
                    // send success! free it and erase for list
                    if (WebsocketServer::GetInstance()->Wswrite(wsi, (const unsigned char *)message) == 0) {
                        free(message);
                        it->second->PopMessage();
                    } else {
                        // Another case ret > 0, send fail! keep message and send it again!
                        // Or maybe the client was shut down abnormally
                        break;
                    }
                }

                // avoid: push message to buffer and set closed true
                if (isSessionClosed) {
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

void DoWriteToClient(session_data *session,
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
    auto *lwsCtx = static_cast<session_data *>(context);

    // CloseWsSession wait IOCopy finished, and then delete session in m_wsis
    // So don't need rdlock m_wsis here
    if (lwsCtx->IsClosed()) {
        return 0;
    }

    DoWriteToClient(lwsCtx, data, len, channel);
    return static_cast<ssize_t>(len);
}
};

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

int closeWsConnect(void *context, char **err)
{
    (void)err;

    if (context == nullptr) {
        ERROR("websocket session context empty");
        return -1;
    }

    auto *lwsCtx = static_cast<session_data *>(context);

    lwsCtx->CloseSession();

    if (lwsCtx->sync_close_sem != nullptr) {
        (void)sem_post(lwsCtx->sync_close_sem);
    }

    return 0;
}
