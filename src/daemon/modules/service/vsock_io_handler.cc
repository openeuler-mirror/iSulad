/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-09-04
 * Description: provide vsock io functions
 ********************************************************************************/
#include "vsock_io_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string>
#include <vector>
#include <memory>
#include <sys/socket.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <isula_libutils/log.h>

#include "console.h"
#include "utils.h"
#include "sandbox_manager.h"
#include "sandbox.h"

const std::string VSOCK_PREFIX = "vsock://";
const int VSOCK_RETRY_INTERVAL = 1000; // 1000ms
const int VSOCK_RETRY_TIMEOUT = 10000; // 10000ms
const int MILLI_TO_MICRO = 1000;

bool is_vsock_path(const char *path)
{
    if (path == NULL) {
        return false;
    }
    std::string path_str = path;
    if (path_str.find(VSOCK_PREFIX) == 0) {
        return true;
    }

    return false;
}

bool parse_vsock_path(const char *vsock_path, uint32_t *cid, uint32_t *port)
{
    uint32_t vsock_cid, vsock_port;

    if (!is_vsock_path(vsock_path)) {
        ERROR("Invalid vsock path, %s", vsock_path);
        return false;
    }
    std::string vsock_path_str = vsock_path;
    std::string vsock_address = vsock_path_str.substr(VSOCK_PREFIX.size());
    if (vsock_address.empty()) {
        ERROR("Invalid vsock address, %s", vsock_path);
        return false;
    }

    // split vsock_address by ':'
    size_t col_pos = vsock_address.find(':');
    if (col_pos == std::string::npos) {
        ERROR("Failed to find ':' in vsock address, %s", vsock_path);
        return false;
    }

    std::string cid_str = vsock_address.substr(0, col_pos);
    if (util_safe_uint(cid_str.c_str(), &vsock_cid) != 0) {
        ERROR("Failed to parse cid, %s", cid_str.c_str());
        return false;
    }

    std::string port_str = vsock_address.substr(col_pos + 1);
    if (util_safe_uint(port_str.c_str(), &vsock_port) != 0) {
        ERROR("Failed to parse port, %s", port_str.c_str());
        return false;
    }

    if (cid != NULL) {
        *cid = vsock_cid;
    }

    if (port != NULL) {
        *port = vsock_port;
    }

    return true;
}

static int find_available_vsock_port_for_sandbox(const char *sandbox_id, uint32_t *port)
{
    if (sandbox_id == NULL || port == NULL) {
        ERROR("Invalid NULL sandbox id or port");
        return -1;
    }
    std::string sandbox_id_str = sandbox_id;
    std::shared_ptr<sandbox::Sandbox> sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(sandbox_id_str);
    if (sandbox == nullptr) {
        ERROR("Failed to find sandbox %s", sandbox_id);
        return -1;
    }

    if (sandbox->FindAvailableVsockPort(*port)) {
        return 0;
    }

    ERROR("Failed to find available vsock port for sandbox %s", sandbox_id);

    return -1;
}

static void release_vsock_port_for_sandbox(const char *sandbox_id, uint32_t port)
{
    if (sandbox_id == NULL) {
        return;
    }
    std::string sandbox_id_str = sandbox_id;
    std::shared_ptr<sandbox::Sandbox> sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(sandbox_id_str);
    if (sandbox == nullptr) {
        return;
    }

    sandbox->ReleaseVsockPort(port);
}

static int set_flags(int fd, int flags)
{
    int curflag;
    int ret;

    curflag = fcntl(fd, F_GETFL, 0);
    if (curflag < 0) {
        SYSERROR("Failed to get flags for vsock fd");
        return -1;
    }

    ret = fcntl(fd, F_SETFL, curflag | flags);
    if (ret != 0) {
        SYSERROR("Failed to set flags for vsock fd");
        return -1;
    }

    return 0;
}

static int vsock_connect(uint32_t cid, uint32_t port)
{
    int fd = -1;
    struct sockaddr_vm sa = { 0 };

    fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        SYSERROR("Failed to create vsock socket");
        return -1;
    }

    sa.svm_family = AF_VSOCK;
    sa.svm_cid = cid;
    sa.svm_port = port;

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) !=0) {
        SYSERROR("Failed to connect vsock socket");
        close(fd);
        return -1;
    }
    return fd;
}

/*
 * We setup connection as a client, so we need to wait the server to be ready.
 * In the following function, we need to keep retrying until connection is established.
 * The retrying time is 10s.
 */
int vsock_open(const char *vsock_path, int *fdout, int flags)
{
    int ret;
    int fd = -1;
    int retry = 0;
    uint32_t cid;
    uint32_t port;

    if (vsock_path == NULL || fdout == NULL) {
        ERROR("Invalid NULL vsock path or fdout");
        return -1;
    }

    if (!parse_vsock_path(vsock_path, &cid, &port)) {
        ERROR("Failed to parse vsock path, %s", vsock_path);
        return -1;
    }

    DEBUG("Open vsock, cid %u, port %u", cid, port);

    while (retry < VSOCK_RETRY_TIMEOUT) {
        fd = vsock_connect(cid, port);
        if (fd >= 0) {
            break;
        }
        DEBUG("Failed to connect vsock socket");
        retry += VSOCK_RETRY_INTERVAL;
        usleep(VSOCK_RETRY_INTERVAL * MILLI_TO_MICRO);
    }

    if (retry >= VSOCK_RETRY_TIMEOUT) {
        ERROR("Failed to connect vsock socket, timeout");
        return -1;
    }

    ret = set_flags(fd, flags);
    if (ret < 0) {
        ERROR("Failed to set flags for vsock fd");
        close(fd);
        return -1;
    }

    *fdout = fd;
    return 0;
}

static char *create_single_vsockpath(const char *sandbox_id, uint32_t cid)
{
    uint32_t vsock_port;

    if (find_available_vsock_port_for_sandbox(sandbox_id, &vsock_port) != 0) {
        ERROR("Failed to find available vsock port for sandbox %s", sandbox_id);
        return NULL;
    }
    std::string vsock_address = VSOCK_PREFIX + std::to_string(cid) + ":" + std::to_string(vsock_port);

    DEBUG("Create vsock path %s for sandbox %s", vsock_address.c_str(), sandbox_id);

    return util_strdup_s(vsock_address.c_str());
}

int create_daemon_vsockpaths(const char *sandbox_id, uint32_t cid, bool attach_stdin, bool attach_stdout,
                             bool attach_stderr, char *vsockpaths[])
{
    int ret = -1;

    if (sandbox_id == NULL || vsockpaths == NULL) {
        return -1;
    }
    if (attach_stdin) {
        vsockpaths[0] = create_single_vsockpath(sandbox_id, cid);
        if (vsockpaths[0] == NULL) {
            goto errout;
        }
    }

    if (attach_stdout) {
        vsockpaths[1] = create_single_vsockpath(sandbox_id, cid);
        if (vsockpaths[1] == NULL) {
            goto errout;
        }
    }

    if (attach_stderr) {
        vsockpaths[2] = create_single_vsockpath(sandbox_id, cid);
        if (vsockpaths[2] == NULL) {
            goto errout;
        }
    }

    ret = 0;
errout:
    if (ret != 0) {
        delete_daemon_vsockpaths(sandbox_id, (const char **)vsockpaths);
        free(vsockpaths[0]);
        free(vsockpaths[1]);
        free(vsockpaths[2]);
        vsockpaths[0] = NULL;
        vsockpaths[1] = NULL;
        vsockpaths[2] = NULL;
    }

    return ret;
}

static void delete_single_vsockpath(const char *sandbox_id, const char *vsockpath)
{
    uint32_t cid;
    uint32_t port;

    if (vsockpath == NULL) {
        return;
    }
    if (!parse_vsock_path(vsockpath, &cid, &port)) {
        ERROR("Failed to parse vsock path, %s", vsockpath);
        return;
    }
    release_vsock_port_for_sandbox(sandbox_id, port);
}

void delete_daemon_vsockpaths(const char *sandbox_id, const char *vsockpaths[])
{
    if (sandbox_id == NULL || vsockpaths == NULL) {
        return;
    }
    if (vsockpaths[0] != NULL) {
        delete_single_vsockpath(sandbox_id, vsockpaths[0]);
    }
    if (vsockpaths[1] != NULL) {
        delete_single_vsockpath(sandbox_id, vsockpaths[1]);
    }
    if (vsockpaths[2] != NULL) {
        delete_single_vsockpath(sandbox_id, vsockpaths[2]);
    }
}

enum IOFlowType{
    IO_SRC = 0,
    IO_DST,
    IO_FLOW_INVALID,
};

static ssize_t WriteToFIFO(void *context, const void *data, size_t len)
{
    ssize_t ret;
    int fd;

    fd = *(int *)context;
    ret = util_write_nointr_in_total(fd, static_cast<const char *>(data), len);
    if ((ret < 0) || (size_t)ret != len) {
        SYSERROR("Failed to write %d", fd);
        return -1;
    }
    return ret;
}

static ssize_t WriteToFd(void *context, const void *data, size_t len)
{
    ssize_t ret;

    ret = util_write_nointr(*(int *)context, static_cast<const char *>(data), len);
    if (ret < 0 || (size_t)ret != len) {
        SYSERROR("Failed to write");
        return -1;
    }
    return ret;
}

class IOEntry {
public:
    IOEntry()
    {
        m_initialized = false;
        m_fd = -1;
        m_flags = 0;
        m_flowType = IO_FLOW_INVALID;
    }

    virtual ~IOEntry() = default;

    virtual int Init() = 0;

    bool Initialized() const
    {
        return m_initialized;
    }

    virtual int GetFd()
    {
        if (!Initialized()) {
            return -1;
        }
        return m_fd;
    }

    virtual struct io_write_wrapper *GetWriter()
    {
        if (!Initialized()) {
            return NULL;
        }
        if (m_flowType == IO_SRC) {
            return NULL;
        }
        return &m_writer;
    }
    virtual std::string ToString() = 0;
protected:
    int m_flags;
    bool m_initialized;
    int m_fd;
    struct io_write_wrapper m_writer;
    IOFlowType m_flowType;
};



class IOFdEntry : public IOEntry {
public:
    IOFdEntry(int fd, IOFlowType flowType): IOEntry()
    {
        m_fd = fd;
        m_flowType = flowType;
    }

    ~IOFdEntry() override
    {
        if (m_initialized && m_fd >= 0) {
            close(m_fd);
            m_fd = -1;
        }
    }

    int Init() override
    {
        if (m_initialized) {
            return 0;
        }
        if (m_flowType == IO_DST) {
            m_writer.context = &m_fd;
            m_writer.write_func = WriteToFd;
        }
        m_initialized = true;
        return 0;
    }

    std::string ToString() override
    {
        return "file descriptor " + std::to_string(m_fd);
    }
};

class IOFifoEntry : public IOEntry {
public:
    IOFifoEntry(const char *path, int flags, IOFlowType flowType): IOEntry()
    {
        m_fifoPath = path;
        m_flags = flags;
        m_flowType = flowType;
    }

    ~IOFifoEntry() override
    {
        if (m_initialized && m_fd >= 0) {
            console_fifo_close(m_fd);
            m_fd = -1;
        }
    }

    int Init() override
    {
        if (m_initialized) {
            return 0;
        }

        if (m_flowType == IO_SRC) {
            if (console_fifo_open(m_fifoPath.c_str(), &m_fd, m_flags) != 0) {
                ERROR("Failed to open fifo, %s", m_fifoPath.c_str());
                return -1;
            }
        } else {
            if (console_fifo_open_withlock(m_fifoPath.c_str(), &m_fd, m_flags)) {
                ERROR("Failed to open console fifo.");
                return -1;
            }
            m_writer.context = &m_fd;
            m_writer.write_func = WriteToFIFO;
        }
        m_initialized = true;
        return 0;
    }

    std::string ToString() override
    {
        return "FIFO " + m_fifoPath;
    }
private:
    std::string m_fifoPath;
};

class IOVsockEntry : public IOEntry {
public:
    IOVsockEntry(const char *path, int flags, IOFlowType flowType): IOEntry()
    {
        m_vsockPath = path;
        m_flags = flags;
        m_flowType = flowType;
    }

    ~IOVsockEntry() override
    {
        if (m_initialized && m_fd >= 0) {
            close(m_fd);
            m_fd = -1;
        }
    }

    int Init() override
    {
        if (m_initialized) {
            return 0;
        }
        if (vsock_open(m_vsockPath.c_str(), &m_fd, m_flags) != 0) {
            ERROR("Failed to open vsock, %s", m_vsockPath.c_str());
            return -1;
        }
        if (m_flowType != IO_SRC) {
            m_writer.context = &m_fd;
            m_writer.write_func = WriteToFd;
        }
        m_initialized = true;
        return 0;
    }

    std::string ToString() override
    {
        return "vsock " + m_vsockPath;
    }
private:
    std::string m_vsockPath;
};

class IOFuncEntry : public IOEntry {
public:
    IOFuncEntry(struct io_write_wrapper *handler, IOFlowType flowType): IOEntry()
    {
        m_handler = handler;
        m_flowType = flowType;
    }

    ~IOFuncEntry() override
    {
        if (m_initialized && m_handler != NULL) {
            if (m_handler->close_func != NULL) {
                m_handler->close_func(m_handler->context, NULL);
            }
            m_handler = NULL;
        }
    }

    int Init() override
    {
        if (m_initialized) {
            return 0;
        }
        if (m_flowType == IO_SRC) {
            ERROR("IO func entry should not be used for stdin channel");
            return -1;
        }
        m_writer.context = m_handler->context;
        m_writer.write_func = m_handler->write_func;
        m_writer.close_func = m_handler->close_func;
        m_initialized = true;
        return 0;
    }

    std::string ToString() override
    {
        return "IO func entry";
    }
private:
    struct io_write_wrapper *m_handler;
};

/**
 * IOCopy defines the copy relationship between two IO.
 * It defines source IOEntry to read data from, destination IOEntry to write data to,
 * and the transfer channel type.
 */
class IOCopy {
public:
    IOCopy(std::unique_ptr<IOEntry> src, std::unique_ptr<IOEntry> dst, transfer_channel_type channel)
    {
        m_src = std::move(src);
        m_dst = std::move(dst);
        m_channel = channel;
    }
    ~IOCopy() = default;
    IOEntry &GetSrc()
    {
        return *m_src;
    }
    IOEntry &GetDst()
    {
        return *m_dst;
    }
    transfer_channel_type GetChannel()
    {
        return m_channel;
    }
private:
    std::unique_ptr<IOEntry> m_src;
    std::unique_ptr<IOEntry> m_dst;
    transfer_channel_type m_channel;
};

class IOCopyCollection {
public:
    IOCopyCollection() = default;
    ~IOCopyCollection() = default;
    void AddIOCopy(std::unique_ptr<IOEntry> src, std::unique_ptr<IOEntry> dst, transfer_channel_type channel)
    {
        m_copies.push_back(std::unique_ptr<IOCopy>(new IOCopy(std::move(src), std::move(dst), channel)));
    }

    int Init()
    {
        for (auto &copy : m_copies) {
            if (copy->GetSrc().Init() != 0) {
                ERROR("Failed to init src IO, %s", copy->GetSrc().ToString().c_str());
                return -1;
            }
            if (copy->GetDst().Init() != 0) {
                ERROR("Failed to init dst IO, %s", copy->GetDst().ToString().c_str());
                return -1;
            }
        }
        return 0;
    }

    size_t Size()
    {
        return m_copies.size();
    }

    int *GetSrcFds()
    {
        size_t len = m_copies.size();
        int *fds = new int[len];
        for (size_t i = 0; i < len; i++) {
            int fd = m_copies[i]->GetSrc().GetFd();
            if (fd < 0) {
                ERROR("Invalid fd: %s", m_copies[i]->GetSrc().ToString().c_str());
                delete[] fds;
                return NULL;
            }
            fds[i] = m_copies[i]->GetSrc().GetFd();
        }
        return fds;
    }

    struct io_write_wrapper *GetDstWriters()
    {
        size_t len = m_copies.size();
        struct io_write_wrapper *writers = new struct io_write_wrapper[len];
        for (size_t i = 0; i < len; i++) {
            struct io_write_wrapper *writer = m_copies[i]->GetDst().GetWriter();
            if (writer == NULL) {
                ERROR("Invalid writer: %s", m_copies[i]->GetDst().ToString().c_str());
                delete[] writers;
                return NULL;
            }
            writers[i] = *writer;
        }
        return writers;
    }

    transfer_channel_type *GetChannels()
    {
        size_t len = m_copies.size();
        transfer_channel_type *channels = new transfer_channel_type[len];
        for (size_t i = 0; i < len; i++) {
            channels[i] = m_copies[i]->GetChannel();
        }
        return channels;
    }

private:
    std::vector<std::unique_ptr<IOCopy>> m_copies;
};

/**
 * IO Copy module basically connect two IO together, and copy data from one to another.
 * For the IO between iSula/Websocket and iSulad, there are two forms:
 * 1. FIFO: iSula/Websocket will create three fifo files for communication with iSulad.
 * 2. FD and Callback: iSula/Websocket will use fd for input Channel with iSulad,
 *                     and use callback for output and error Channel.
 * The IO between iSulad and container could be different types, such as FIFO, VSOCK.
    --------------------------------------------------------------------------------------
    |  CHANNEL |   iSula/Websocket                  iSulad                      container|
    --------------------------------------------------------------------------------------
    |          |                fifoin | stdin_fd                  vsocks[0]             |
    |    IN    |       RDWR       -------->       RD      RDWR     -------->         RD  |
    --------------------------------------------------------------------------------------
    |          |             fifoout | stdout_handler              vsocks[1]             |
    |    OUT   |       RD         <--------       WR       RD      <--------         WR  |
    --------------------------------------------------------------------------------------
    |          |             fifoerr stderr_handler                vsocks[2]             |
    |    ERR   |       RD         <--------       WR       RD      <--------        WR   |
    --------------------------------------------------------------------------------------
*/
static void PrepareIOCopyCollection(const char *fifoin, const char *fifoout, const char *fifoerr,
                                    int stdin_fd, struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler,
                                    const char *vsocks[], IOCopyCollection &ioCollection)
{
    if (fifoin != NULL) {
        ioCollection.AddIOCopy(std::unique_ptr<IOEntry>(new IOFifoEntry(fifoin, O_RDONLY | O_NONBLOCK, IO_SRC)),
                               std::unique_ptr<IOEntry>(new IOVsockEntry(vsocks[0], O_WRONLY | O_NONBLOCK, IO_DST)), STDIN_CHANNEL);
    }
    if (fifoout != NULL) {
        ioCollection.AddIOCopy(std::unique_ptr<IOEntry>(new IOVsockEntry(vsocks[1], O_RDONLY | O_NONBLOCK, IO_SRC)),
                               std::unique_ptr<IOEntry>(new IOFifoEntry(fifoout, O_WRONLY | O_NONBLOCK, IO_DST)), STDOUT_CHANNEL);
    }
    if (fifoerr != NULL) {
        ioCollection.AddIOCopy(std::unique_ptr<IOEntry>(new IOVsockEntry(vsocks[2], O_RDONLY | O_NONBLOCK, IO_SRC)),
                               std::unique_ptr<IOEntry>(new IOFifoEntry(fifoerr, O_WRONLY | O_NONBLOCK, IO_DST)), STDERR_CHANNEL);
    }
    if (stdin_fd >= 0) {
        ioCollection.AddIOCopy(std::unique_ptr<IOEntry>(new IOFdEntry(stdin_fd, IO_SRC)),
                               std::unique_ptr<IOEntry>(new IOVsockEntry(vsocks[0], O_WRONLY | O_NONBLOCK, IO_DST)), STDIN_CHANNEL);
    }
    if (stdout_handler != NULL) {
        ioCollection.AddIOCopy(std::unique_ptr<IOEntry>(new IOVsockEntry(vsocks[1], O_RDONLY | O_NONBLOCK, IO_SRC)),
                               std::unique_ptr<IOEntry>(new IOFuncEntry(stdout_handler, IO_DST)), STDOUT_CHANNEL);
    }
    if (stderr_handler != NULL) {
        ioCollection.AddIOCopy(std::unique_ptr<IOEntry>(new IOVsockEntry(vsocks[2], O_RDONLY | O_NONBLOCK, IO_SRC)),
                               std::unique_ptr<IOEntry>(new IOFuncEntry(stderr_handler, IO_DST)), STDERR_CHANNEL);
    }
}

struct IOCopyThreadArgs {
    IOCopyCollection ioCollection;
    int sync_fd;
    bool detach;
    std::string exec_id;
    IOCopyThreadArgs() = default;
    ~IOCopyThreadArgs() = default;
};

static void *IOCopyThread(void *arg)
{
    if (arg == NULL) {
        return NULL;
    }

    std::unique_ptr<IOCopyThreadArgs> threadArg((struct IOCopyThreadArgs *)arg);

    if (threadArg->detach) {
        if (pthread_detach(pthread_self()) != 0) {
            CRIT("Set thread detach fail");
            return NULL;
        }
    }

    std::string tname = "IoCopy";
    if (!threadArg->exec_id.empty()) {
        // The name of the thread cannot be longer than 16 bytes,
        // so just use the first 4 bytes of exec_id as thread name.
        tname = "IoCopy-" + threadArg->exec_id.substr(0, 4);
    }

    (void)prctl(PR_SET_NAME, tname.c_str());

    if (threadArg->ioCollection.Init() != 0) {
        ERROR("Failed to init IO copy collection");
        return NULL;
    }

    size_t len = threadArg->ioCollection.Size();
    if (len == 0) {
        ERROR("No IO copy to be done");
        return NULL;
    }

    std::unique_ptr<int[]> srcfds(threadArg->ioCollection.GetSrcFds());
    if (srcfds == NULL) {
        ERROR("Failed to get src fds");
        return NULL;
    }

    std::unique_ptr<struct io_write_wrapper[]> writers(threadArg->ioCollection.GetDstWriters());
    if (writers == NULL) {
        ERROR("Failed to get dst writers");
        return NULL;
    }

    std::unique_ptr<transfer_channel_type[]> channels(threadArg->ioCollection.GetChannels());
    if (channels == NULL) {
        ERROR("Failed to get channels");
        return NULL;
    }

    (void)console_loop_io_copy(threadArg->sync_fd, srcfds.get(), writers.get(), channels.get(), len);
    return NULL;
}

int start_vsock_io_copy(const char *exec_id, int sync_fd, bool detach, const char *fifoin, const char *fifoout, const char *fifoerr,
                        int stdin_fd, struct io_write_wrapper *stdout_handler, struct io_write_wrapper *stderr_handler,
                        const char *vsocks[], pthread_t *tid)
{
    if (sync_fd < 0 || vsocks == NULL || tid == NULL) {
        ERROR("Invalid NULL arguments");
        return -1;
    }

    struct IOCopyThreadArgs *args = new IOCopyThreadArgs();
    args->sync_fd = sync_fd;
    args->detach = detach;
    if (exec_id != NULL) {
        args->exec_id = exec_id;
    }

    PrepareIOCopyCollection(fifoin, fifoout, fifoerr, stdin_fd, stdout_handler, stderr_handler, vsocks, args->ioCollection);

    int ret = pthread_create(tid, NULL, IOCopyThread, (void *)args);
    if (ret != 0) {
        CRIT("Thread creation failed");
        delete args;
    }

    return ret;
}
