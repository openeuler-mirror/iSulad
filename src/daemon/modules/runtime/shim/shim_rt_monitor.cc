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
 * Create: 2023-08-17
 * Description: shim v2 runtime monitor definition
 ******************************************************************************/

#include "shim_rt_monitor.h"

#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <memory>
#include <map>
#include <mutex>
#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/log.h>

#include "utils.h"
#include "error.h"

extern "C" {
    #include <shim_v2.h>
}

struct shim_monitor_data {
    std::string id;
    std::string exit_fifo;

    shim_monitor_data(const std::string &id, const std::string &exit_fifo)
        : id(id), exit_fifo(exit_fifo) {}
    ~shim_monitor_data() = default;
};

class ShimV2onitor {
public:
    ShimV2onitor() = default;
    ~ShimV2onitor() = default;


    bool Monitor(const std::string &id, std::string &exit_fifo)
    {
        if (IsInMonitorList(id)) {
            return true;
        }

        if (!util_file_exists(exit_fifo.c_str())) {
            ERROR("Exit FIFO %s does not exist", exit_fifo.c_str());
            return false;
        }

        std::unique_ptr<shim_monitor_data> data =
            std::unique_ptr<shim_monitor_data>(new shim_monitor_data(id, exit_fifo));

        AddToMonitorList(id);

        std::thread t(&ShimV2onitor::MonitorThread, this, std::move(data));

        t.detach();

        return true;
    }

    bool IsMonitored(const std::string &id)
    {
        return IsInMonitorList(id);
    }

private:
    void AddToMonitorList(const std::string &id)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_monitorList[id] = true;
    }

    void RemoveFromMonitorList(const std::string &id)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_monitorList.find(id) == m_monitorList.end()) {
            return;
        }
        m_monitorList.erase(id);
    }

    bool IsInMonitorList(const std::string &id)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_monitorList.find(id) == m_monitorList.end()) {
            return false;
        }
        return true;
    }

    int WriteToExitFifo(const std::string &exit_fifo, int exit_status)
    {
        int ret = 0;
        int exit_fifo_fd;

        if (!util_file_exists(exit_fifo.c_str())) {
            ERROR("Exit FIFO %s does not exist", exit_fifo.c_str());
            return -1;
        }

        exit_fifo_fd = util_open(exit_fifo.c_str(), O_WRONLY | O_NONBLOCK, 0);
        if (exit_fifo_fd < 0) {
            SYSERROR("Failed to open exit FIFO %s.", exit_fifo.c_str());
            return -1;
        }

        if (util_write_nointr(exit_fifo_fd, &exit_status, sizeof(int)) <= 0) {
            ERROR("Failed to write exit fifo fd %s", exit_fifo.c_str());
            ret = -1;
        }

        close(exit_fifo_fd);
        return ret;
    }

    void MonitorThread(std::unique_ptr<shim_monitor_data> data)
    {
        int exit_status = 0;
        pthread_setname_np(pthread_self(), "shimMonitor");
        if (shim_v2_wait(data->id.c_str(), NULL, &exit_status) != 0) {
            ERROR("%s: failed to wait for container", data->id.c_str());
        }

        if (WriteToExitFifo(data->exit_fifo, exit_status) != 0) {
            ERROR("Failed to write to exit fifo %s", data->exit_fifo.c_str());
        } else {
            DEBUG("Write to exit fifo successfully, %s", data->exit_fifo.c_str());
        }

        RemoveFromMonitorList(data->id);
    }

    std::map<std::string, bool> m_monitorList;
    std::mutex m_mutex;
};

static ShimV2onitor g_ShimV2Monitor;

int shim_rt_monitor(const char *id, const char *exit_fifo)
{
    if (id == nullptr || exit_fifo == nullptr) {
        ERROR("Invalid input arguments");
        return -1;
    }

    std::string id_str = id;
    std::string exit_fifo_str = exit_fifo;

    if (g_ShimV2Monitor.Monitor(id_str, exit_fifo_str)) {
        return 0;
    }

    return -1;
}
