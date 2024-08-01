/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2024-03-15
 * Description: provide plugin class definition
 *********************************************************************************/

#ifndef DAEMON_NRI_PLUGIN_PLUGIN_H
#define DAEMON_NRI_PLUGIN_PLUGIN_H

#include <condition_variable>

#include <isula_libutils/nri_stop_container_request.h>
#include <isula_libutils/nri_stop_container_response.h>
#include <isula_libutils/nri_state_change_event.h>

#include "errors.h"
#include "read_write_lock.h"
#include "nri_result.h"

const std::string NRIRruntime = "v2";
const std::string NRIVersion = "2.0.0-beta.2+unknown";

class NRIPlugin {
public:
    // init client conn
    NRIPlugin(std::string &idx, std::string &name, std::string &config);
    NRIPlugin(int fd, std::string &name);
    // todo: close client conn ?? or single close func?
    virtual ~NRIPlugin() = default;
    // wait for plugin to register, then configure it.
    auto Start(int64_t registry_timeout, int64_t request_timeout) -> bool;
    // close a plugin shutting down its multiplexed ttrpc connections.
    auto Close(void) -> bool;
    // stop a plugin (if it was launched by us)
    auto Stop(void) -> bool;

    // Name returns a string indentication for the plugin.
    auto GetName(void) -> const std::string &;
    auto GetIndex(void) -> const std::string &;
    auto GetPeerSockFd(void) -> uint32_t;
    auto GetQualifiedName(void) -> std::string;

    void SetReady(void);
    void SetPid(int pid);

    auto IsClose(void) -> bool;

    auto CreateSocketPair(void) -> bool;

    auto Configure(Errors &error) -> bool;
    // Only called in external plugin scenario
    auto Synchronize(std::vector<std::unique_ptr<nri_pod_sandbox>> pods,
                     std::vector<std::unique_ptr<nri_container>> &containers, nri_container_update ***update, size_t update_len,
                     Errors &error) -> bool;
    auto CreateContainer(nri_create_container_request *req, nri_create_container_response **resp, Errors &error) -> bool;
    auto UpdateContainer(nri_update_container_request *req, nri_update_container_response **resp, Errors &error) -> bool;
    auto StopContainer(nri_stop_container_request *req, nri_stop_container_response **resp, Errors &error) -> bool;
    auto StateChange(nri_state_change_event *evt, Errors &error) -> bool;

private:
    auto Connect(int64_t timeout) -> bool;

    auto WaitForReady(int64_t timeout) -> bool;
    auto IsSetEvent(EventMask e) -> bool;

private:
    RWMutex m_mutex;
    bool m_external;
    std::string m_idx;
    std::string m_name;
    std::string m_config;
    int m_pid;
    std::string m_cmd;
    std::vector<uint32_t> m_sockFds;
    std::string m_localFileName;
    std::string m_peerFileName;
    // TODO:zhontao monitor?
    bool m_closed;
    std::mutex m_readyMutex;
    bool m_ready;
    std::condition_variable m_condition;
    EventMask m_events;
};


#endif // DAEMON_NRI_PLUGIN_PLUGIN_H