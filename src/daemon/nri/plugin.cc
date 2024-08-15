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

#include "plugin.h"

#include <string>
#include <mutex>
#include <google/protobuf/map.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <fcntl.h>

#include <nri_plugin.h>

#include <isula_libutils/log.h>
#include <isula_libutils/nri_create_container_request.h>
#include <isula_libutils/nri_create_container_response.h>
#include <isula_libutils/nri_configure_request.h>
#include <isula_libutils/nri_configure_response.h>
#include <isula_libutils/nri_state_change_event.h>
#include <isula_libutils/nri_stop_container_request.h>
#include <isula_libutils/nri_stop_container_response.h>
#include <isula_libutils/nri_synchronize_request.h>
#include <isula_libutils/nri_synchronize_response.h>
#include <isula_libutils/nri_update_container_request.h>
#include <isula_libutils/nri_update_container_response.h>

#include "utils.h"
#include "cstruct_wrapper.h"

// same as containerd
std::string DefaultNRIVersion = "2.0.0-beta.2+unknown";
// same as containerd
std::string DefaultNRIRuntimeName = "v2";
// defualt timeout for wait: 2s
const int64_t DefaultWaitTimeout = 2000;
const uint64_t SECOND_TO_NANOS = 1000000000;

// init client conn
NRIPlugin::NRIPlugin(std::string &idx, std::string &name, std::string &config)
{
    m_idx = idx;
    m_name = name;
    m_config = config;
    m_closed = false;
    m_external = false;
    m_pid = -1;
}

NRIPlugin::NRIPlugin(int fd, std::string &name)
{
    m_sockFds.push_back(fd);
    m_name = name;
    m_closed = false;
    m_external = true;
    m_pid = -1;
}

// wait for plugin to register, then configure it.
auto NRIPlugin::Start(int64_t registry_timeout, int64_t request_timeout) -> bool
{
    Errors error;

    // todo: what if timeout is 0 or other invalid value?

    if (!Connect(request_timeout)) {
        ERROR("Failed to connect nri plugin %s", m_name.c_str());
        return false;
    }

    if (!WaitForReady(registry_timeout)) {
        ERROR("Failed to wait plugin %s ready with timeout %ld", m_name.c_str(), registry_timeout);
        return false;
    }

    if (!Configure(error)) {
        ERROR("Failed to configure nri plugin %s", m_name.c_str());
        return false;
    }

    return true;
}

auto NRIPlugin::shutdown() -> void
{
    if (!Close()) {
        ERROR("Failed to close plugin %s", m_name.c_str());
    }

    if (!Stop()) {
        ERROR("Failed to stop plugin %s", m_name.c_str());
    }
}

// create client connect
auto NRIPlugin::Connect(int64_t timeout) -> bool
{
    if (m_name.empty()) {
        ERROR("Empty nri plugin name");
        return false;
    }

    if (nri_plugin_connect(m_name.c_str(), m_sockFds[0], timeout * SECOND_TO_NANOS) != 0) {
        ERROR("Failed to create a new client for plugin %s", m_name.c_str());
        return false;
    }

    return true;
}

// close a plugin shutting down its multiplexed ttrpc connections.
auto NRIPlugin::Close() -> bool
{
    if (IsClose()) {
        return true;
    }

    if (nri_plugin_disconnect(m_name.c_str()) != 0) {
        ERROR("Failed to close plugin %s", m_name.c_str());
        return false;
    }

    SetClose();
    return true;
}

// stop a plugin (if it was launched by us)
auto NRIPlugin::Stop() -> bool
{
    if (m_external) {
        return true;
    }

    if (m_pid <= 0) {
        WARN("Invalid pid %d", m_pid);
        return false;
    }

    int nret = kill(m_pid, SIGKILL);
    if (nret < 0 && errno != ESRCH) {
        SYSWARN("Can not kill process (pid=%d) with SIGKILL", m_pid);
        return false;
    }

    if (util_waitpid_with_timeout(m_pid, DefaultWaitTimeout, NULL) != 0) {
        WARN("Failed to wait for plugin %s to exit", m_name.c_str());
        return false;
    }
    return true;
}

// Name returns a string indentication for the plugin.
auto NRIPlugin::GetName() -> const std::string &
{
    return m_name;
}

auto NRIPlugin::GetIndex() -> const std::string &
{
    return m_idx;
}

auto NRIPlugin::GetPeerSockFd() -> uint32_t
{
    return m_sockFds[1];
}

auto NRIPlugin::GetQualifiedName() -> std::string
{
    return m_idx + "-" +  m_name;
}

void NRIPlugin::SetReady(void)
{
    std::unique_lock<std::mutex> lock(m_readyMutex);
    m_ready = true;
    m_condition.notify_one();
}

void NRIPlugin::SetPid(int pid)
{
    m_pid = pid;
}

auto NRIPlugin::CreateSocketPair() -> bool
{
    int fds[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1) {
        ERROR("Failed to create socketpair");
        return false;
    }

    m_sockFds.push_back(fds[0]);
    m_sockFds.push_back(fds[1]);
    return true;
}

auto NRIPlugin::Configure(Errors &error) -> bool
{
    auto req = makeUniquePtrCStructWrapper<nri_configure_request>(free_nri_configure_request);
    if (req == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    req->get()->config = isula_strdup_s(m_config.c_str());
    req->get()->runtime_name = isula_strdup_s(NRIRruntime.c_str());
    req->get()->runtime_version = isula_strdup_s(NRIVersion.c_str());

    nri_configure_response *resp = nullptr;
    if (nri_plugin_configure(m_name.c_str(), req->get(), &resp) != 0) {
        ERROR("Failed to configure plugin %s", m_name.c_str());
        return false;
    }

    auto resp_wrapper = makeUniquePtrCStructWrapper<nri_configure_response>(resp, free_nri_configure_response);
    if (resp_wrapper == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    EventMask events = resp_wrapper->get()->events;
    if (events != 0) {
        EventMask extra = events & ~ValidEvents;
        if (extra != 0) {
            ERROR("Invalid plugin events: %d", extra);
            return false;
        }
    } else {
        events = ValidEvents;
    }

    m_events = events;
    return true;
}

auto NRIPlugin::Synchronize(std::vector<nri_pod_sandbox *> &pods, std::vector<nri_container *> &containers,
                            nri_container_update ***update, size_t update_len, Errors &error) -> bool
{
    size_t i;

    auto req = makeUniquePtrCStructWrapper<nri_synchronize_request>(free_nri_synchronize_request);
    if (req == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    if (pods.size() != 0) {
        req->get()->pods = (nri_pod_sandbox **)util_common_calloc_s(pods.size() * sizeof(nri_pod_sandbox *));
        if (req->get()->pods == nullptr) {
            ERROR("Out of memory");
            return false;
        }

        for (i = 0; i < pods.size(); i++) {
            req->get()->pods[i] = pods[i];
            req->get()->pods_len++;
        }
    }

    if (containers.size() != 0) {
        req->get()->containers = (nri_container **)util_common_calloc_s(containers.size() * sizeof(nri_container *));
        if (req->get()->containers == nullptr) {
            ERROR("Out of memory");
            return false;
        }

        for (i = 0; i < containers.size(); i++) {
            req->get()->containers[i] = containers[i];
            req->get()->containers_len++;
        }
    }

    nri_synchronize_response *resp = nullptr;
    if (nri_plugin_synchronize(m_name.c_str(), req->get(), &resp) != 0) {
        ERROR("Failed to synchronize plugin %s", m_name.c_str());
        return false;
    }

    auto resp_wrapper = makeUniquePtrCStructWrapper<nri_synchronize_response>(resp, free_nri_synchronize_response);
    if (resp_wrapper == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    *update = resp->update;
    resp->update = nullptr;
    update_len = resp->update_len;
    resp->update_len = 0;
    return true;
}

auto NRIPlugin::CreateContainer(nri_create_container_request *req, nri_create_container_response **resp,
                                Errors &error) -> bool
{
    if (req == nullptr) {
        ERROR("Invalid input");
        return false;
    }

    if (IsSetEvent(CREATE_CONTAINER) == false) {
        return true;
    }

    if (nri_plugin_create_container(m_name.c_str(), req, resp) != 0) {
        ERROR("Failed to create container by plugin %s", m_name.c_str());
        return false;
    }

    return true;
}

auto NRIPlugin::UpdateContainer(nri_update_container_request *req, nri_update_container_response **resp,
                                Errors &error) -> bool
{
    if (req == nullptr) {
        ERROR("Invalid input");
        return false;
    }

    if (!IsSetEvent(UPDATE_CONTAINER)) {
        return true;
    }

    if (nri_plugin_update_container(m_name.c_str(), req, resp) != 0) {
        ERROR("Failed to update container by plugin %s", m_name.c_str());
        return false;
    }
    return true;
}

auto NRIPlugin::StopContainer(nri_stop_container_request *req, nri_stop_container_response **resp,
                              Errors &error) -> bool
{
    if (req == nullptr) {
        ERROR("Invalid input");
        return false;
    }

    if (!IsSetEvent(STOP_CONTAINER)) {
        return true;
    }

    if (nri_plugin_stop_container(m_name.c_str(), req, resp) != 0) {
        ERROR("Failed to stop container by plugin %s", m_name.c_str());
        return false;
    }
    return true;
}

// do nothing with event
auto NRIPlugin::StateChange(nri_state_change_event *evt, Errors &error) -> bool
{
    if (evt == nullptr) {
        ERROR("Invalid input");
        return false;
    }

    if (!IsSetEvent(evt->event)) {
        return true;
    }

    if (nri_plugin_state_change(m_name.c_str(), evt) != 0) {
        ERROR("Failed to state change by plugin %s", m_name.c_str());
        return false;
    }
    return true;
}

auto NRIPlugin::WaitForReady(int64_t timeout) -> bool
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout * 1000);
    std::unique_lock<std::mutex> readyMutex(m_readyMutex);

    if (timeout == 0) {
        m_condition.wait(readyMutex);
        return true;
    }

    if (m_condition.wait_until(readyMutex, deadline) == std::cv_status::timeout) {
        return false;
    }

    return true;
}

auto NRIPlugin::IsSetEvent(EventMask e) -> bool
{
    return (m_events & (1 << (e - 1))) != 0;
}

auto NRIPlugin::IsClose() -> bool
{
    ReadGuard<RWMutex> lock(m_mutex);
    return m_closed;
}

void NRIPlugin::SetClose()
{
    WriteGuard<RWMutex> lock(m_mutex);
    m_closed = true;
}