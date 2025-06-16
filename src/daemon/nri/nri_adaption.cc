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
 * Description: provide plugin manager(NRI adaption) class definition
 *********************************************************************************/

#include "nri_adaption.h"

#include <sys/stat.h>

#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>

#include "isulad_config.h"
#include "utils_file.h"
#include "utils_string.h"
#include "utils.h"
#include "nri_convert.h"
#include "nri_plugin.h"
#include "nri_result.h"
#include "sandbox_manager.h"

std::atomic<NRIAdaptation *> NRIAdaptation::m_instance;

NRIAdaptation *NRIAdaptation::GetInstance() noexcept
{
    static std::once_flag flag;

    std::call_once(flag, [] { m_instance = new NRIAdaptation; });

    return m_instance;
}

NRIAdaptation::~NRIAdaptation()
{
    for (const auto &pair : m_storeMap) {
        auto plugin = pair.second;
        plugin->shutdown();
    }
}

auto NRIAdaptation::Init(Errors &error) -> bool
{
    std::map<std::string, std::shared_ptr<NRIPlugin>> tmp_storeMap;

    m_support = conf_get_nri_support();
    if (!m_support) {
        return true;
    }

    m_external_support = conf_get_nri_external_support();
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr) {
        ERROR("Init isulad service executor failure.");
        return false;
    }

    m_containerManager = std::make_unique<CRIV1::ContainerManagerService>(cb);

    m_pluginConfigPath = GetNRIPluginConfigPath();
    m_pluginPath = GetNRIPluginPath();
    m_plugin_registration_timeout = conf_get_nri_plugin_registration_timeout();
    m_plugin_requst_timeout = conf_get_nri_plugin_requst_timeout();
    m_sock_path = GetNRISockPath();

    if (!StartPlugin()) {
        ERROR("Failed to do StartPlugin");
        return false;
    }

    if (!SortPlugins()) {
        ERROR("Failed to do SortPlugins");
        return false;
    }

    return true;
}

void NRIAdaptation::RemoveClosedPlugins()
{
    std::vector<std::string> closedPlugin;

    GetClosedPlugins(closedPlugin);

    for (const auto &key : closedPlugin) {
        RemovePluginByIndex(key);
    }
}

void NRIAdaptation::GetClosedPlugins(std::vector<std::string> &closedPlugin)
{
    ReadGuard<RWMutex> lock(m_mutex);
    for (const auto &pair : m_storeMap) {
        auto plugin = pair.second;
        if (plugin->IsClose()) {
            closedPlugin.push_back(pair.first);
        }
    }
}

auto NRIAdaptation::IsSupport() -> bool
{
    return m_support;
}

auto NRIAdaptation::GetPluginByIndex(const std::string &index) -> std::shared_ptr<NRIPlugin>
{
    ReadGuard<RWMutex> lock(m_mutex);
    return m_storeMap[index];
}

void NRIAdaptation::RemovePluginByIndex(const std::string &index)
{
    WriteGuard<RWMutex> lock(m_mutex);
    m_storeMap.erase(index);
}

void NRIAdaptation::AddPluginByIndex(const std::string &index, std::shared_ptr<NRIPlugin> plugin)
{
    WriteGuard<RWMutex> lock(m_mutex);
    m_storeMap[index] = plugin;
}

auto NRIAdaptation::ApplyUpdates(const std::vector<nri_container_update *> &update,
                                 std::vector<nri_container_update *> &failed, bool getFailed, Errors &error) -> bool
{
    for (auto &u : update) {
        runtime::v1::LinuxContainerResources resources;
        if (!LinuxResourcesFromNRI(u->linux->resources, resources)) {
            ERROR("Failed to convert Linux resources from NRI");
            error.Errorf("Failed to convert Linux resources from NRI");
            return false;
        }

        m_containerManager->UpdateContainerResources(u->container_id, resources, error);

        if (error.NotEmpty()) {
            ERROR("Failed to update container: %s resources: %s", u->container_id, error.GetCMessage());
            if (!static_cast<bool>(u->ignore_failure) && getFailed) {
                failed.push_back(u);
            }
            continue;
        }

        TRACE("NRI update of container %s successful", u->container_id);
    }

    if (failed.size() != 0) {
        error.Errorf("NRI update of some containers failed");
        return false;
    }
    return true;
}

auto NRIAdaptation::NewExternalPlugin(int fd) -> bool
{
    if (!m_external_support) {
        ERROR("External plugin support is disabled");
        return false;
    }
    if (fd < 0) {
        ERROR("Invalid fd");
        return false;
    }

    std::string plugin_name;
    NRIHelpers::GenerateRandomExternalName(plugin_name);
    if (plugin_name.empty()) {
        ERROR("Failed to generate random external name");
        return false;
    }

    auto plugin = std::make_shared<NRIPlugin>(fd, plugin_name);

    AddPluginByIndex(plugin_name, plugin);

    if (!plugin->Start(m_plugin_registration_timeout, m_plugin_requst_timeout)) {
        ERROR("Failed to start plugin ready for conn fd %d", fd);
        RemovePluginByIndex(plugin_name);
        return false;
    }

    std::vector<nri_pod_sandbox *> pods;
    std::vector<nri_container *> cons;
    nri_container_update **updateRes;
    size_t update_len = 0;

    std::vector<std::shared_ptr<sandbox::Sandbox>> sandboxes;
    runtime::v1::PodSandboxFilter podFilter;
    std::vector<std::unique_ptr<runtime::v1::Container>> containers;
    Errors tmpError;

    std::vector<nri_container_update *> updates;
    std::vector<nri_container_update *> failed;

    sandbox::SandboxManager::GetInstance()->ListAllSandboxes(podFilter, sandboxes);

    if (!PodSandboxesToNRI(sandboxes, pods)) {
        ERROR("Failed to convert podsandbox to nri");
        NRIHelpers::FreeNriPodVector(pods);
        return false;
    }

    m_containerManager->ListContainers(nullptr, containers, tmpError);

    if (!ContainersToNRI(containers, cons)) {
        ERROR("Failed to convert container to nri");
        NRIHelpers::FreeNriPodVector(pods);
        NRIHelpers::FreeNriContainerVector(cons);
        return false;
    }

    // pods and cons's memory transfer to nri_synchronize_request,
    // and is automatically freed when nri_synchronize_request is freed
    if (!plugin->Synchronize(pods, cons, &updateRes, update_len, tmpError)) {
        ERROR("Failed to synchronize plugin");
        return false;
    }

    for (size_t i = 0; i < update_len; i++) {
        updates.push_back(updateRes[i]);
    }

    if (!ApplyUpdates(updates, failed, false, tmpError)) {
        ERROR("Failed to update post-sync");
    }

    NRIHelpers::FreeNriContainerUpdateVector(updates);
    NRIHelpers::FreeNriContainerUpdateVector(failed);
    INFO("plugin %s connected", plugin_name.c_str());
    return true;
}

auto NRIAdaptation::RunPodSandbox(std::shared_ptr<const sandbox::Sandbox> sandbox, Errors &error) -> bool
{
    if (!m_support) {
        return true;
    }

    auto pod = NRIPodSandbox(sandbox, error);
    if (pod == nullptr) {
        ERROR("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        return false;
    }

    auto runPodEvent = makeUniquePtrCStructWrapper<nri_state_change_event>(free_nri_state_change_event);
    if (runPodEvent == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    runPodEvent->get()->pod = pod->move();
    runPodEvent->get()->event = RUN_POD_SANDBOX;
    return StateChange(runPodEvent->get(), error);
}

auto NRIAdaptation::StopPodSandbox(std::shared_ptr<const sandbox::Sandbox> sandbox, Errors &error) -> bool
{
    if (!m_support) {
        return true;
    }

    auto pod = NRIPodSandbox(sandbox, error);
    if (pod == nullptr) {
        ERROR("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        return false;
    }

    auto stopPodEvent = makeUniquePtrCStructWrapper<nri_state_change_event>(free_nri_state_change_event);
    if (stopPodEvent == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    stopPodEvent->get()->pod = pod->move();
    stopPodEvent->get()->event = STOP_POD_SANDBOX;
    return StateChange(stopPodEvent->get(), error);
}

auto NRIAdaptation::RemovePodSandbox(std::shared_ptr<const sandbox::Sandbox> sandbox, Errors &error) -> bool
{
    if (!m_support) {
        return true;
    }

    auto pod = NRIPodSandbox(sandbox, error);
    if (pod == nullptr) {
        ERROR("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        return false;
    }

    auto removePodEvent = makeUniquePtrCStructWrapper<nri_state_change_event>(free_nri_state_change_event);
    if (removePodEvent == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    removePodEvent->get()->pod = pod->move();
    removePodEvent->get()->event = REMOVE_POD_SANDBOX;
    return StateChange(removePodEvent->get(), error);
}

auto NRIAdaptation::CreateContainer(std::shared_ptr<const sandbox::Sandbox> sandbox, const std::string &conId,
                                    const runtime::v1::ContainerConfig &containerConfig, nri_container_adjustment **adjust, Errors &error) -> bool
{
    if (!m_support) {
        return true;
    }

    auto pod = NRIPodSandbox(sandbox, error);
    if (pod == nullptr) {
        ERROR("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        return false;
    }

    auto con = NRIContainerByConConfig(sandbox, containerConfig, error);
    if (con == nullptr) {
        ERROR("Failed to covert container to nri: %s", conId.c_str());
        return false;
    }

    auto req = makeUniquePtrCStructWrapper<nri_create_container_request>(free_nri_create_container_request);
    if (req == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    req->get()->container = con->move();
    req->get()->pod = pod->move();

    pluginResult result;
    result.InitByConId(conId);

    if (!PluginsCreateContainer(req->get(), conId, result)) {
        ERROR("Failed to call create container to all plugins");
        return false;
    }

    RemoveClosedPlugins();

    // TODO:evict container do not aply

    // TODO:how can i rollback on failure
    std::vector<nri_container_update *> failed;
    if (!ApplyUpdates(result.GetReplyUpdate(), failed, false, error)) {
        ERROR("Failed to apply updates");
        NRIHelpers::FreeNriContainerUpdateVector(failed);
        return false;
    }

    *adjust = result.MoveReplyAdjust();
    NRIHelpers::FreeNriContainerUpdateVector(failed);
    return true;
}

bool NRIAdaptation::PluginsCreateContainer(nri_create_container_request *req, const std::string &conId,
                                           pluginResult &result)
{
    ReadGuard<RWMutex> lock(m_mutex);

    for (const auto &pair : m_storeMap) {
        auto plugin = pair.second;
        Errors tmpError;
        nri_create_container_response *resp = nullptr;

        if (!plugin->CreateContainer(req, &resp, tmpError)) {
            ERROR("Failed to call create container: %s to pliugin: %s", conId.c_str(), plugin->GetName().c_str());
            (void)plugin->shutdown();
            continue;
        }

        if (resp == nullptr) {
            ERROR("Empty CreateContainer resp : %s", plugin->GetName().c_str());
            continue;
        }

        auto resp_wrapper =
            makeUniquePtrCStructWrapper<nri_create_container_response>(resp, free_nri_create_container_response);
        if (resp_wrapper == nullptr) {
            ERROR("Out of memory");
            return false;
        }

        result.Apply(CREATE_CONTAINER, resp_wrapper->get()->adjust, resp_wrapper->get()->update,
                     resp_wrapper->get()->update_len, plugin->GetName());
    }
    return true;
}

auto NRIAdaptation::PostCreateContainer(const std::string &conId, Errors &error) -> bool
{
    if (!m_support) {
        return true;
    }

    auto con = NRIContainerByID(conId, error);
    if (con == nullptr) {
        ERROR("Failed to covert container to nri: %s", conId.c_str());
        return false;
    }

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(con->get()->pod_sandbox_id);
    if (sandbox == nullptr) {
        ERROR("Failed to get sandbox info for nri");
        return false;
    }

    auto pod = NRIPodSandbox(sandbox, error);
    if (pod == nullptr) {
        ERROR("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        return false;
    }

    auto postCreateConEvent = makeUniquePtrCStructWrapper<nri_state_change_event>(free_nri_state_change_event);
    if (postCreateConEvent == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    postCreateConEvent->get()->container = con->move();
    postCreateConEvent->get()->pod = pod->move();
    postCreateConEvent->get()->event = POST_CREATE_CONTAINER;
    return StateChange(postCreateConEvent->get(), error);
}

auto NRIAdaptation::StartContainer(const std::string &conId, Errors &error) -> bool
{
    if (!m_support) {
        return true;
    }

    auto con = NRIContainerByID(conId, error);
    if (con == nullptr) {
        ERROR("Failed to covert container to nri: %s", conId.c_str());
        return false;
    }

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(con->get()->pod_sandbox_id);
    if (sandbox == nullptr) {
        ERROR("Failed to get sandbox info for nri");
        return false;
    }

    if (sandbox == nullptr) {
        ERROR("Failed to get sandbox for container: %s, sandbox id: %s", conId.c_str(), con->get()->pod_sandbox_id);
        return false;
    }

    auto pod = NRIPodSandbox(sandbox, error);
    if (pod == nullptr) {
        ERROR("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        return false;
    }

    auto startConEvent = makeUniquePtrCStructWrapper<nri_state_change_event>(free_nri_state_change_event);
    if (startConEvent == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    startConEvent->get()->container = con->move();
    startConEvent->get()->pod = pod->move();
    startConEvent->get()->event = START_CONTAINER;
    return StateChange(startConEvent->get(), error);
}

auto NRIAdaptation::PostStartContainer(const std::string &conId, Errors &error) -> bool
{
    if (!m_support) {
        return true;
    }

    auto con = NRIContainerByID(conId, error);
    if (con == nullptr) {
        ERROR("Failed to covert container to nri: %s", conId.c_str());
        return false;
    }

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(con->get()->pod_sandbox_id);
    if (sandbox == nullptr) {
        ERROR("Failed to get sandbox info for nri");
        return false;
    }

    auto pod = NRIPodSandbox(sandbox, error);
    if (pod == nullptr) {
        ERROR("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        return false;
    }

    auto postStartConEvent = makeUniquePtrCStructWrapper<nri_state_change_event>(free_nri_state_change_event);
    if (postStartConEvent == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    postStartConEvent->get()->container = con->move();
    postStartConEvent->get()->pod = pod->move();
    postStartConEvent->get()->event = POST_START_CONTAINER;
    return StateChange(postStartConEvent->get(), error);
}

auto NRIAdaptation::UndoCreateContainer(std::shared_ptr<const sandbox::Sandbox> sandbox, const std::string &conId,
                                        Errors &error) -> bool
{
    if (!m_support) {
        return true;
    }

    if (!StopContainer(conId, error)) {
        ERROR("container creation undo (stop) failed: %s", conId.c_str());
    }

    if (!RemoveContainer(conId, error)) {
        ERROR("container creation undo (remove) failed: %s", conId.c_str());
    }

    return true;
}

auto NRIAdaptation::UpdateContainer(const std::string &conId, const runtime::v1::LinuxContainerResources &resources,
                                    runtime::v1::LinuxContainerResources &adjust, Errors &error) -> bool
{
    if (!m_support) {
        return true;
    }

    auto con = NRIContainerByID(conId, error);
    if (con == nullptr) {
        ERROR("Failed to covert container to nri: %s", conId.c_str());
        return false;
    }

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(con->get()->pod_sandbox_id);
    if (sandbox == nullptr) {
        ERROR("Failed to get sandbox info for nri");
        return false;
    }

    auto pod = NRIPodSandbox(sandbox, error);
    if (pod == nullptr) {
        ERROR("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        return false;
    }

    auto req = makeUniquePtrCStructWrapper<nri_update_container_request>(free_nri_update_container_request);
    if (req == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    auto reqRes = LinuxResourcesToNRI(resources);

    req->get()->container = con->move();
    req->get()->pod = pod->move();
    req->get()->linux_resources = reqRes;

    pluginResult result;
    result.InitByUpdateReq(req->get());

    if (!PluginsUpdateContainer(req->get(), conId, result)) {
        ERROR("Failed to call update container to all plugins");
        return false;
    }

    RemoveClosedPlugins();

    // TODO:evict container do not aply

    // TODO:how can i rollback on failure
    std::vector<nri_container_update *> failed;
    if (!ApplyUpdates(result.GetReplyUpdate(), failed, false, error)) {
        ERROR("Failed to apply updates");
        NRIHelpers::FreeNriContainerUpdateVector(failed);
        return false;
    }

    NRIHelpers::FreeNriContainerUpdateVector(failed);

    if (!LinuxResourcesFromNRI(result.GetReplyResources(conId), adjust)) {
        ERROR("Failed to convert Linux resources from NRI");
        return false;
    }

    return true;
}

bool NRIAdaptation::PluginsUpdateContainer(nri_update_container_request *req, const std::string &conId,
                                           pluginResult &result)
{
    ReadGuard<RWMutex> lock(m_mutex);

    for (const auto &pair : m_storeMap) {
        auto plugin = pair.second;
        Errors tmpError;
        nri_update_container_response *resp = nullptr;

        if (!plugin->UpdateContainer(req, &resp, tmpError)) {
            ERROR("Failed to call create container: %s to pliugin: %s", conId.c_str(), plugin->GetName().c_str());
            plugin->shutdown();
            continue;
        }

        if (resp == nullptr) {
            ERROR("Empty UpdateContainer resp : %s", plugin->GetName().c_str());
            continue;
        }

        auto resp_wrapper =
            makeUniquePtrCStructWrapper<nri_update_container_response>(resp, free_nri_update_container_response);
        if (resp_wrapper == nullptr) {
            ERROR("Out of memory");
            return false;
        }

        result.Apply(UPDATE_CONTAINER, nullptr, resp_wrapper->get()->update, resp_wrapper->get()->update_len,
                     plugin->GetName());
    }
    return true;
}

bool NRIAdaptation::PluginsStopContainer(nri_stop_container_request *req, const std::string &conId,
                                         pluginResult &result)
{
    ReadGuard<RWMutex> lock(m_mutex);

    for (const auto &pair : m_storeMap) {
        auto plugin = pair.second;
        Errors tmpError;
        nri_stop_container_response *resp = nullptr;

        if (!plugin->StopContainer(req, &resp, tmpError)) {
            ERROR("Failed to call create container: %s to pliugin: %s", conId.c_str(), plugin->GetName().c_str());
            plugin->shutdown();
            continue;
        }

        if (resp == nullptr) {
            ERROR("Empty StopContainer resp : %s", plugin->GetName().c_str());
            continue;
        }

        auto resp_wrapper = makeUniquePtrCStructWrapper<nri_stop_container_response>(resp, free_nri_stop_container_response);
        if (resp_wrapper == nullptr) {
            ERROR("Out of memory");
            return false;
        }

        result.Apply(STOP_CONTAINER, nullptr, resp_wrapper->get()->update, resp_wrapper->get()->update_len, plugin->GetName());
    }
    return true;
}

auto NRIAdaptation::PostUpdateContainer(const std::string &conId, Errors &error) ->bool
{
    if (!m_support) {
        return true;
    }

    auto con = NRIContainerByID(conId, error);
    if (con == nullptr) {
        ERROR("Failed to covert container to nri: %s", conId.c_str());
        return false;
    }

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(con->get()->pod_sandbox_id);
    if (sandbox == nullptr) {
        ERROR("Failed to get sandbox info for nri");
        return false;
    }

    auto pod = NRIPodSandbox(sandbox, error);
    if (pod == nullptr) {
        ERROR("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        return false;
    }

    auto postUpdateConEvent = makeUniquePtrCStructWrapper<nri_state_change_event>(free_nri_state_change_event);
    if (postUpdateConEvent == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    postUpdateConEvent->get()->container = con->move();
    postUpdateConEvent->get()->pod = pod->move();
    postUpdateConEvent->get()->event = POST_UPDATE_CONTAINER;
    return StateChange(postUpdateConEvent->get(), error);
}

auto NRIAdaptation::StopContainer(const std::string &conId, Errors &error) ->bool
{
    if (!m_support) {
        return true;
    }

    auto con = NRIContainerByID(conId, error);
    if (con == nullptr) {
        ERROR("Failed to covert container to nri: %s", conId.c_str());
        return false;
    }

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(con->get()->pod_sandbox_id);
    if (sandbox == nullptr) {
        ERROR("Failed to get sandbox info for nri");
        return false;
    }

    auto pod = NRIPodSandbox(sandbox, error);
    if (pod == nullptr) {
        ERROR("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        return false;
    }

    auto req = makeUniquePtrCStructWrapper<nri_stop_container_request>(free_nri_stop_container_request);
    if (req == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    req->get()->pod = pod->move();
    req->get()->container = con->move();

    pluginResult result;
    result.Init();

    if (!PluginsStopContainer(req->get(), conId, result)) {
        ERROR("Failed to call stop container to all plugins");
        return false;
    }

    RemoveClosedPlugins();

    // TODO:how can i rollback on failure
    std::vector<nri_container_update *> failed;
    if (!ApplyUpdates(result.GetReplyUpdate(), failed, false, error)) {
        ERROR("Failed to apply updates");
        NRIHelpers::FreeNriContainerUpdateVector(failed);
        return false;
    }

    NRIHelpers::FreeNriContainerUpdateVector(failed);
    return true;
}

auto NRIAdaptation::RemoveContainer(const std::string &conId, Errors &error) ->bool
{
    if (!m_support) {
        return true;
    }

    auto con = NRIContainerByID(conId, error);
    if (con == nullptr) {
        ERROR("Failed to covert container to nri: %s", conId.c_str());
        return false;
    }

    auto sandbox = sandbox::SandboxManager::GetInstance()->GetSandbox(con->get()->pod_sandbox_id);
    if (sandbox == nullptr) {
        ERROR("Failed to get sandbox info for nri");
        return false;
    }

    auto pod = NRIPodSandbox(sandbox, error);
    if (pod == nullptr) {
        ERROR("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        return false;
    }

    auto removeConEvent = makeUniquePtrCStructWrapper<nri_state_change_event>(free_nri_state_change_event);
    if (removeConEvent == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    removeConEvent->get()->container = con->move();
    removeConEvent->get()->pod = pod->move();
    removeConEvent->get()->event = REMOVE_CONTAINER;
    return StateChange(removeConEvent->get(), error);
}

auto NRIAdaptation::StateChange(nri_state_change_event *evt, Errors &error) ->bool
{
    if (evt->event == UNKNOWN) {
        ERROR("invalid (unset) event in state change notification");
        error.SetError("invalid (unset) event in state change notification");
        return false;
    }

    PluginsStateChange(evt);

    RemoveClosedPlugins();
    return true;
}

void NRIAdaptation::PluginsStateChange(nri_state_change_event *evt)
{
    ReadGuard<RWMutex> lock(m_mutex);

    for (const auto &pair : m_storeMap) {
        auto plugin = pair.second;
        Errors tmpError;
        if (!plugin->StateChange(evt, tmpError)) {
            ERROR("invalid (unset) event in state change notification: %s", plugin->GetName().c_str());
            plugin->shutdown();
            continue;
        }
    }
}

// Perform a set of unsolicited container updates requested by a plugin.
auto NRIAdaptation::updateContainers(const nri_update_containers_request *req,
                                     nri_update_containers_response **resp) ->bool
{
    std::vector<nri_container_update *> failed;
    std::vector<nri_container_update *> vec;
    size_t i;
    Errors error;
    bool ret = false;

    if (req == nullptr) {
        ERROR("Invalid request");
        return false;
    }

    for (i = 0; i < req->update_len; i++) {
        vec.push_back(req->update[i]);
    }

    if (!ApplyUpdates(vec, failed, false, error)) {
        ERROR("Failed to apply updates: %s", error.GetCMessage());
        goto free_out;
    }

    if (failed.size() == 0) {
        ret = true;
        goto free_out;
    }

    (*resp)->failed = (nri_container_update **)util_common_calloc_s(failed.size() * sizeof(nri_container_update *));
    if ((*resp)->failed == nullptr) {
        ERROR("Out of memory");
        goto free_out;
    }

    for (i = 0; i < failed.size(); i++) {
        (*resp)->failed[i] = failed[i];
        failed[i] = nullptr;
        (*resp)->failed_len++;
    }
    ret = true;

free_out:
    NRIHelpers::FreeNriContainerUpdateVector(vec);
    NRIHelpers::FreeNriContainerUpdateVector(failed);
    return ret;
}

auto NRIAdaptation::StartPlugin() -> bool
{
    std::map<std::string, std::shared_ptr<NRIPlugin>> tmp_storeMap;

    if (!DiscoverPlugins(tmp_storeMap) != 0) {
        ERROR("Failed to do DiscoverPlugins");
        return false;
    }

    for (const auto &pair : tmp_storeMap) {
        const std::string &index = pair.first;
        auto plugin = pair.second;

        if (!NewLaunchedPlugin(plugin)) {
            ERROR("Failed to do NewLaunchedPlugin for %s", plugin->GetName().c_str());
            continue;
        }

        AddPluginByIndex(index, plugin);

        if (!plugin->Start(m_plugin_registration_timeout, m_plugin_requst_timeout)) {
            ERROR("Failed to start plugin %s ready", plugin->GetName().c_str());
            RemovePluginByIndex(index);
            (void)plugin->shutdown();
            continue;
        }
    }

    return true;
}

// return true always, failure to obtain one plugin does not affect other plugin
static auto walk_plugin_dir_cb(const char *path_name, const struct dirent *sub_dir, void *context) -> bool
{
    std::string full_path = std::string(path_name) + "/" + sub_dir->d_name;
    struct stat file_stat = { 0 };

    if (stat(full_path.c_str(), &file_stat) != 0) {
        WARN("Failed to get NRI plugin %s stat", sub_dir->d_name);
        return true;
    }

    if (S_ISDIR(file_stat.st_mode)) {
        INFO("Skip dir in plugin path %s", sub_dir->d_name);
        return true;
    }

    // 1. Verify plugin permissions for exec
    if (!(file_stat.st_mode & S_IXUSR)) {
        ERROR("NRI plugin %s has no permission for exec", sub_dir->d_name);
        return true;
    }

    // 2. Parse plugin name
    __isula_auto_array_t char **arr = util_string_split_n(sub_dir->d_name, '-', 2);
    if (arr == nullptr) {
        ERROR("Invalid plugin name %s, idx-pluginname expected", sub_dir->d_name);
        return true;
    }

    if (!NRIHelpers::CheckPluginIndex(arr[0])) {
        ERROR("Invalid plugin name %s, invalid idx", sub_dir->d_name);
        return true;
    }

    // 3. init plugin
    std::string index(arr[0]);
    std::string pluginName(arr[1]);
    std::string config;

    std::map<std::string, std::shared_ptr<NRIPlugin>> &map =
                                                       *static_cast<std::map<std::string, std::shared_ptr<NRIPlugin>>*>(context);
    if (!NRIHelpers::GetPluginConfig(index, pluginName, config)) {
        ERROR("Failed to get plugin %s config", pluginName.c_str());
        return true;
    }

    auto plugin = std::make_shared<NRIPlugin>(index, pluginName, config);

    // todo:use random id str
    map[pluginName] = plugin;
    return true;
}

static void plugin_exec_func(nri_plugin_exec_args_t * plugin_args)
{
    const char *params[PARAM_NUM] = {0};
    int i = 0;
    std::string sock = std::to_string(plugin_args->sockFd);

    if (plugin_args == nullptr) {
        ERROR("Missing plugin exec info");
        _exit(EXIT_FAILURE);
    }

    if (chdir(plugin_args->workdir) < 0) {
        ERROR("Failed to chdir to %s", plugin_args->workdir);
        _exit(EXIT_FAILURE);
    }

    if (setenv(PluginNameEnv.c_str(), plugin_args->name, 1) != 0) {
        ERROR("%s: failed to set PluginNameEnv for process %d", plugin_args->name, getpid());
        exit(EXIT_FAILURE);
    }

    if (setenv(PluginIdxEnv.c_str(), plugin_args->index, 1) != 0) {
        ERROR("%s: failed to set PluginIdxEnv for process %d", plugin_args->name, getpid());
        exit(EXIT_FAILURE);
    }

    if (setenv(PluginSocketEnv.c_str(), sock.c_str(), 1) != 0) {
        ERROR("%s: failed to set PluginSocketEnv for process %d", plugin_args->name, getpid());
        exit(EXIT_FAILURE);
    }

    if (util_check_inherited(true, plugin_args->sockFd) != 0) {
        ERROR("Failed to close inherited fds");
        exit(EXIT_FAILURE);
    }

    if (setsid() < 0) {
        ERROR("Failed to setsid for nri plugin: %s", plugin_args->name);
        exit(EXIT_FAILURE);
    }

    params[i++] = plugin_args->name;

    execvp(plugin_args->cmd, (char * const *)params);
    ERROR("Failed to exec %s", plugin_args->cmd);
    _exit(EXIT_FAILURE);
}

// create socket, and call plugin start
auto NRIAdaptation::NewLaunchedPlugin(const std::shared_ptr<NRIPlugin> &plugin) -> bool
{
    // 1. create socket for plugin
    if (!plugin->CreateSocketPair()) {
        ERROR("Failed to create socket pair");
        return false;
    }

    std::string name = plugin->GetQualifiedName();
    std::string cmd = m_pluginPath + "/" + name;

    DEBUG("Plugin %s start", cmd.c_str());

    // 2. exec plugin
    nri_plugin_exec_args_t p_args = {
        .workdir = m_pluginPath.c_str(),
        .cmd = cmd.c_str(),
        .name = name.c_str(),
        .index = plugin->GetIndex().c_str(),
        .sockFd = plugin->GetPeerSockFd(),
    };

    int pid = fork();
    if (pid == (pid_t) -1) {
        SYSERROR("Failed to fork");
        return false;
    }

    if (pid == (pid_t)0) {
        set_child_process_pdeathsig();

        plugin_exec_func(&p_args);
    }

    close(plugin->GetPeerSockFd());

    plugin->SetPid(pid);

    return true;
}

// find plugin and create plugin
auto NRIAdaptation::DiscoverPlugins(std::map<std::string, std::shared_ptr<NRIPlugin>> &map) -> bool
{
    int nret = 0;

    // 1. get all plugin
    nret = util_scan_subdirs(m_pluginPath.c_str(), walk_plugin_dir_cb, static_cast<void*>(&map));
    if (nret != 0) {
        ERROR("Failed to scan nri plugin subdirs");
    }
    return true;
}

auto NRIAdaptation::SortPlugins() -> bool
{
    RemoveClosedPlugins();

    std::vector<std::pair<std::string, std::shared_ptr<NRIPlugin>>> sortedPlugins(m_storeMap.begin(), m_storeMap.end());

    std::sort(sortedPlugins.begin(), sortedPlugins.end(), [](const auto & a, const auto & b) {
        return a.first < b.first;
    });

    WriteGuard<RWMutex> lock(m_mutex);
    m_storeMap.clear();
    for (const auto &pair : sortedPlugins) {
        m_storeMap.insert(pair);
    }

    return true;
}

auto NRIAdaptation::GetNRIPluginConfigPath(void) -> std::string
{
    __isula_auto_free char *config_path = nullptr;
    std::string ret;

    config_path = conf_get_nri_plugin_config_path();
    if (config_path == nullptr) {
        return ret;
    }
    ret = std::string(config_path);
    return ret;
}

auto NRIAdaptation::GetNRIPluginPath(void) -> std::string
{
    __isula_auto_free char *plugin_path = nullptr;
    std::string ret;

    plugin_path = conf_get_nri_plugin_path();
    if (plugin_path == nullptr) {
        return ret;
    }
    ret = std::string(plugin_path);
    return ret;
}

auto NRIAdaptation::GetNRISockPath(void) -> std::string
{
    __isula_auto_free char *sock_path = nullptr;
    std::string ret;

    sock_path = conf_get_socket_path();
    if (sock_path == nullptr) {
        return ret;
    }
    ret = std::string(sock_path);
    return ret;
}

auto NRIAdaptation::NRIPodSandbox(const std::shared_ptr<const sandbox::Sandbox> &sandbox,
                                  Errors &error) -> std::unique_ptr<CStructWrapper<nri_pod_sandbox>>
{
    auto pod = makeUniquePtrCStructWrapper<nri_pod_sandbox>(free_nri_pod_sandbox);
    if (pod == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }

    if (!PodSandboxToNRI(sandbox, *pod->get())) {
        error.Errorf("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        ERROR("Failed to covert podsandbox to nri: %s", sandbox->GetId().c_str());
        return nullptr;
    }

    return pod;
}

auto NRIAdaptation::NRIContainerByID(const std::string &id,
                                     Errors &error) -> std::unique_ptr<CStructWrapper<nri_container>>
{
    auto con = makeUniquePtrCStructWrapper<nri_container>(free_nri_container);
    if (con == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }

    if (!ContainerToNRIByID(id, *con->get())) {
        error.Errorf("Failed to covert container to nri: %s", id.c_str());
        ERROR("Failed to covert container to nri: %s", id.c_str());
        return nullptr;
    }

    return con;
}

auto NRIAdaptation::NRIContainerByConConfig(const std::shared_ptr<const sandbox::Sandbox> &sandbox,
                                            const runtime::v1::ContainerConfig &containerConfig, Errors &error) -> std::unique_ptr<CStructWrapper<nri_container>>
{
    auto con = makeUniquePtrCStructWrapper<nri_container>(free_nri_container);
    if (con == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }

    if (!ContainerToNRIByConConfig(containerConfig, *con->get())) {
        error.Errorf("Failed to covert container to nri: %s", con->get()->name);
        ERROR("Failed to covert container to nri: %s", con->get()->name);
        return nullptr;
    }
    con->get()->pod_sandbox_id = isula_strdup_s(sandbox->GetId().c_str());

    return con;
}