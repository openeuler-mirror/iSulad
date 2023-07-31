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
 * Author: zhongtao
 * Create: 2023-06-19
 * Description: provide sandbox class definition
 *********************************************************************************/
#include "sandbox.h"

#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <mutex>
#include <memory>
#include <sstream>

#include <isula_libutils/log.h>
#include <isula_libutils/sandbox_metadata.h>
#include <isula_libutils/sandbox_state.h>
#include <google/protobuf/util/json_util.h>
#include <isula_libutils/auto_cleanup.h>

#include "utils_file.h"
#include "constants.h"
#include "isulad_config.h"
#include "utils.h"
#include "namespace.h"
#include "transform.h"
#include "cxxutils.h"
#include "controller_manager.h"

#define SANDBOX_READY_STATE_STR "SANDBOX_READY"
#define SANDBOX_NOTREADY_STATE_STR "SANDBOX_NOTREADY"

namespace sandbox {

Sandbox::Sandbox(const std::string id, const std::string &rootdir, const std::string &statedir, const std::string name,
                 const RuntimeInfo info, std::string netMode, std::string netNsPath, const runtime::v1::PodSandboxConfig sandboxConfig)
{
    m_id = id;
    m_name = name;
    m_runtimeInfo.runtime = info.runtime;
    m_runtimeInfo.sandboxer = info.sandboxer;
    m_runtimeInfo.runtimeHandler = info.runtimeHandler;
    m_rootdir = rootdir + "/" + m_id;
    m_statedir = statedir + "/" + m_id;
    // the sandbox instance is not initialized and will not be used,
    // and the state does not need to be locked
    m_state.status = SANDBOX_STATUS_UNKNOWN;
    m_netNsPath = netNsPath;
    m_networkReady = false;
    m_netMode = netMode;
    m_sandboxConfig = std::make_shared<runtime::v1::PodSandboxConfig>(sandboxConfig);
    m_statsInfo = {0, 0};
}

auto Sandbox::IsReady() -> bool
{
    ReadGuard<RWMutex> lock(m_stateMutex);
    if (m_state.status == SANDBOX_STATUS_RUNNING) {
        return true;
    }
    return false;
}

auto Sandbox::GetId() -> const std::string &
{
    return m_id;
}

auto Sandbox::GetName() -> const std::string &
{
    return m_name;
}

auto Sandbox::GetRuntime() -> const std::string &
{
    return m_runtimeInfo.runtime;
}

auto Sandbox::GetSandboxer() -> const std::string &
{
    return m_runtimeInfo.sandboxer;
}

auto Sandbox::GetRuntimeHandle() -> const std::string &
{
    return m_runtimeInfo.runtimeHandler;
}

auto Sandbox::GetContainers() -> const std::vector<std::string> &
{
    return m_containers;
}

auto Sandbox::GetSandboxConfig() -> std::shared_ptr<runtime::v1::PodSandboxConfig>
{
    return m_sandboxConfig;
}

auto Sandbox::GetRootDir() -> std::string
{
    return m_rootdir;
}

auto Sandbox::GetStateDir() -> std::string
{
    return m_statedir;
}

auto Sandbox::GetResolvPath() -> std::string
{
    return m_rootdir + std::string("/resolv.conf");
}

auto Sandbox::GetShmPath() -> std::string
{
    return m_rootdir + std::string("/dev/shm");
}

auto Sandbox::GetStatsInfo() -> StatsInfo
{
    ReadGuard<RWMutex> lock(m_stateMutex);
    StatsInfo info;
    info.cpuUseNanos = m_statsInfo.cpuUseNanos;
    info.timestamp = m_statsInfo.timestamp;
    return info;
}

auto Sandbox::GetNetworkReady() -> bool
{
    return m_networkReady;
}

auto Sandbox::GetNetMode() -> const std::string &
{
    return m_netMode;
}

auto GetNetNsPath() -> const std::string &
{
    return m_netNsPath;
}

void Sandbox::DoUpdateExitedStatus(const ControllerExitInfo &exitInfo)
{
    WriteGuard<RWMutex> lock(m_stateMutex);
    m_state.exitStatus = exitInfo.exitStatus;
    m_state.exitedAt = exitInfo.exitedAt;
    m_state.status = SANDBOX_STATUS_STOPPED;
}

void Sandbox::DoUpdateStatus(std::unique_ptr<ControllerSandboxStatus> status, Errors &error)
{
    if (status == nullptr) {
        ERROR("Status is nullptr, %s", m_id.c_str());
        error.Errorf("Status is nullptr, %s", m_id.c_str());
        return;
    }
    m_taskAddress = status->taskAddress;
    WriteGuard<RWMutex> lock(m_stateMutex);
    // now, info is unused
    m_state.pid = status->pid;
    m_state.createdAt = status->createdAt;
    m_state.exitedAt = status->exitedAt;
    if (status->state == std::string(SANDBOX_READY_STATE_STR)) {
        m_state.status = SANDBOX_STATUS_RUNNING;
    }
}

void Sandbox::SetNetMode(const std::string &mode)
{
    m_netMode = mode;
}

void Sandbox::SetController(std::shared_ptr<Controller> controller)
{
    m_controller = controller;
}

void Sandbox::AddAnnotations(const std::string &key, const std::string &value)
{
    m_sandboxConfig->mutable_annotations()->insert({key, value});
}

void Sandbox::RemoveAnnotations(const std::string &key)
{
    m_sandboxConfig->mutable_annotations()->erase(key);
}

void Sandbox::AddLabels(const std::string &key, const std::string &value)
{
    m_sandboxConfig->mutable_labels()->insert({key, value});
}

void Sandbox::RemoveLabels(const std::string &key)
{
    m_sandboxConfig->mutable_labels()->erase(key);
}

void Sandbox::AddContainer(const std::string &id)
{
    m_containers.push_back(id);
}

void Sandbox::SetConatiners(const std::vector<std::string> &cons)
{
    m_containers = cons;
}

void Sandbox::RemoveContainer(const std::string &id)
{
    auto it = std::find(m_containers.begin(), m_containers.end(), id);
    if (it != m_containers.end()) {
        m_containers.erase(it);
    }
}

void Sandbox::UpdateNetworkSettings(const std::string &settingsJson, Errors &error)
{
    if (settingsJson.length() == 0) {
        error.Errorf("Empty settingsJson for %s", m_id.c_str());
        return;
    }

    if (!m_controller->UpdateNetworkSettings(m_id, settingsJson, error)) {
        error.Errorf("Failed to update networkSettings for %s", m_id.c_str());
        return;
    }

    SetNetworkSettings(settingsJson, error);
    if (error.NotEmpty()) {
        ERROR("Failed to set networkSettings for %s", m_id.c_str());
    }
}

auto Sandbox::UpdateStatsInfo(const StatsInfo &info) -> StatsInfo
{
    WriteGuard<RWMutex> lock(m_stateMutex);
    StatsInfo old;
    old.cpuUseNanos = m_statsInfo.cpuUseNanos;
    old.timestamp = m_statsInfo.timestamp;

    m_statsInfo.cpuUseNanos = info.cpuUseNanos;
    m_statsInfo.timestamp = info.timestamp;
    return old;
}

void Sandbox::SetNetworkReady(bool ready)
{
    m_networkReady = ready;
}

auto Sandbox::Save(Errors &error) -> bool
{
    if (!SaveState(error)) {
        ERROR("Failed to save state for %s", m_id.c_str());
        return false;
    }

    if (!SaveMetadata(error)) {
        ERROR("Failed to save metadata for %s", m_id.c_str());
        return false;
    }

    if (!SaveNetworkSetting(error)) {
        ERROR("Failed to save networkSettings for %s", m_id.c_str());
        return false;
    }

    return true;
}

auto Sandbox::Load(Errors &error) -> bool
{
    if (!LoadState(error)) {
        return false;
    }

    if (!LoadMetadata(error)) {
        return false;
    }

    m_controller = ControllerManager::GetInstance()->GetController(m_runtimeInfo.sandboxer);
    if (m_controller == nullptr) {
        error.Errorf("Failed to find controller %s", m_runtimeInfo.sandboxer.c_str());
        ERROR("Failed to find controller %s", m_runtimeInfo.sandboxer.c_str());
        return false;
    }

    if (!LoadNetworkSetting(error)) {
        return false;
    }

    if (!UpdateStatus(error)) {
        ERROR("Failed to update status of Sandbox, id='%s'", m_id.c_str());
        return false;
    }

    // TODO: distinguish the meaning of Wait() return value in different states of sandbox
    if (!m_controller->Wait(shared_from_this(), m_id, error)) {
        ERROR("Failed to restore wait callback");
        return false;
    }

    return true;
}

void Sandbox::OnSandboxExit(const ControllerExitInfo &exitInfo)
{
    Errors error;
    DoUpdateExitedStatus(exitInfo);

    if (!SaveState(error)) {
        ERROR("Failed to save sandbox state, %s", m_id.c_str());
    }
}

auto Sandbox::UpdateStatus(Errors &error) -> bool
{
    bool verbose = false;
    std::unique_ptr<ControllerSandboxStatus> status = m_controller->Status(m_id, verbose, error);
    if (status == nullptr) {
        ERROR("Failed to get status of Sandbox, id='%s'", m_id.c_str());
        return false;
    }

    DoUpdateStatus(std::move(status), error);
    if (error.NotEmpty()) {
        return false;
    }

    if (!SaveState(error)) {
        ERROR("Failed to save sandbox state, %s", m_id.c_str());
        return false;
    }
    return true;
}

auto Sandbox::GenerateSandboxStateJson(sandbox_state *state) -> std::string
{
    __isula_auto_free parser_error error;
    std::string ret;
    __isula_auto_free char *state_json = NULL;
    state_json = sandbox_state_generate_json(state, NULL, &(error));
    if (state_json == NULL || strlen(state_json) == 0) {
        return ret;
    }
    ret = std::string(state_json);
    return ret;
}

auto Sandbox::SaveState(Errors &error) -> bool
{
    sandbox_state state = { 0 };
    std::string stateJson;
    int nret = -1;
    const std::string path = GetStatePath();
    WriteGuard<RWMutex> lock(m_stateMutex);

    state.created_at = m_state.createdAt;
    state.exited_at = m_state.exitedAt;
    state.pid = m_state.pid;
    state.status = m_state.status;
    state.updated_at = m_state.updatedAt;

    stateJson = GenerateSandboxStateJson(&state);
    if (stateJson.length() == 0) {
        error.Errorf("Failed to get sandbox state json for sandbox: '%s'", m_id.c_str());
        return false;
    }

    nret = util_atomic_write_file(path.c_str(), stateJson.c_str(), stateJson.length(), CONFIG_FILE_MODE, false);
    if (nret != 0) {
        error.Errorf("Failed to write file %s: %s", path.c_str(), strerror(errno));
        return false;
    }

    return true;
}

auto Sandbox::SaveNetworkSetting(Errors &error) -> bool
{
    int nret = -1;
    const std::string path = GetNetworkSettingsPath();
    WriteGuard<RWMutex> lock(m_stateMutex);

    nret = util_atomic_write_file(path.c_str(), m_networkSettings.c_str(), m_networkSettings.length(), CONFIG_FILE_MODE,
                                  false);
    if (nret != 0) {
        ERROR("Failed to write file %s: %s", path.c_str(), strerror(errno));
        error.Errorf("Failed to write file %s: %s", path.c_str(), strerror(errno));
        return false;
    }

    return true;
}

auto Sandbox::GenerateSandboxMetadataJson(sandbox_metadata *metadata) -> std::string
{
    __isula_auto_free parser_error error;
    std::string ret;
    __isula_auto_free char *metadata_json = NULL;
    metadata_json = sandbox_metadata_generate_json(metadata, NULL, &(error));
    if (metadata_json == NULL || strlen(metadata_json) == 0) {
        return ret;
    }
    ret = std::string(metadata_json);
    return ret;
}

auto Sandbox::SaveMetadata(Errors &error) -> bool
{
    sandbox_metadata metadata = { 0 };
    int nret = -1;
    const std::string path = GetMetadataJsonPath();
    std::string metadataJson;

    FillSandboxMetadata(&metadata, error);
    if (!error.Empty()) {
        return false;
    }

    metadataJson = GenerateSandboxMetadataJson(&metadata);
    if (metadataJson.length() == 0) {
        error.Errorf("Failed to get sandbox metadata json for sandbox: '%s'", m_id.c_str());
        return false;
    }

    nret = util_atomic_write_file(path.c_str(), metadataJson.c_str(), metadataJson.length(), CONFIG_FILE_MODE, false);
    if (nret != 0) {
        error.Errorf("Failed to write file %s: %s", path.c_str(), strerror(errno));
        return false;
    }
    return true;
}

auto Sandbox::ParseSandboxStateFile() ->std::unique_ptr<CStructWrapper<sandbox_state>>
{
    __isula_auto_free parser_error err = NULL;
    const std::string path = GetStatePath();
    sandbox_state *state = NULL;
    std::unique_ptr<CStructWrapper<sandbox_state>> ret;

    state = sandbox_state_parse_file(path.c_str(), NULL, &err);
    if (state == NULL) {
        return ret;
    }
    ret = std::unique_ptr<CStructWrapper<sandbox_state>>(new CStructWrapper<sandbox_state>(state, free_sandbox_state));
    return ret;
}

auto Sandbox::LoadState(Errors &error) -> bool
{
    std::unique_ptr<CStructWrapper<sandbox_state>> state;

    state = ParseSandboxStateFile();
    if (state == nullptr) {
        error.Errorf("Failed to parse sandbox state file");
        return false;
    }

    // the sandbox instance has not been loaded and will not be used,
    // and the state does not need to be locked
    m_state.pid = state->get()->pid;
    m_state.exitedAt = state->get()->exited_at;
    m_state.createdAt = state->get()->created_at;
    m_state.updatedAt = state->get()->updated_at;
    m_state.status = (SandboxStatus)state->get()->status;

    return true;
}

auto Sandbox::ParseSandboxMetadataFile() -> std::unique_ptr<CStructWrapper<sandbox_metadata>>
{
    __isula_auto_free parser_error err = NULL;
    const std::string path = GetStatePath();
    sandbox_metadata *metadata = NULL;
    std::unique_ptr<CStructWrapper<sandbox_metadata>> ret;

    metadata = sandbox_metadata_parse_file(path.c_str(), NULL, &err);
    if (metadata == NULL) {
        return ret;
    }
    ret = std::unique_ptr<CStructWrapper<sandbox_metadata>>(new CStructWrapper<sandbox_metadata>(metadata,
                                                                                                 free_sandbox_metadata));
    return ret;
}

auto Sandbox::isValidMetadata(std::unique_ptr<CStructWrapper<sandbox_metadata>> &metadata) -> bool
{
    bool unvalid = metadata->get()->id == nullptr || metadata->get()->name == nullptr ||
                   metadata->get()->runtime_info->runtime == nullptr || metadata->get()->runtime_info->sandboxer == nullptr ||
                   metadata->get()->runtime_info->runtime_handler == nullptr || metadata->get()->net_mode == nullptr ||
                   metadata->get()->task_address == nullptr || metadata->get()->net_ns_path == nullptr;
    if (unvalid) {
        return false;
    }
    return true;
}

auto Sandbox::LoadMetadata(Errors &error) -> bool
{
    bool ret = false;
    runtime::v1::PodSandboxConfig config;
    std::unique_ptr<CStructWrapper<sandbox_metadata>> metadata;

    metadata = ParseSandboxMetadataFile();
    if (metadata == nullptr) {
        error.Errorf("Failed to parse sandbox metadata file for sandbox: '%s'", m_id.c_str());
        return false;
    }

    if (!isValidMetadata(metadata)) {
        error.Errorf("Failed to load corrupt sandbox metadata file for sandbox: '%s'", m_id.c_str());
        return false;
    }

    m_name = std::string(metadata->get()->name);
    m_runtimeInfo.runtime = std::string(metadata->get()->runtime_info->runtime);
    m_runtimeInfo.sandboxer = std::string(metadata->get()->runtime_info->sandboxer);
    m_runtimeInfo.runtimeHandler = std::string(metadata->get()->runtime_info->runtime_handler);
    m_netMode = std::string(metadata->get()->net_mode);
    m_networkReady = metadata->get()->network_ready;
    m_taskAddress = std::string(metadata->get()->task_address);
    m_netNsPath = std::string(metadata->get()->net_ns_path);
    Transform::CharArrayToStringVector((const char **)metadata->get()->containers,
                                       util_array_len((const char **)metadata->get()->containers), m_containers);

    ret = google::protobuf::util::JsonStringToMessage(metadata->get()->sandbox_config_json, &config).ok();
    if (!ret) {
        error.Errorf("Failed to parse sandbox config json for sandbox: '%s'", m_id.c_str());
        return false;
    }
    m_sandboxConfig = std::make_shared<runtime::v1::PodSandboxConfig>(config);

    return true;
}

auto Sandbox::LoadNetworkSetting(Errors &error) -> bool
{
    __isula_auto_free char *settings = NULL;
    const std::string path = GetNetworkSettingsPath();

    settings = util_read_content_from_file(path.c_str());
    if (settings == NULL || strlen(settings) == 0 || strcmp(settings, "\n") == 0) {
        error.Errorf("%s: failed to read file %s", m_id.c_str(), path.c_str());
        return false;
    }

    m_networkSettings = std::string(settings);
    return true;
}

void Sandbox::SetSandboxConfig(const runtime::v1::PodSandboxConfig &config)
{
    m_sandboxConfig = std::make_shared<runtime::v1::PodSandboxConfig>(config);
}

void Sandbox::SetNetworkSettings(const std::string &settings, Errors &error)
{
    m_stateMutex.wrlock();
    m_networkSettings = settings;
    m_stateMutex.unlock();
    if (!SaveNetworkSetting(error)) {
        ERROR("Failed to save networkSettings for %s", m_id.c_str());
    }
}

auto Sandbox::GetTaskAddress() -> const std::string &
{
    return m_taskAddress;
}

auto Sandbox::GetHostnamePath() -> std::string
{
    return m_rootdir + std::string("/hostname");
}

auto Sandbox::GetHostsPath() -> std::string
{
    return m_rootdir + std::string("/hosts");
}

auto Sandbox::GetMetadataJsonPath() -> std::string
{
    return m_rootdir + std::string("/") + SANDBOX_METADATA_JSON;
}

auto Sandbox::GetStatePath() -> std::string
{
    return m_statedir + std::string("/") + SANDBOX_STATE_JSON;
}

auto Sandbox::GetNetworkSettingsPath() -> std::string
{
    return m_rootdir + std::string("/") + NETWORK_SETTINGS_JSON;
}

void Sandbox::FillSandboxMetadata(sandbox_metadata* metadata, Errors &error)
{
    std::string jsonStr;
    metadata->id = util_strdup_s(m_id.c_str());
    metadata->name = util_strdup_s(m_name.c_str());
    metadata->runtime_info->runtime = util_strdup_s(m_runtimeInfo.runtime.c_str());
    metadata->runtime_info->sandboxer = util_strdup_s(m_runtimeInfo.sandboxer.c_str());
    metadata->runtime_info->runtime_handler = util_strdup_s(m_runtimeInfo.runtimeHandler.c_str());
    metadata->net_mode = util_strdup_s(m_netMode.c_str());
    metadata->network_ready = m_networkReady;
    metadata->task_address = util_strdup_s(m_taskAddress.c_str());
    metadata->net_ns_path = util_strdup_s(m_netNsPath.c_str());

    metadata->containers = Transform::StringVectorToCharArray(m_containers);

    google::protobuf::util::MessageToJsonString(*m_sandboxConfig.get(), &jsonStr);
    if (jsonStr.length() == 0) {
        error.Errorf("Failed to get sandbox config json for sandbox: '%s'", m_id.c_str());
        ERROR("Failed to get sandbox config json for sandbox: '%s'", m_id.c_str());
    }

    metadata->sandbox_config_json = util_strdup_s(jsonStr.c_str());
}
}