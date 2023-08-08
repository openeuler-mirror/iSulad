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
 * Description: provide sandbox manager class definition
 *********************************************************************************/

#include "sandbox_manager.h"

#include <string>
#include <map>
#include <mutex>

#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/log.h>

#include "sandbox.h"
#include "isulad_config.h"
#include "utils_verify.h"
#include "utils_file.h"
#include "cstruct_wrapper.h"
#include "transform.h"
#include "id_name_manager.h"

namespace sandbox {
std::atomic<SandboxManager *> SandboxManager::m_instance;

SandboxManager *SandboxManager::GetInstance() noexcept
{
    static std::once_flag flag;

    std::call_once(flag, [] { m_instance = new SandboxManager; });

    return m_instance;
}

auto SandboxManager::Init(Errors &error) -> bool
{
    m_rootdir = GetSandboxRootpath();
    if (m_rootdir.length() == 0) {
        error.SetError("Failed to get sandbox rootdir");
        return false;
    }

    m_statedir = GetSandboxStatepath();
    if (m_statedir.length() == 0) {
        error.SetError("Failed to get sandbox statedir");
        return false;
    }
    return true;
}

void SandboxManager::TryGenerateId(std::string &id)
{
    __isula_auto_free char *newId = NULL;
    newId = get_new_id();
    if (newId == NULL) {
        return;
    }
    id = std::string(newId);
}

auto SandboxManager::CreateSandbox(const std::string &name, RuntimeInfo &info, std::string &netNsPath,
                                   std::string &netMode, const runtime::v1::PodSandboxConfig &sandboxConfig, Errors &error) -> std::shared_ptr<Sandbox>
{
    std::shared_ptr<Sandbox> sandbox;
    std::string id;

    if (!util_valid_container_id_or_name(name.c_str())) {
        ERROR("Invalid sandbox name: %s", name.c_str());
        error.Errorf("Invalid sandbox name: %s", name.c_str());
        return nullptr;
    }

    if (netNsPath.empty() || netMode.empty()) {
        ERROR("Invalid params for create sandbox %s", name.c_str());
        error.Errorf("Invalid params for create sandbox %s", name.c_str());
        return nullptr;
    }

    auto controller = ControllerManager::GetInstance()->GetController(info.sandboxer);
    if (controller == nullptr) {
        ERROR("Invalid sandboxer name: %s", info.sandboxer.c_str());
        error.Errorf("Invalid sandboxer name: %s", info.sandboxer.c_str());
        return nullptr;
    }

    std::shared_ptr<Sandbox> old = GetSandbox(name, error);
    if (old != nullptr) {
        ERROR("Conflict. The name \"%s\" is already in use by sandbox %s. "
              "You have to remove that sandbox to be able to reuse that name.",
              name.c_str(), old->GetId().c_str());
        error.Errorf("Conflict. The name \"%s\" is already in use by sandbox %s. "
                     "You have to remove that sandbox to be able to reuse that name.",
                     name.c_str(), old->GetId().c_str());
        return nullptr;
    }

    if (!IDNameManagerNewEntry(id, name, true, error)) {
        ERROR("Failed add sandbox %s to id name manager", id.c_str());
        return nullptr;
    }

    sandbox = std::shared_ptr<Sandbox>(new Sandbox(id, m_rootdir, m_statedir, name, info, netMode, netNsPath,
                                                   sandboxConfig));
    if (sandbox == nullptr) {
        ERROR("Failed to malloc for sandbox: %s", name.c_str());
        error.Errorf("Failed to malloc for sandbox: %s", name.c_str());
        goto out;
    }

    sandbox->SetController(controller);

    if (!sandbox->Create(error)) {
        error.AppendError("Failed to create sandbox.");
        ERROR("Failed to create sandbox: %s", name.c_str());
        goto out;
    }

    SaveSandboxToStore(id, sandbox);

    return sandbox;

out:
    // delete unexited id or name will generate WARN img.
    if (!IDNameManagerRemoveEntry(id, name)) {
        WARN("Failed to remove %s form id name manager", name.c_str());
    }
    return nullptr;
}

auto SandboxManager::RestoreSandboxes(Errors &error) -> bool
{
    std::vector<std::string> subdir;

    if (!ListAllSandboxdir(subdir)) {
        error.SetError("Failed to list sandboxes");
        return false;
    }

    for (auto &id : subdir) {
        if (!util_valid_container_id_or_name(id.c_str())) {
            ERROR("Invalid sandbox name: %s", id.c_str());
            continue;
        }

        std::shared_ptr<Sandbox> sandbox = std::shared_ptr<Sandbox>(new Sandbox(id, m_rootdir, m_statedir));
        if (sandbox == nullptr) {
            ERROR("Failed to malloc for sandboxes: %s", id.c_str());
            continue;
        }

        if (!sandbox->Load(error)) {
            ERROR("Failed to load subdir:%s", id.c_str());
            continue;
        }

        if (!IDNameManagerNewEntry(id, sandbox->GetName(), false, error)) {
            ERROR("Failed add sandbox %s to id name manager", id.c_str());
            continue;
        }

        SaveSandboxToStore(id, sandbox);
    }

    return true;
}

void SandboxManager::ListAllSandboxes(runtime::v1::PodSandboxFilter &filters,
                                      std::vector<std::shared_ptr<Sandbox>> &sandboxes)
{
    // 1. get all sandboxes
    std::vector<std::shared_ptr<Sandbox>> allsandboxes;
    StoreGetAll(allsandboxes);
    // 2. filter sandboxes by filter
    for (const auto &sandbox : allsandboxes) {
        // (1) filter by id
        if (!filters.id().empty() && filters.id() != sandbox->GetId()) {
            continue;
        }
        // (2) filter by state
        if (filters.has_state()) {
            if (filters.state().state() == runtime::v1::SANDBOX_READY && !sandbox->IsReady()) {
                continue;
            }
            if (filters.state().state() == runtime::v1::SANDBOX_NOTREADY && sandbox->IsReady()) {
                continue;
            }
        }
        // (3) filter by labels
        bool match = true;
        auto labels = sandbox->GetSandboxConfig()->labels();
        for (auto &iter : filters.label_selector()) {
            auto val = labels.find(iter.first);
            if (val == labels.end() || val->second != iter.second) {
                match = false;
                break;
            }
        }
        if (match) {
            sandboxes.push_back(sandbox);
        }
    }
}

// Delete the id and name of the sandbox from the map of the id_name_manager module
bool SandboxManager::IDNameManagerRemoveEntry(const std::string &id, const std::string &name)
{
    bool ret = true;
    if (!try_remove_id(id.c_str())) {
        ret = false;
    }

    if (!try_remove_name(name.c_str())) {
        ret = false;
    }

    return ret;
}

// Save the id and name of the sandbox to the map of the id_name_manager module
bool SandboxManager::IDNameManagerNewEntry(std::string &id, const std::string &name, bool generateId, Errors &error)
{
    if (generateId) {
        TryGenerateId(id);
        if (id.empty()) {
            error.Errorf("Failed to generate id for sandbox: %s", name.c_str());
            return false;
        }
    } else {
        if (!try_add_id(id.c_str())) {
            error.Errorf("Failed add %s to id map", id.c_str());
            return false;
        }
    }

    if (!try_add_name(name.c_str())) {
        error.Errorf("Failed to add %s to name map", name.c_str());
        goto error_load;
    }

    return true;

error_load:
    if (!IDNameManagerRemoveEntry(id, name)) {
        WARN("Failed to remove %s form id name manager", name.c_str());
    }
    return false;
}

// Save sandbox to the map of the sandbox manager module
void SandboxManager::SaveSandboxToStore(const std::string &id, std::shared_ptr<Sandbox> sandbox)
{
    NameIndexAdd(sandbox->GetName(), id);
    StoreAdd(id, sandbox);
}

// Delete sandbox from the map of the sandbox manager module
void SandboxManager::DeleteSandboxFromStore(const std::string &id, const std::string &name)
{
    NameIndexRemove(name);
    StoreRemove(id);
}

void SandboxManager::StoreAdd(const std::string &id, std::shared_ptr<Sandbox> sandbox)
{
    WriteGuard<RWMutex> lock(m_storeRWMutex);
    m_storeMap[id] = sandbox;
}

void SandboxManager::StoreRemove(const std::string &id)
{
    WriteGuard<RWMutex> lock(m_storeRWMutex);
    m_storeMap.erase(id);
}

auto SandboxManager::GetSandbox(const std::string &idOrName, Errors &error) -> std::shared_ptr<Sandbox>
{
    std::shared_ptr<Sandbox> sandbox = nullptr;

    if (!util_valid_container_id_or_name(idOrName.c_str())) {
        error.Errorf("Invalid sandbox name: %s", idOrName.c_str());
        ERROR("Invalid sandbox name: %s", idOrName.c_str());
        return nullptr;
    }

    // A full sandbox ID, which do an exact match a sandbox in daemon's list
    sandbox = StoreGetById(idOrName);
    if (sandbox != nullptr) {
        return sandbox;
    }

    // A sandbox name, which will only do an exact match via the StoreGetByNames() function
    sandbox = StoreGetByName(idOrName);
    if (sandbox != nullptr) {
        return sandbox;
    }

    // A partial sandbox ID prefix
    sandbox = StoreGetByPrefix(idOrName);
    if (sandbox != nullptr) {
        return sandbox;
    }

    return nullptr;
}

auto SandboxManager::DeleteSandbox(const std::string &idOrName, Errors &error) -> bool
{
    if (!util_valid_container_id_or_name(idOrName.c_str())) {
        ERROR("Invalid sandbox name: %s", idOrName.c_str());
        error.Errorf("Invalid sandbox name: %s", idOrName.c_str());
        return false;
    }

    std::shared_ptr<Sandbox> sandbox = GetSandbox(idOrName, error);
    if (sandbox == nullptr) {
        ERROR("Failed to find sandbox %s", idOrName.c_str());
        error.AppendError("Failed to find sandbox.");
        return false;
    }

    if (!sandbox->Remove(error)) {
        ERROR("Failed to do delete sandbox %s", idOrName.c_str());
        return false;
    }

    auto id = sandbox->GetId();
    auto name = sandbox->GetName();

    if (!IDNameManagerRemoveEntry(id, name)) {
        ERROR("Failed to remove sandbox form id name manager: %s", name.c_str());
    }

    DeleteSandboxFromStore(id, name);

    return true;
}

void SandboxManager::StoreGetAll(std::vector<std::shared_ptr<Sandbox>> &sandboxes)
{
    ReadGuard<RWMutex> lock(m_storeRWMutex);
    for (const auto &pair : m_storeMap) {
        sandboxes.push_back(pair.second);
    }
}

auto SandboxManager::StoreGetById(const std::string &id) -> std::shared_ptr<Sandbox>
{
    ReadGuard<RWMutex> lock(m_storeRWMutex);
    auto iter = m_storeMap.find(id);
    if (iter != m_storeMap.end()) {
        return iter->second;
    }
    return nullptr;
}

auto SandboxManager::StoreGetByName(const std::string &name) -> std::shared_ptr<Sandbox>
{
    std::string id;

    id = NameIndexGet(name);
    if (id.length() == 0) {
        WARN("Could not find entity for %s", name.c_str());
        return nullptr;
    }

    return StoreGetById(id);
}

auto SandboxManager::StoreGetByPrefix(const std::string &prefix) -> std::shared_ptr<Sandbox>
{
    std::shared_ptr<Sandbox> sandbox = nullptr;
    ReadGuard<RWMutex> lock(m_storeRWMutex);

    for (auto it = m_storeMap.begin(); it != m_storeMap.end(); it++) {
        if (it->first.compare(0, prefix.length(), prefix, 0, prefix.length()) == 0) {
            if (sandbox != nullptr) {
                WARN("Multiple IDs found with provided prefix: %s", prefix.c_str());
                return nullptr;
            } else {
                sandbox = it->second;
            }
        }
    }

    return sandbox;
}

void SandboxManager::NameIndexRemove(const std::string &name)
{
    WriteGuard<RWMutex> lock(m_indexRWMutex);
    m_nameIndexMap.erase(name);
}

void SandboxManager::NameIndexAdd(const std::string &name, const std::string &id)
{
    WriteGuard<RWMutex> lock(m_indexRWMutex);
    m_nameIndexMap[name] = id;
}

auto SandboxManager::NameIndexGet(const std::string &name) -> std::string
{
    ReadGuard<RWMutex> lock(m_indexRWMutex);
    auto iter = m_nameIndexMap.find(name);
    if (iter != m_nameIndexMap.end()) {
        return iter->second;
    }
    return std::string();
}

auto SandboxManager::NameIndexGetAll(void) -> std::map<std::string, std::string>
{
    ReadGuard<RWMutex> lock(m_indexRWMutex);
    return m_nameIndexMap;
}

auto SandboxManager::GetSandboxRootpath() -> std::string
{
    __isula_auto_free char *root_path = NULL;
    std::string ret;

    root_path = conf_get_sandbox_rootpath();
    if (root_path == NULL) {
        return ret;
    }
    ret = std::string(root_path);
    return ret;
}

auto SandboxManager::GetSandboxStatepath() -> std::string
{
    __isula_auto_free char *state_path = NULL;
    std::string ret;

    state_path = conf_get_sandbox_statepath();
    if (state_path == NULL) {
        return ret;
    }
    ret = std::string(state_path);
    return ret;
}

bool SandboxManager::ListAllSandboxdir(std::vector<std::string> &allSubdir)
{
    char **subdir = NULL;
    int nret = -1;

    nret = util_list_all_subdir(m_rootdir.c_str(), &subdir);
    if (nret != 0) {
        return false;
    }

    Transform::CharArrayToStringVector((const char **)subdir, util_array_len((const char **)subdir), allSubdir);
    util_free_array(subdir);
    return true;
}

}