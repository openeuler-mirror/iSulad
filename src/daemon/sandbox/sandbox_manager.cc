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
#include "namespace.h"
#include "utils.h"

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

    if (netMode.empty()) {
        ERROR("Empty netMode for creating sandbox %s", name.c_str());
        error.Errorf("Empty netMode for creating sandbox %s", name.c_str());
        return nullptr;
    }

    if (netMode == SHARE_NAMESPACE_CNI && netNsPath.empty()) {
        ERROR("Empty netNsPath for create sandbox %s when net Mode is cni", name.c_str());
        error.Errorf("Empty netNsPath for create sandbox %s when net Mode is cni", name.c_str());
        return nullptr;
    }

    auto controller = ControllerManager::GetInstance()->GetController(info.sandboxer);
    if (controller == nullptr) {
        ERROR("Invalid sandboxer name: %s", info.sandboxer.c_str());
        error.Errorf("Invalid sandboxer name: %s", info.sandboxer.c_str());
        return nullptr;
    }

    std::shared_ptr<Sandbox> old = GetSandbox(name);
    if (old != nullptr) {
        ERROR("Conflict. The name \"%s\" is already in use by sandbox %s. "
              "You have to remove that sandbox to be able to reuse that name.",
              name.c_str(), old->GetId().c_str());
        error.Errorf("Conflict. The name \"%s\" is already in use by sandbox %s. "
                     "You have to remove that sandbox to be able to reuse that name.",
                     name.c_str(), old->GetId().c_str());
        return nullptr;
    }

    if (!IDNameManagerNewEntry(id, name)) {
        error.Errorf("Failed add sandbox %s to id name manager", name.c_str());
        ERROR("Failed add sandbox %s to id name manager", name.c_str());
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

    // If failed after this in this function, CleanupSandboxDirs() should be called
    sandbox->PrepareSandboxDirs(error);
    if (error.NotEmpty()) {
        ERROR("Failed to prepare sandbox dirs: %s", error.GetCMessage());
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

// TODO: if the sandbox metadata is lost, do I need to clean up the sandbox and its containers?
// if the metadata of the pause container is lost or the sandbox in kuasar is abnormal,
// the sandbox will fail to load because it cannot updatestatus, and isulad cannot manage the sandbox
auto SandboxManager::RestoreSandboxes(Errors &error) -> bool
{
    std::vector<std::string> subdir;

    if (!ListAllSandboxdir(subdir)) {
        error.SetError("Failed to list sandboxes");
        return false;
    }

    for (auto &id : subdir) {
        std::shared_ptr<Sandbox> sandbox = LoadSandbox(id);
        if (sandbox != nullptr) {
            SaveSandboxToStore(id, sandbox);
            continue;
        }
        // If loading fails, delete the residual directory
        CleanInValidSandboxDir(id);
    }

    return true;
}

void SandboxManager::ListAllSandboxes(const runtime::v1::PodSandboxFilter &filters,
                                      std::vector<std::shared_ptr<Sandbox>> &sandboxes)
{
    // 1. get all sandboxes
    std::vector<std::shared_ptr<Sandbox>> allsandboxes;
    StoreGetAll(allsandboxes);
    // 2. filter sandboxes by filter
    for (const auto &sandbox : allsandboxes) {
        // (1) filter by id
        if (!filters.id().empty() && sandbox->GetId().compare(0, filters.id().length(), filters.id()) != 0) {
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
        if (filters.label_selector_size() == 0) {
            sandboxes.push_back(sandbox);
            continue;
        }

        if (sandbox->GetMutableSandboxConfig() == nullptr) {
            continue;
        }

        bool match = true;
        auto labels = sandbox->GetMutableSandboxConfig()->labels();
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
    return id_name_manager_remove_entry(id.c_str(), name.c_str());
}

// Save the id and name of the sandbox to the map of the id_name_manager module
bool SandboxManager::IDNameManagerNewEntry(std::string &id, const std::string &name)
{
    bool ret = false;
    if (id.empty()) {
        __isula_auto_free char *tmpId = NULL;
        ret = id_name_manager_add_entry_with_new_id(name.c_str(), &tmpId);
        if (tmpId != NULL) {
            id = tmpId;
        }
    } else {
        ret = id_name_manager_add_entry_with_existing_id(id.c_str(), name.c_str());
    }
    if (!ret) {
        ERROR("Failed to add a new entry to id_name_manager");
        return false;
    }
    return true;
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

auto SandboxManager::GetSandbox(const std::string &idOrName) -> std::shared_ptr<Sandbox>
{
    std::shared_ptr<Sandbox> sandbox = nullptr;

    if (!util_valid_container_id_or_name(idOrName.c_str())) {
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

    // Error message not set here since it might make sense: 1. after deleted 2. before created
    return nullptr;
}

auto SandboxManager::DeleteSandbox(const std::string &idOrName, Errors &error) -> bool
{
    if (!util_valid_container_id_or_name(idOrName.c_str())) {
        ERROR("Invalid sandbox name: %s", idOrName.c_str());
        error.Errorf("Invalid sandbox name: %s", idOrName.c_str());
        return false;
    }

    std::shared_ptr<Sandbox> sandbox = GetSandbox(idOrName);
    if (sandbox == nullptr) {
        ERROR("Failed to find sandbox %s", idOrName.c_str());
        error.Errorf("Failed to find sandbox %s", idOrName.c_str());
        return false;
    }

    // TODO: Might fail here. Consider unified cleaning of residual resources in the future.
    sandbox->CleanupSandboxDirs();

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

    // If m_rootdir does not exist, an error still needs to be reported,
    // because it is not known whether the folder is missing or the folder has never been created
    nret = util_list_all_subdir(m_rootdir.c_str(), &subdir);
    if (nret != 0) {
        return false;
    }

    Transform::CharArrayToStringVector((const char **)subdir, util_array_len((const char **)subdir), allSubdir);
    util_free_array(subdir);
    return true;
}

auto SandboxManager::LoadSandbox(std::string &id) -> std::shared_ptr<Sandbox>
{
    std::shared_ptr<Sandbox> sandbox = nullptr;

    if (!util_valid_container_id_or_name(id.c_str())) {
        ERROR("Invalid sandbox name: %s", id.c_str());
        return nullptr;
    }

    sandbox = std::shared_ptr<Sandbox>(new Sandbox(id, m_rootdir, m_statedir));
    if (sandbox == nullptr) {
        ERROR("Failed to malloc for sandboxes: %s", id.c_str());
        return nullptr;
    }

    Errors tmpError;

    if (!sandbox->Load(tmpError)) {
        ERROR("Failed to load subdir:%s", id.c_str());
        return nullptr;
    }

    if (!IDNameManagerNewEntry(id, sandbox->GetName())) {
        ERROR("Failed add sandbox %s to id name manager", id.c_str());
        return nullptr;
    }

    return sandbox;
}

void SandboxManager::CleanInValidSandboxDir(const std::string &id)
{
    std::string rootDir = m_rootdir + "/" + id;
    std::string stateDir = m_statedir + "/" + id;

    if (util_recursive_rmdir(stateDir.c_str(), 0) != 0) {
        ERROR("Failed to delete sandbox's state directory %s", stateDir.c_str());
    }

    if (!util_deal_with_mount_info(util_umount_residual_shm, rootDir.c_str())) {
        ERROR("Failed to clean sandbox's mounts: %s", id.c_str());
    }

    if (util_recursive_rmdir(rootDir.c_str(), 0) != 0) {
        ERROR("Failed to delete sandbox's root directory %s", rootDir.c_str());
    }
}

}