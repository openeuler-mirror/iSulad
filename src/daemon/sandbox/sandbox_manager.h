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

#ifndef DAEMON_SANDBOX_SANDBOX_MANAGER_H
#define DAEMON_SANDBOX_SANDBOX_MANAGER_H

#include <string>
#include <map>
#include <mutex>

#include "api_v1.grpc.pb.h"
#include "sandbox.h"
#include "read_write_lock.h"
#include "error.h"

namespace sandbox {

class SandboxManager {
public:
    // Singleton
    static SandboxManager *GetInstance() noexcept;

    // initialize value
    auto Init(Errors &error) -> bool;

    // Create meanningful sandbox instance
    auto CreateSandbox(const std::string &name, RuntimeInfo &info, std::string &netNsPath, std::string &netMode,
                       const runtime::v1::PodSandboxConfig &sandboxConfig, Errors &error) -> std::shared_ptr<Sandbox>;

    auto GetSandbox(const std::string &idOrName, Errors &error) -> std::shared_ptr<Sandbox>;
    auto DeleteSandbox(const std::string &idOrName, Errors &error) -> bool;

    auto RestoreSandboxes(Errors &error) -> bool;
    // list all sandboxes by filter
    void ListAllSandboxes(runtime::v1::PodSandboxFilter &filters, std::vector<std::shared_ptr<Sandbox>> &sandboxes);
private:
    SandboxManager() = default;
    SandboxManager(const SandboxManager &other) = delete;
    SandboxManager &operator=(const SandboxManager &) = delete;
    virtual ~SandboxManager() = default;

    void StoreAdd(const std::string &id, std::shared_ptr<Sandbox> sandbox);
    void StoreRemove(const std::string &id);
    void StoreGetAll(std::vector<std::shared_ptr<Sandbox>> &sandboxes);
    auto StoreGetById(const std::string &id) -> std::shared_ptr<Sandbox>;
    auto StoreGetByName(const std::string &name) -> std::shared_ptr<Sandbox>;
    auto StoreGetByPrefix(const std::string &prefix) -> std::shared_ptr<Sandbox>;

    void NameIndexAdd(const std::string &name, const std::string &id);
    void NameIndexRemove(const std::string &name);
    auto NameIndexGet(const std::string &name) -> std::string;
    auto NameIndexGetAll(void) -> std::map<std::string, std::string>;

    auto IDNameManagerRemoveEntry(const std::string &id, const std::string &name) -> bool;
    auto IDNameManagerNewEntry(std::string &id, const std::string &name, bool generateId, Errors &error) -> bool;

    void SaveSandboxToStore(const std::string &id, std::shared_ptr<Sandbox> sandbox);
    void DeleteSandboxFromStore(const std::string &id, const std::string &name);

    auto GetSandboxRootpath() -> std::string;
    auto GetSandboxStatepath() -> std::string;
    void TryGenerateId(std::string &id);
    bool ListAllSandboxdir(std::vector<std::string> &allSubdir);

private:
    static std::atomic<SandboxManager *> m_instance;
    std::string m_rootdir;
    std::string m_statedir;
    // id --> sandbox map
    std::map<std::string, std::shared_ptr<Sandbox>> m_storeMap;
    // name --> id map
    std::map<std::string, std::string> m_nameIndexMap;
    // Read-write locks can only be used if the C++ standard is greater than 17
    RWMutex m_storeRWMutex;
    RWMutex m_indexRWMutex;
};

} // namespace sandbox


#endif // DAEMON_SANDBOX_SANDBOX_MANAGER_H