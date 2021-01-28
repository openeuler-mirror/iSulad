/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide cni network plugin function definition
 ********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_CNI_NETWORK_PLUGIN_H
#define DAEMON_ENTRY_CRI_CNI_NETWORK_PLUGIN_H

#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <isula_libutils/container_inspect.h>

#include "cri_runtime_service.h"
#include "errors.h"
#include "network_plugin.h"
#include "utils.h"
#include "isula_libutils/container_inspect.h"
#include "network_api.h"

namespace Network {
#define UNUSED(x) ((void)(x))
static const std::string CNI_PLUGIN_NAME { "cni" };
static const std::string DEFAULT_NET_DIR { "/etc/cni/net.d" };
static const std::string DEFAULT_CNI_DIR { "/opt/cni/bin" };

class CniNetworkPlugin : public NetworkPlugin {
public:
    CniNetworkPlugin(std::vector<std::string> &binDirs, const std::string &confDir,
                     const std::string &podCidr = "");

    virtual ~CniNetworkPlugin();

    void Init(const std::string &hairpinMode, const std::string &nonMasqueradeCIDR,
              int mtu, Errors &error) override;

    void Event(const std::string &name, std::map<std::string, std::string> &details) override;

    auto Name() const -> const std::string &override;

    auto Capabilities() -> std::map<int, bool> * override;

    void SetUpPod(const std::string &ns, const std::string &name,
                  const std::string &interfaceName, const std::string &podSandboxID,
                  const std::map<std::string, std::string> &annotations,
                  const std::map<std::string, std::string> &options, std::string &network_settings_json, Errors &error) override;

    void TearDownPod(const std::string &ns, const std::string &name,
                     const std::string &interfaceName, const std::string &podSandboxID,
                     const std::map<std::string, std::string> &annotations, Errors &error) override;

    void GetPodNetworkStatus(const std::string &ns, const std::string &name, const std::string &interfaceName,
                             const std::string &podSandboxID, PodNetworkStatus &status, Errors &error) override;

    void Status(Errors &error) override;

private:
    auto GetNetNS(const std::string &podSandboxID, Errors &err) -> std::string;
    auto GetNetworkSettingsJson(const std::string &podSandboxID, const std::string netnsPath,
                                network_api_result_list *result, Errors &err) -> std::string;

private:
    virtual void PlatformInit(Errors &error);
    virtual void SyncNetworkConfig();

    virtual void CheckInitialized(Errors &error);

    void RLockNetworkMap(Errors &error);
    void WLockNetworkMap(Errors &error);
    void UnlockNetworkMap(Errors &error);

    void SetPodCidr(const std::string &podCidr);
    void UpdateDefaultNetwork();

    NoopNetworkPlugin m_noop;

    std::string m_nsenterPath;
    std::string m_confDir;
    std::vector<std::string> m_binDirs;
    std::string m_podCidr;

    pthread_rwlock_t m_netsLock = PTHREAD_RWLOCK_INITIALIZER;

    std::thread m_syncThread;
    bool m_needFinish;
};

} // namespace Network

#endif
