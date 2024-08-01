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
 * Create: 2024-06-29
 * Description: provide nri result definition
 *********************************************************************************/

#ifndef DAEMON_NRI_PLUGIN_NRI_RESULT_H
#define DAEMON_NRI_PLUGIN_NRI_RESULT_H

#include <map>

#include <isula_libutils/nri_create_container_request.h>
#include <isula_libutils/nri_create_container_response.h>
#include <isula_libutils/nri_update_container_request.h>
#include <isula_libutils/nri_update_container_response.h>
#include <isula_libutils/nri_container_update.h>
#include <isula_libutils/nri_mount.h>

#include "api_v1.pb.h"
#include "nri_helpers.h"
#include "nri_utils.h"

using EventMask = std::int32_t;

const EventMask ValidEvents = (1 << (LAST - 1)) - 1;

struct owners {
    std::map<std::string, std::string> annotations;
    std::map<std::string, std::string> mounts;
    std::map<std::string, std::string> devices;
    std::map<std::string, std::string> env;
    std::string memLimit;
    std::string memReservation;
    std::string memSwapLimit;
    std::string memKernelLimit;
    std::string memTCPLimit;
    std::string memSwappiness;
    std::string memDisableOomKiller;
    std::string memUseHierarchy;
    std::string cpuShares;
    std::string cpuQuota;
    std::string cpuPeriod;
    std::string cpuRealtimeRuntime;
    std::string cpuRealtimePeriod;
    std::string cpusetCpus;
    std::string cpusetMems;
    std::map<std::string, std::string> hugepageLimits;
    std::string blockioClass;
    std::string rdtClass;
    std::map<std::string, std::string> unified;
    std::string cgroupsPath;
    std::map<std::string, std::string> rlimits;
};

struct resultReply {
    nri_container_adjustment* adjust;
    std::vector<nri_container_update*> update;
};

using resultOwners = std::map<std::string, owners>;

class pluginResult {
public:
    pluginResult() = default;

    ~pluginResult() = default;

    auto InitByConId(std::string conId) -> bool;
    auto InitByUpdateReq(nri_update_container_request *req) -> bool;

    auto GetReplyUpdate() -> std::vector<nri_container_update *>;
    auto GetReplyAdjust() -> nri_container_adjustment *;

    auto Apply(int32_t event, nri_container_adjustment *adjust, nri_container_update **update, size_t update_len,
               const std::string &plugin) -> bool;
    auto Update(nri_container_update **updates, size_t update_len, const std::string &plugin) -> bool;

private:
    auto GetContainerUpdate(nri_container_update *update, const std::string &plugin, nri_container_update **out) -> bool;
    auto UpdateResources(nri_container_update *reply, nri_container_update *u, const std::string &plugin) -> bool;

    auto InitReply(void) -> bool;

    auto Adjust(nri_container_adjustment *adjust, const std::string &plugin) -> bool;

    auto AdjustAnnotations(json_map_string_string *annos, const std::string &plugin) -> bool;
    auto AdjustMounts(nri_mount **mounts, size_t mounts_size, const std::string &plugin) -> bool;
    auto AdjustEnv(nri_key_value **envs, size_t envs_size, const std::string &plugin) -> bool;
    auto AdjustHooks(nri_hooks *hooks, const std::string &plugin) -> bool;
    auto AdjustDevices(nri_linux_device **devices, size_t devices_size, const std::string &plugin) -> bool;
    auto AdjustResources(nri_linux_resources *resources, const std::string &plugin) -> bool;
    bool ClaimAndCopyResources(nri_linux_resources *src, std::string &id, const std::string &plugin,
                               nri_linux_resources *dest);
    auto AdjustCgroupsPath(char *path, const std::string &plugin) -> bool;
    auto AdjustRlimits(nri_posix_rlimit **rlimits, size_t rlimits_len, const std::string &plugin) -> bool;

private:
    std::string m_conId;
    nri_linux_resources *m_update_req;
    resultReply m_reply;
    std::map<std::string, nri_container_update *> m_updates;
    resultOwners m_owners;
};

#endif