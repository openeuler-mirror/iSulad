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

#include "nri_result.h"

#include <isula_libutils/log.h>
#include <isula_libutils/nri_container_adjustment.h>

#include "cxxutils.h"
#include "transform.h"
#include "utils.h"

pluginResult::~pluginResult()
{
    free_nri_linux_resources(m_update_req);
    free_nri_container_adjustment(m_reply.adjust);
    for (size_t i = 0; i < m_reply.update.size(); i++) {
        free_nri_container_update(m_reply.update[i]);
    }
}

auto pluginResult::InitReply() -> bool
{
    m_reply.adjust = (nri_container_adjustment *)util_common_calloc_s(sizeof(nri_container_adjustment));
    if (m_reply.adjust == NULL) {
        ERROR("Out of memory");
        return false;
    }
    return true;
}

auto pluginResult::Init() -> bool
{
    if (!InitReply()) {
        ERROR("Failed to init reply");
        return false;
    }
    m_update_req = nullptr;
    return true;
}

auto pluginResult::InitByConId(std::string conId) -> bool
{
    m_conId = conId;

    if (!InitReply()) {
        ERROR("Failed to init reply");
        return false;
    }

    m_update_req = nullptr;
    return true;
}

auto pluginResult::InitByUpdateReq(nri_update_container_request *req) -> bool
{
    m_conId = req->container->id;
    m_update_req = copy_nri_linux_resources(req->linux_resources);
    if (m_update_req == nullptr) {
        ERROR("Failed to copy nri linux resources");
        return false;
    }

    if (!InitReply()) {
        ERROR("Failed to init reply");
        return false;
    }
    m_update_req = nullptr;
    return true;
}

auto pluginResult::GetReplyUpdate() -> std::vector<nri_container_update*>
{
    return m_reply.update;
}

auto pluginResult::MoveReplyAdjust() -> nri_container_adjustment *
{
    nri_container_adjustment *ret = m_reply.adjust;
    m_reply.adjust = nullptr;
    return ret;
}

auto pluginResult::GetReplyResources(const std::string &id) -> const nri_linux_resources *
{
    nri_linux_resources *ret = NULL;
    nri_container_update *update = m_updates[id];
    ret = update->linux->resources;
    return ret;
}

auto pluginResult::Apply(int32_t event, const nri_container_adjustment *adjust, nri_container_update **update,
                         size_t update_len, const std::string &plugin) -> bool
{
    if (plugin.length() == 0) {
        ERROR("Empty plugin name");
        return false;
    }
    if (event == CREATE_CONTAINER) {
        if (!Adjust(adjust, plugin)) {
            ERROR("Failed to do adjust to plugin: %s", plugin.c_str());
            return false;
        }

        if (!Update(update, update_len, plugin)) {
            ERROR("Failed to do update to plugin: %s", plugin.c_str());
            return false;
        }
        return true;
    } else if (event == UPDATE_CONTAINER) {
        if (!Update(update, update_len, plugin)) {
            ERROR("Failed to do update to plugin: %s", plugin.c_str());
            return false;
        }
        return true;
    } else if (event == STOP_CONTAINER) {
        if (!Update(update, update_len, plugin)) {
            ERROR("Failed to do update to plugin: %s", plugin.c_str());
            return false;
        }
        return true;
    } else {
        ERROR("Cannot apply response of invalid type %d", event);
        return false;
    }
    return true;
}

auto pluginResult::Adjust(const nri_container_adjustment *adjust, const std::string &plugin) -> bool
{
    if (adjust == nullptr) {
        return true;
    }

    if (!AdjustAnnotations(adjust->annotations, plugin)) {
        ERROR("Cannot adajust annotations by plugin %s", plugin.c_str());
        return false;
    }

    if (!AdjustMounts(adjust->mounts, adjust->mounts_len, plugin)) {
        ERROR("Cannot adajust mounts by plugin %s", plugin.c_str());
        return false;
    }

    if (!AdjustEnv(adjust->env, adjust->env_len, plugin)) {
        ERROR("Cannot adajust mounts by plugin %s", plugin.c_str());
        return false;
    }

    if (!AdjustHooks(adjust->hooks, plugin)) {
        ERROR("Cannot adajust hooks by plugin %s", plugin.c_str());
        return false;
    }

    if (adjust->linux != nullptr) {
        if (m_reply.adjust->linux == nullptr) {
            m_reply.adjust->linux = (nri_linux_container_adjustment *)util_common_calloc_s(sizeof(nri_linux_container_adjustment));
            if (m_reply.adjust->linux == nullptr) {
                ERROR("Out of memory");
                return false;
            }
        }

        if (!AdjustDevices(adjust->linux->devices, adjust->linux->devices_len, plugin)) {
            ERROR("Cannot adajust devices by plugin %s", plugin.c_str());
            return false;
        }

        if (!AdjustResources(adjust->linux->resources, plugin)) {
            ERROR("Cannot adajust devices by plugin %s", plugin.c_str());
            return false;
        }

        if (!AdjustCgroupsPath(adjust->linux->cgroups_path, plugin)) {
            ERROR("Cannot adajust cgroups path by plugin %s", plugin.c_str());
            return false;
        }
    }

    if (!AdjustRlimits(adjust->rlimits, adjust->rlimits_len, plugin)) {
        ERROR("Cannot adajust rlimits path by plugin %s", plugin.c_str());
        return false;
    }

    return true;
}

auto pluginResult::AdjustAnnotations(json_map_string_string *annos, const std::string &plugin) -> bool
{
    if (annos == nullptr || annos->len == 0) {
        return true;
    }

    if (m_reply.adjust->annotations == nullptr) {
        m_reply.adjust->annotations = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
        if (m_reply.adjust->annotations == nullptr) {
            ERROR("Out of memory");
            return false;
        }
    }

    google::protobuf::Map<std::string, std::string> del;
    const char *id = m_conId.c_str();
    google::protobuf::Map<std::string, std::string> mapAnno;
    Transform::JsonMapToProtobufMapForString(annos, mapAnno);

    // if key is marked for remove, add pair to del, and delete key from annos
    for (auto it = mapAnno.begin(); it != mapAnno.end();) {
        const std::string &key = it->first;
        char *out = NULL;
        if (is_marked_for_removal(key.c_str(), &out)) {
            del[out] = "";
            it = mapAnno.erase(it);
        } else {
            ++it;
        }
    }

    for (const auto &iter : mapAnno) {
        std::string key = iter.first;
        std::string value = iter.second;
        auto it = del.find(key);
        if (it != del.end()) {
            auto owner = m_owners.find(id);
            if (owner != m_owners.end()) {
                m_owners[id].annotations.erase(key);
            }
            append_json_map_string_string(m_reply.adjust->annotations, NRIHelpers::MarkForRemoval(key).c_str(), "");
        }

        // set annotations's owner plugin
        auto owner = m_owners.find(id);
        if (owner != m_owners.end()) {
            auto anno = m_owners[id].annotations.find(key);
            if (anno != m_owners[id].annotations.end()) {
                ERROR("plugins %s and %s both tried to set annotation: %s", plugin.c_str(), anno->second.c_str(), key.c_str());
                return false;
            }
            m_owners[id].annotations[key] = plugin;
        }

        // add pair to m_reply.adjust
        append_json_map_string_string(m_reply.adjust->annotations, key.c_str(), value.c_str());
        del.erase(key);
    }

    // add del to m_reply.adjust
    for (auto &pair : del) {
        append_json_map_string_string(m_reply.adjust->annotations, NRIHelpers::MarkForRemoval(pair.first).c_str(), "");
    }

    return true;
}

auto pluginResult::AdjustMounts(nri_mount **mounts, size_t mounts_size, const std::string &plugin) -> bool
{
    if (mounts == nullptr || mounts_size == 0) {
        return true;
    }

    size_t i;
    std::vector<nri_mount *> add;
    std::map<std::string, nri_mount *> del;
    std::string id = m_conId.c_str();

    // first split removals from the rest of adjustments
    for (i = 0; i < mounts_size; i++) {
        char *out = NULL;
        if (is_marked_for_removal(mounts[i]->destination, &out)) {
            del[out] = mounts[i];
        } else {
            add.push_back(mounts[i]);
        }
    }

    // next remove marked mounts from collected adjustments
    nri_mount** cleard = nullptr;
    size_t clearLen = 0;

    if (m_reply.adjust->mounts_len > 0) {
        cleard = (nri_mount **)util_common_calloc_s(m_reply.adjust->mounts_len * sizeof(nri_mount *));
        if (cleard == nullptr) {
            ERROR("Out of memory");
            return false;
        }

        for (i = 0; i < m_reply.adjust->mounts_len; i++) {
            auto removed = del.find(m_reply.adjust->mounts[i]->destination);
            if (removed != del.end()) {
                auto owner = m_owners.find(id);
                if (owner != m_owners.end()) {
                    m_owners[id].mounts.erase(m_reply.adjust->mounts[i]->destination);
                }
                continue;
            }
            cleard[clearLen] = copy_nri_mount(m_reply.adjust->mounts[i]);
            if (cleard[clearLen] == nullptr) {
                ERROR("Failed to copy nri mounts to cleard");
                return false;
            }
            clearLen++;
        }

        NRIHelpers::freeArray(m_reply.adjust->mounts, m_reply.adjust->mounts_len);
        m_reply.adjust->mounts = cleard;
        m_reply.adjust->mounts_len = clearLen;   
    }

    // finally, apply additions to collected adjustments
    size_t oldSize, newSize;
    oldSize = m_reply.adjust->mounts_len * sizeof(nri_mount *);
    newSize = oldSize + add.size() * sizeof(nri_mount *);
    int ret = util_mem_realloc((void **)(&m_reply.adjust->mounts), newSize, (void *)m_reply.adjust->mounts, oldSize);
    if (ret != 0) {
        ERROR("Failed to realloc and assign nri mounts array");
        return false;
    }
    for (i = 0; i < add.size(); i++) {
        // set mounts's owner plugin
        auto owner = m_owners.find(id);
        if (owner != m_owners.end()) {
            auto mount = m_owners[id].mounts.find(add[i]->destination);
            if (mount != m_owners[id].mounts.end()) {
                ERROR("plugins %s and %s both tried to set mount: %s", plugin.c_str(), mount->second.c_str(), add[i]->destination);
                return false;
            }
            m_owners[id].mounts[add[i]->destination] = plugin;
        }
        m_reply.adjust->mounts[m_reply.adjust->mounts_len] = copy_nri_mount(add[i]);
        if (m_reply.adjust->mounts[m_reply.adjust->mounts_len] == nullptr) {
            ERROR("Failed to copy add nri mounts to reply adjust");
            return false;
        }
        m_reply.adjust->mounts_len++;
    }

    return true;
}

auto pluginResult::AdjustEnv(nri_key_value **envs, size_t envs_size, const std::string &plugin) -> bool
{
    if (envs == nullptr || envs_size == 0) {
        return true;
    }

    size_t i;
    std::vector<nri_key_value *> add;
    std::map<std::string, nri_key_value *> del;
    std::string id = m_conId.c_str();

    // first split removals from the rest of adjustments
    for (i = 0; i < envs_size; i++) {
        char *out = NULL;
        if (is_marked_for_removal(envs[i]->key, &out)) {
            del[out] = envs[i];
        } else {
            add.push_back(envs[i]);
        }
    }

    // next remove marked mounts from collected adjustments
    nri_key_value** cleard;
    size_t clearLen = 0;

    if(m_reply.adjust->env_len > 0) {
        cleard = (nri_key_value **)util_common_calloc_s(m_reply.adjust->env_len * sizeof(nri_key_value *));
        if (cleard == nullptr) {
            ERROR("Out of memory");
            return false;
        }

        for (i = 0; i < m_reply.adjust->env_len; i++) {
            auto removed = del.find(m_reply.adjust->env[i]->key);
            if (removed != del.end()) {
                auto owner = m_owners.find(id);
                if (owner != m_owners.end()) {
                    m_owners[id].env.erase(m_reply.adjust->env[i]->key);
                }
                continue;
            }
            cleard[clearLen] = copy_nri_key_value(m_reply.adjust->env[i]);
            if (cleard[clearLen] == nullptr) {
                ERROR("Failed to copy nri env key value to cleard");
                return false;
            }
            clearLen++;
        }

        NRIHelpers::freeArray(m_reply.adjust->env, m_reply.adjust->env_len);
        m_reply.adjust->env = cleard;
        m_reply.adjust->env_len = clearLen;
    }

    // finally, apply additions to collected adjustments
    size_t oldSize, newSize;
    oldSize = m_reply.adjust->env_len * sizeof(nri_key_value *);
    newSize = oldSize + add.size() * sizeof(nri_key_value *);
    int ret = util_mem_realloc((void **)(&m_reply.adjust->env), newSize, m_reply.adjust->env, oldSize);
    if (ret != 0) {
        ERROR("Failed to realloc and assign nri env array");
        return false;
    }
    for (i = 0; i < add.size(); i++) {
        // set env's owner plugin
        auto owner = m_owners.find(id);
        if (owner != m_owners.end()) {
            auto env = m_owners[id].env.find(add[i]->key);
            if (env != m_owners[id].env.end()) {
                ERROR("plugins %s and %s both tried to set env: %s", plugin.c_str(), env->second.c_str(), add[i]->key);
                return false;
            }
            m_owners[id].env[add[i]->key] = plugin;
        }
        m_reply.adjust->env[m_reply.adjust->env_len] = copy_nri_key_value(add[i]);
        if (m_reply.adjust->env[m_reply.adjust->env_len] == nullptr) {
            ERROR("Failed to copy add nri env to reply adjust");
            return false;
        }
        m_reply.adjust->env_len++;
    }

    return true;
}

auto pluginResult::AdjustHooks(const nri_hooks *hooks, const std::string &plugin) -> bool
{
    if (hooks == nullptr) {
        return true;
    }

    if (m_reply.adjust->hooks == nullptr) {
        m_reply.adjust->hooks = (nri_hooks *)util_common_calloc_s(sizeof(nri_hooks));
        if (m_reply.adjust->hooks == nullptr) {
            ERROR("Out of memory");
            return false;
        }
    }

    nri_hooks * reply = m_reply.adjust->hooks;

    if (!merge_nri_hooks(reply->prestart, reply->prestart_len, (const nri_hook**)hooks->prestart, hooks->prestart_len)) {
        ERROR("Failed to realloc and copy prestart hooks");
        return false;
    }

    if (!merge_nri_hooks(reply->poststart, reply->poststart_len, (const nri_hook**)hooks->poststart,
                         hooks->poststart_len)) {
        ERROR("Failed to realloc and copy poststart hooks");
        return false;
    }

    if (!merge_nri_hooks(reply->poststop, reply->poststop_len, (const nri_hook**)hooks->poststop, hooks->poststop_len)) {
        ERROR("Failed to realloc and copy poststop hooks");
        return false;
    }

    /* TODO:zhongtao
    * The OCI being used by the iSulad not supportes
    * createRuntime/createContainer/startContainer currently.
    */
    if (!merge_nri_hooks(reply->create_runtime, reply->create_runtime_len, (const nri_hook**)hooks->create_runtime,
                         hooks->create_runtime_len)) {
        ERROR("Failed to realloc and copy create_runtime hooks");
        return false;
    }

    if (!merge_nri_hooks(reply->create_container, reply->create_container_len, (const nri_hook**)hooks->create_container,
                         hooks->create_container_len)) {
        ERROR("Failed to realloc and copy create_container hooks");
        return false;
    }

    if (!merge_nri_hooks(reply->start_container, reply->start_container_len, (const nri_hook**)hooks->start_container,
                         hooks->start_container_len)) {
        ERROR("Failed to realloc and copy start_container hooks");
        return false;
    }

    return false;
}

auto pluginResult::AdjustDevices(nri_linux_device **devices, size_t devices_size, const std::string &plugin) -> bool
{
    if (devices_size == 0) {
        return true;
    }

    size_t i;
    std::vector<nri_linux_device *> add;
    std::map<std::string, nri_linux_device *> del;
    std::string id = m_conId.c_str();

    // first split removals from the rest of adjustments
    for (i = 0; i < devices_size; i++) {
        char *out = NULL;
        if (is_marked_for_removal(devices[i]->path, &out)) {
            del[out] = devices[i];
        } else {
            add.push_back(devices[i]);
        }
    }

    // next remove marked mounts from collected adjustments
    nri_linux_device** cleard;
    size_t clearLen = 0;

    if (m_reply.adjust->linux->devices_len > 0) {
        cleard = (nri_linux_device **)util_common_calloc_s(m_reply.adjust->linux->devices_len * sizeof(nri_linux_device *));
        if (cleard == nullptr) {
            ERROR("Out of memory");
            return false;
        }
        for (i = 0; i < m_reply.adjust->linux->devices_len; i++) {
            auto removed = del.find(m_reply.adjust->linux->devices[i]->path);
            if (removed != del.end()) {
                auto owner = m_owners.find(id);
                if (owner != m_owners.end()) {
                    m_owners[id].devices.erase(m_reply.adjust->linux->devices[i]->path);
                }
                continue;
            }
            cleard[clearLen] = copy_nri_device(m_reply.adjust->linux->devices[i]);
            if (cleard[clearLen] == nullptr) {
                ERROR("Failed to copy nri linux device to cleard");
                return false;
            }
            clearLen++;
        }

        NRIHelpers::freeArray(m_reply.adjust->linux->devices, m_reply.adjust->linux->devices_len);
        m_reply.adjust->linux->devices = cleard;
        m_reply.adjust->linux->devices_len = clearLen;
    }

    // finally, apply additions to collected adjustments
    size_t oldSize, newSize;
    oldSize = m_reply.adjust->linux->devices_len * sizeof(nri_linux_device *);
    newSize = oldSize + add.size() * sizeof(nri_linux_device *);
    int ret = util_mem_realloc((void **)(&m_reply.adjust->linux->devices), newSize, m_reply.adjust->linux->devices, oldSize);
    if (ret != 0) {
        ERROR("Failed to realloc and assign nri devices array");
        return false;
    }
    for (i = 0; i < add.size(); i++) {
        // set mounts's owner plugin
        auto owner = m_owners.find(id);
        if (owner != m_owners.end()) {
            auto device = m_owners[id].devices.find(add[i]->path);
            if (device != m_owners[id].devices.end()) {
                ERROR("plugins %s and %s both tried to set devices: %s", plugin.c_str(), device->second.c_str(), add[i]->path);
                return false;
            }
            m_owners[id].devices[add[i]->path] = plugin;
        }
        m_reply.adjust->linux->devices[m_reply.adjust->linux->devices_len] = copy_nri_device(add[i]);
        if (m_reply.adjust->linux->devices[m_reply.adjust->linux->devices_len] == nullptr) {
            ERROR("Failed to copy add nri devices to reply adjust");
            return false;
        }
        m_reply.adjust->linux->devices_len++;
    }

    return true;
}

auto pluginResult::AdjustResources(nri_linux_resources *resources, const std::string &plugin) -> bool
{
    if (resources == nullptr) {
        return true;
    }

    if (m_reply.adjust->linux->resources == nullptr) {
        m_reply.adjust->linux->resources = (nri_linux_resources *)util_common_calloc_s(sizeof(nri_linux_resources));
        if (m_reply.adjust->linux->resources == nullptr) {
            ERROR("Out of memory");
            return false;
        }
    }

    std::string id = m_conId.c_str();
    nri_linux_resources *reply = m_reply.adjust->linux->resources;

    return ClaimAndCopyResources(resources, id, plugin, reply);
}

bool pluginResult::ClaimAndCopyResources(nri_linux_resources *src, std::string &id, const std::string &plugin,
                                         nri_linux_resources *dest)
{
    size_t i;
    if (src->memory != nullptr) {
        if (dest->memory == nullptr) {
            dest->memory = (nri_linux_memory *)util_common_calloc_s(sizeof(nri_linux_memory));
            if (dest->memory == nullptr) {
                ERROR("Out of memory");
                return false;
            }
        }
        if (src->memory->limit != nullptr) {
            auto memLimit = m_owners[id].memLimit;
            if (!memLimit.empty()) {
                ERROR("plugins %s and %s both tried to set devices's memory limit", plugin.c_str(), memLimit.c_str());
                return false;
            }
            m_owners[id].memLimit = plugin;
            dest->memory->limit = NRIHelpers::copy_pointer(src->memory->limit);
            if (dest->memory->limit == nullptr) {
                ERROR("Failed to copy memory limit to reply adjust");
                return false;
            }
        }

        if (src->memory->reservation != nullptr) {
            auto memReservation = m_owners[id].memReservation;
            if (!memReservation.empty()) {
                ERROR("plugins %s and %s both tried to set devices's memory reservation", plugin.c_str(),
                      memReservation.c_str());
                return false;
            }
            m_owners[id].memReservation = plugin;
            dest->memory->reservation = NRIHelpers::copy_pointer(src->memory->reservation);
            if (dest->memory->reservation == nullptr) {
                ERROR("Failed to copy memory reservation to reply adjust");
                return false;
            }
        }

        if (src->memory->swap != nullptr) {
            auto memSwapLimit = m_owners[id].memSwapLimit;
            if (!memSwapLimit.empty()) {
                ERROR("plugins %s and %s both tried to set devices's memory swap limit", plugin.c_str(),
                      memSwapLimit.c_str());
                return false;
            }
            m_owners[id].memSwapLimit = plugin;
            dest->memory->swap = NRIHelpers::copy_pointer(src->memory->swap);
            if (dest->memory->swap == nullptr) {
                ERROR("Failed to copy memory swap to reply adjust");
                return false;
            }
        }

        if (src->memory->kernel != nullptr) {
            auto memKernelLimit = m_owners[id].memKernelLimit;
            if (!memKernelLimit.empty()) {
                ERROR("plugins %s and %s both tried to set devices's memory kernel limit", plugin.c_str(),
                      memKernelLimit.c_str());
                return false;
            }
            m_owners[id].memKernelLimit = plugin;
            dest->memory->kernel = NRIHelpers::copy_pointer(src->memory->kernel);
            if (dest->memory->kernel == nullptr) {
                ERROR("Failed to copy memory kernel to reply adjust");
                return false;
            }
        }

        if (src->memory->kernel_tcp != nullptr) {
            auto memTCPLimit = m_owners[id].memTCPLimit;
            if (!memTCPLimit.empty()) {
                ERROR("plugins %s and %s both tried to set devices's memory tcp limit", plugin.c_str(),
                      memTCPLimit.c_str());
                return false;
            }
            m_owners[id].memTCPLimit = plugin;
            dest->memory->kernel_tcp = NRIHelpers::copy_pointer(src->memory->kernel_tcp);
            if (dest->memory->kernel_tcp == nullptr) {
                ERROR("Failed to copy memory kernel tcp to reply adjust");
                return false;
            }
        }

        if (src->memory->swappiness != nullptr) {
            auto memSwappiness = m_owners[id].memSwappiness;
            if (!memSwappiness.empty()) {
                ERROR("plugins %s and %s both tried to set devices's memory swappiness", plugin.c_str(),
                      memSwappiness.c_str());
                return false;
            }
            m_owners[id].memSwappiness = plugin;
            dest->memory->swappiness = NRIHelpers::copy_pointer(src->memory->swappiness);
            if (dest->memory->swappiness == nullptr) {
                ERROR("Failed to copy memory swappiness to reply adjust");
                return false;
            }
        }

        if (src->memory->disable_oom_killer != nullptr) {
            auto memDisableOomKiller = m_owners[id].memDisableOomKiller;
            if (!memDisableOomKiller.empty()) {
                ERROR("plugins %s and %s both tried to set devices's memory disable_oom_killer", plugin.c_str(),
                      memDisableOomKiller.c_str());
                return false;
            }
            m_owners[id].memDisableOomKiller = plugin;
            dest->memory->disable_oom_killer = NRIHelpers::copy_pointer(src->memory->disable_oom_killer);
            if (dest->memory->disable_oom_killer == nullptr) {
                ERROR("Failed to copy memory disable_oom_killer to reply adjust");
                return false;
            }
        }

        if (src->memory->use_hierarchy != nullptr) {
            auto memUseHierarchy = m_owners[id].memUseHierarchy;
            if (!memUseHierarchy.empty()) {
                ERROR("plugins %s and %s both tried to set devices's memory use_hierarchy", plugin.c_str(),
                      memUseHierarchy.c_str());
                return false;
            }
            m_owners[id].memUseHierarchy = plugin;
            dest->memory->use_hierarchy = NRIHelpers::copy_pointer(src->memory->use_hierarchy);
            if (dest->memory->use_hierarchy == nullptr) {
                ERROR("Failed to copy memory use_hierarchy to reply adjust");
                return false;
            }
        }
    }

    if (src->cpu != nullptr) {
        if (dest->cpu == nullptr) {
            dest->cpu = (nri_linux_cpu *)util_common_calloc_s(sizeof(nri_linux_cpu));
            if (dest->cpu == nullptr) {
                ERROR("Out of memory");
                return false;
            }
        }
        if (src->cpu->shares != nullptr) {
            auto cpuShares = m_owners[id].cpuShares;
            if (!cpuShares.empty()) {
                ERROR("plugins %s and %s both tried to set devices's cpu shares", plugin.c_str(), cpuShares.c_str());
                return false;
            }
            m_owners[id].cpuShares = plugin;
            dest->cpu->shares = NRIHelpers::copy_pointer(src->cpu->shares);
            if (dest->cpu->shares == nullptr) {
                ERROR("Failed to copy cpu shares to reply adjust");
                return false;
                }
        }

        if (src->cpu->quota != nullptr) {
            auto cpuQuota = m_owners[id].cpuQuota;
            if (!cpuQuota.empty()) {
                ERROR("plugins %s and %s both tried to set devices's cpu quota", plugin.c_str(), cpuQuota.c_str());
                return false;
            }
            m_owners[id].cpuQuota = plugin;
            dest->cpu->quota = NRIHelpers::copy_pointer(src->cpu->quota);
            if (dest->cpu->quota == nullptr) {
                ERROR("Failed to copy cpu quota to reply adjust");
                return false;
            }
        }

        if (src->cpu->period != nullptr) {
            auto cpuPeriod = m_owners[id].cpuPeriod;
            if (!cpuPeriod.empty()) {
                ERROR("plugins %s and %s both tried to set devices's cpu period", plugin.c_str(), cpuPeriod.c_str());
                return false;
            }
            m_owners[id].cpuPeriod = plugin;
            dest->cpu->period = NRIHelpers::copy_pointer(src->cpu->period);
            if (dest->cpu->period == nullptr) {
                ERROR("Failed to copy cpu period to reply adjust");
                return false;
            }
        }

        if (src->cpu->realtime_runtime != nullptr) {
            auto cpuRealtimePeriod = m_owners[id].cpuRealtimePeriod;
            if (!cpuRealtimePeriod.empty()) {
                ERROR("plugins %s and %s both tried to set devices's cpu realtime_runtime", plugin.c_str(),
                      cpuRealtimePeriod.c_str());
                return false;
            }
            m_owners[id].cpuRealtimePeriod = plugin;
            dest->cpu->realtime_runtime = NRIHelpers::copy_pointer(src->cpu->realtime_runtime);
            if (dest->cpu->realtime_runtime == nullptr) {
                ERROR("Failed to copy cpu realtime_runtime to reply adjust");
                return false;
            }
        }

        if (src->cpu->realtime_period != nullptr) {
            auto cpuRealtimePeriod = m_owners[id].cpuRealtimePeriod;
            if (!cpuRealtimePeriod.empty()) {
                ERROR("plugins %s and %s both tried to set devices's cpu realtime_period", plugin.c_str(),
                      cpuRealtimePeriod.c_str());
                return false;
            }
            m_owners[id].cpuRealtimePeriod = plugin;
            dest->cpu->realtime_period = NRIHelpers::copy_pointer(src->cpu->realtime_period);
            if (dest->cpu->realtime_period == nullptr) {
                ERROR("Failed to copy cpu realtime_period to reply adjust");
                return false;
            }
        }

        if (src->cpu->cpus != nullptr) {
            auto cpusetCpus = m_owners[id].cpusetCpus;
            if (!cpusetCpus.empty()) {
                ERROR("plugins %s and %s both tried to set devices's cpu cpus", plugin.c_str(), cpusetCpus.c_str());
                return false;
            }
            m_owners[id].cpusetCpus = plugin;
            dest->cpu->cpus = NRIHelpers::copy_pointer(src->cpu->cpus);
            if (dest->cpu->cpus == nullptr) {
                ERROR("Failed to copy cpu cpus to reply adjust");
                return false;
            }
        }

        if (src->cpu->mems != nullptr) {
            auto cpusetMems = m_owners[id].cpusetMems;
            if (!cpusetMems.empty()) {
                ERROR("plugins %s and %s both tried to set devices's cpu mems", plugin.c_str(), cpusetMems.c_str());
                return false;
            }
            m_owners[id].cpusetMems = plugin;
            dest->cpu->mems = NRIHelpers::copy_pointer(src->cpu->mems);
            if (dest->cpu->mems == nullptr) {
                ERROR("Failed to copy cpu mems to reply adjust");
                return false;
            }
        }
    }

    for (i = 0; i < src->hugepage_limits_len; i++) {
        auto owner = m_owners.find(id);
        if (owner != m_owners.end()) {
            auto find = m_owners[id].hugepageLimits.find(src->hugepage_limits[i]->page_size);
            if (find != m_owners[id].hugepageLimits.end()) {
                ERROR("plugins %s and %s both tried to set hugepageLimits: %s", plugin.c_str(), find->second.c_str(),
                      src->hugepage_limits[i]->page_size);
                return false;
            }
            m_owners[id].hugepageLimits[src->hugepage_limits[i]->page_size] = plugin;
        }
    }

    if (src->unified->len != 0) {
        google::protobuf::Map<std::string, std::string> mapAnno;
        Transform::JsonMapToProtobufMapForString(src->unified, mapAnno);
        for (const auto &iter : mapAnno) {
            std::string key = iter.first;
            std::string value = iter.second;
            auto owner = m_owners.find(id);
            if (owner != m_owners.end()) {
                auto anno = m_owners[id].unified.find(key);
                if (anno != m_owners[id].unified.end()) {
                    ERROR("plugins %s and %s both tried to set unified: %s", plugin.c_str(), anno->second.c_str(),
                          key.c_str());
                    return false;
                }
                m_owners[id].unified[key] = plugin;
            }
            // add pair to m_reply.adjust
            append_json_map_string_string(dest->unified, key.c_str(), value.c_str());
        }
    }

    if (src->blockio_class != nullptr) {
        auto blockioClass = m_owners[id].blockioClass;
        if (!blockioClass.empty()) {
            ERROR("plugins %s and %s both tried to set devices's blockio_class", plugin.c_str(), blockioClass.c_str());
            return false;
        }
        m_owners[id].blockioClass = plugin;
        dest->blockio_class = util_strdup_s(src->blockio_class);
    }

    if (src->rdt_class != nullptr) {
        auto rdtClass = m_owners[id].rdtClass;
        if (!rdtClass.empty()) {
            ERROR("plugins %s and %s both tried to set devices's rdt_class", plugin.c_str(), rdtClass.c_str());
            return false;
        }
        m_owners[id].rdtClass = plugin;
        dest->rdt_class = util_strdup_s(src->rdt_class);
    }
    return true;
}

auto pluginResult::AdjustCgroupsPath(char *path, const std::string &plugin) -> bool
{
    if (path == nullptr || strcmp(path, "") == 0) {
        return true;
    }

    std::string id = m_conId.c_str();

    auto cgroupsPath = m_owners[id].cgroupsPath;
    if (!cgroupsPath.empty()) {
        ERROR("plugins %s and %s both tried to set devices's cgroups path", plugin.c_str(), cgroupsPath.c_str());
        return false;
    }
    m_owners[id].cgroupsPath = plugin;
    m_reply.adjust->linux->cgroups_path = util_strdup_s(path);

    return true;
}

auto pluginResult::AdjustRlimits(nri_posix_rlimit **rlimits, size_t rlimits_len, const std::string &plugin) -> bool
{
    if (rlimits_len == 0) {
        return true;
    }

    size_t i;
    std::string id = m_conId.c_str();

    size_t oldSize, newSize;
    oldSize = m_reply.adjust->rlimits_len * sizeof(nri_posix_rlimit *);
    newSize = oldSize + rlimits_len * sizeof(nri_posix_rlimit *);
    int ret = util_mem_realloc((void **)(&m_reply.adjust->rlimits), newSize, m_reply.adjust->rlimits, oldSize);
    if (ret != 0) {
        ERROR("Failed to realloc and assign nri rlimits array");
        return false;
    }

    for (i = 0; i < rlimits_len; i++) {
        auto owner = m_owners.find(id);
        if (owner != m_owners.end()) {
            auto find = m_owners[id].rlimits.find(rlimits[i]->type);
            if (find != m_owners[id].rlimits.end()) {
                ERROR("plugins %s and %s both tried to set rlimits type: %s", plugin.c_str(), find->second.c_str(), rlimits[i]->type);
                return false;
            }
            m_owners[id].rlimits[rlimits[i]->type] = plugin;
        }
        m_reply.adjust->rlimits[m_reply.adjust->rlimits_len] = copy_nri_posix_rlimit(rlimits[i]);
        if (m_reply.adjust->rlimits[m_reply.adjust->rlimits_len] == nullptr) {
            ERROR("Failed to copy add nri rlimits to reply adjust");
            return false;
        }
        m_reply.adjust->rlimits_len++;
    }
    return true;
}

auto pluginResult::Update(nri_container_update **updates, size_t update_len, const std::string &plugin) -> bool
{
    if (update_len == 0) {
        return true;
    }

    size_t i;

    for (i = 0; i < update_len; i++) {
        nri_container_update *reply;
        if (!GetContainerUpdate(updates[i], plugin, &reply)) {
            ERROR("Failed to get container update in plugin result");
            return false;
        }

        if (!UpdateResources(reply, updates[i], plugin) && !updates[i]->ignore_failure) {
            ERROR("Failed to update container resources in plugin result");
            return false;
        }
    }

    return true;
}

auto pluginResult::GetContainerUpdate(nri_container_update *update, const std::string &plugin,
                                      nri_container_update **out) -> bool
{
    if (update == nullptr || out == nullptr || plugin.empty()) {
        ERROR("Empyt input args");
        return false;
    }

    auto id = update->container_id;

    if (std::string(id) == m_conId) {
        ERROR("Plugin %s asked update of %s during creation", plugin.c_str(), id);
        return false;
    }

    auto find = m_updates.find(id);
    if (find != m_updates.end()) {
        *out = m_updates[id];
        (*out)->ignore_failure = (*out)->ignore_failure && update->ignore_failure;
        return true;
    }

    *out = init_nri_container_update(id, update->ignore_failure);
    if (*out == nullptr) {
        ERROR("Failed to init nri container update");
        return false;
    }

    m_updates[id] = *out;

    // for update requests delay appending the requested container (in the response getter)
    if (m_conId != id) {
        m_reply.update.push_back(*out);
    }

    return true;
}

auto pluginResult::UpdateResources(nri_container_update *reply, nri_container_update *u,
                                   const std::string &plugin) -> bool
{
    if (u->linux == nullptr || u->linux->resources == nullptr) {
        return true;
    }

    std::string id = u->container_id;
    nri_linux_resources *resources;

    // operate on a copy: we won't touch anything on (ignored) failures
    if (m_conId == id) {
        resources = copy_nri_linux_resources(m_update_req);
        if (resources == nullptr) {
            ERROR("Failed to copy request's nri linux resources");
            return false;
        }
    } else {
        resources = copy_nri_linux_resources(reply->linux->resources);
        if (resources == nullptr) {
            ERROR("Failed to copy reply's nri linux resources");
            return false;
        }
    }

    if (!ClaimAndCopyResources(u->linux->resources, id, plugin, resources)) {
        ERROR("Failed to claim and copy resources in plugin result");
        return false;
    }

    // update reply from copy on success
    free_nri_linux_resources(reply->linux->resources);
    reply->linux->resources = copy_nri_linux_resources(resources);
    if (reply->linux->resources == nullptr) {
        ERROR("Failed to copy resources's nri linux resources to reply");
        return false;
    }

    return true;
}