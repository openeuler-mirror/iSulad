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
 * Create: 2024-03-16
 * Description: provide nri convert functions
 *********************************************************************************/

#include "nri_convert.h"

#include "container_api.h"
#include "v1_cri_helpers.h"
#include "path.h"
#include "transform.h"
#include "nri_utils.h"
#include "cstruct_wrapper.h"

static int64_t DefaultOOMScoreAdj = 0;

static bool NRILinuxCpuFromCRI(const runtime::v1::LinuxContainerResources &config, nri_linux_cpu &cpu)
{
    if (!config.cpuset_cpus().empty()) {
        cpu.cpus = util_strdup_s(config.cpuset_cpus().c_str());
    }

    if (!config.cpuset_mems().empty()) {
        cpu.mems = util_strdup_s(config.cpuset_mems().c_str());
    }

    cpu.period = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
    if (cpu.period == nullptr) {
        ERROR("Out of memory");
        return false;
    }
    *(cpu.period) = config.cpu_period();

    cpu.quota = (int64_t  *)util_common_calloc_s(sizeof(int64_t));
    if (cpu.quota == nullptr) {
        ERROR("Out of memory");
        return false;
    }
    *(cpu.quota) = config.cpu_quota();

    cpu.shares = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
    if (cpu.shares == nullptr) {
        ERROR("Out of memory");
        return false;
    }
    *(cpu.shares) = config.cpu_shares();

    // consistent with other container engines,
    // not obtained cpu.realtime_period & cpu.realtime_runtime
    return true;
}

static bool NRILinuxMemoryFromCRI(const runtime::v1::LinuxContainerResources &config, nri_linux_memory &memory)
{
    memory.limit = (int64_t *)util_common_calloc_s(sizeof(int64_t));
    if (memory.limit == nullptr) {
        ERROR("Out of memory");
        return false;
    }
    *(memory.limit) = config.memory_limit_in_bytes();

    // consistent with other container engines,
    // not obtained other memory info

    return true;
}

static bool NRIHugePageLimitFromCRI(const runtime::v1::LinuxContainerResources &config, nri_linux_resources &resources)
{
    int i;
    nri_hugepage_limit *tmp = nullptr;

    if (config.hugepage_limits_size() == 0) {
        return true;
    }

    resources.hugepage_limits = (nri_hugepage_limit **)util_smart_calloc_s(sizeof(nri_hugepage_limit *),
                                                                           config.hugepage_limits_size());
    if (resources.hugepage_limits == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    for (i = 0; i < config.hugepage_limits_size(); i++) {
        tmp = (nri_hugepage_limit *)util_common_calloc_s(sizeof(nri_hugepage_limit));
        if (tmp == nullptr) {
            ERROR("Out of memory");
            return false;
        }
        tmp->page_size = util_strdup_s(config.hugepage_limits(i).page_size().c_str());
        tmp->limit = config.hugepage_limits(i).limit();
        resources.hugepage_limits[i] = tmp;
        resources.hugepage_limits_len++;
        tmp = nullptr;
    }
    return true;
}

static auto NRILinuxResourcesFromCRI(const runtime::v1::LinuxContainerResources &config,
                                     nri_linux_resources &resources) -> bool
{
    if (!NRILinuxMemoryFromCRI(config, *resources.memory)) {
        ERROR("Failed to transform memory to nri for container");
        return false;
    }

    if (!NRILinuxCpuFromCRI(config, *resources.cpu)) {
        ERROR("Failed to transform cpu to nri for container");
        return false;
    }

    if (!NRIHugePageLimitFromCRI(config, resources)) {
        ERROR("Failed to transform hugepage limits to nri for container");
        return false;
    }

    // resources.blockio_class is not support
    // resources.rdt_class is not support
    // They are not standard fields in oci spec

    Errors tmpError;

    resources.unified = Transform::ProtobufMapToJsonMapForString(config.unified(), tmpError);
    if (resources.unified == nullptr) {
        ERROR("Failed to transform unified to nri for container : %s", tmpError.GetMessage().c_str());
        return false;
    }

    // resources.devices is not set in pod

    return true;
}

static auto NRILinuxFromCRI(const runtime::v1::LinuxPodSandboxConfig &config, nri_linux_pod_sandbox &linux) -> bool
{
    if (config.has_overhead()) {
        linux.pod_overhead = init_nri_linux_resources();
        if (linux.pod_overhead == nullptr) {
            ERROR("Failed to init nri linux overhead resources for pod");
            return false;
        }
        if (!NRILinuxResourcesFromCRI(config.overhead(), *linux.pod_overhead)) {
            ERROR("Failed to transform overhead to nri for pod");
            return false;
        }
    }

    if (config.has_resources()) {
        linux.pod_resources = init_nri_linux_resources();
        if (linux.pod_resources == nullptr) {
            ERROR("Failed to init nri linux resources resources for pod");
            return false;
        }
        if (!NRILinuxResourcesFromCRI(config.resources(), *linux.pod_resources)) {
            ERROR("Failed to transform resources to nri for pod");
            return false;
        }
    }

    linux.cgroup_parent = util_strdup_s(config.cgroup_parent().c_str());

    // todo: other container engines get linux.cgroups_path/linux.resourses/linux.namespace from spec.linux,
    // How does isulad get these values ​​from CRI module?
    return true;
}

auto PodSandboxToNRI(const std::shared_ptr<const sandbox::Sandbox> &sandbox, nri_pod_sandbox &pod) -> bool
{
    container_t *cont = nullptr;
    Errors tmpError;

    cont = containers_store_get(sandbox->GetName().c_str());
    if (cont != nullptr) {
        pod.pid = container_state_get_pid(cont->state);
        container_unref(cont);
    }

    pod.id = util_strdup_s(sandbox->GetId().c_str());
    pod.name = util_strdup_s(sandbox->GetName().c_str());
    if (sandbox->GetSandboxConfig().has_metadata()) {
        pod.uid = util_strdup_s(sandbox->GetSandboxConfig().metadata().uid().c_str());
        pod._namespace = util_strdup_s(sandbox->GetSandboxConfig().metadata().namespace_().c_str());
    }


    pod.labels = Transform::ProtobufMapToJsonMapForString(sandbox->GetSandboxConfig().labels(), tmpError);
    if (pod.labels == nullptr) {
        ERROR("Failed to transform labels to nri for pod : %s, : %s", pod.name, tmpError.GetMessage().c_str());
        return false;
    }

    pod.annotations = Transform::ProtobufMapToJsonMapForString(sandbox->GetSandboxConfig().annotations(), tmpError);
    if (pod.annotations == nullptr) {
        ERROR("Failed to transform annotations to nri for pod : %s, : %s", pod.name, tmpError.GetMessage().c_str());
        return false;
    }

    if (sandbox->GetSandboxConfig().has_linux()) {
        pod.linux = (nri_linux_pod_sandbox *)util_common_calloc_s(sizeof(nri_linux_pod_sandbox));
        if (pod.linux == nullptr) {
            ERROR("Out of memory");
            return false;
        }
        if (!NRILinuxFromCRI(sandbox->GetSandboxConfig().linux(), *pod.linux)) {
            ERROR("Failed to transform linux to nri for pod : %s", pod.name);
            return false;
        }
    }

    pod.runtime_handler = util_strdup_s(sandbox->GetRuntimeHandle().c_str());

    return true;
}

static auto CRIMountArrToNRI(const runtime::v1::ContainerConfig &containerConfig, nri_container &con) -> bool
{
    size_t i, len;

    // get mount from cont
    len = containerConfig.mounts_size();
    if (len == 0) {
        return true;
    }
    con.mounts = (nri_mount **)util_smart_calloc_s(sizeof(nri_mount *), len);
    if (con.mounts == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    nri_mount *tmp = nullptr;

    for (i = 0; i < len; i++) {
        tmp = (nri_mount *)util_common_calloc_s(sizeof(nri_mount));
        if (tmp == nullptr) {
            ERROR("Out of memory");
            goto error_out;
        }

        if (containerConfig.mounts()[i].container_path().empty() || containerConfig.mounts()[i].host_path().empty()) {
            ERROR("Mount path is empty");
            goto error_out;
        }

        char path[PATH_MAX] = { 0 };
        if (!util_clean_path(containerConfig.mounts()[i].container_path().c_str(), path, sizeof(path))) {
            ERROR("Failed to get clean path for mount src path: %s", containerConfig.mounts()[i].container_path().c_str());
            goto error_out;
        }

        tmp->destination = util_strdup_s(path);

        if (!util_clean_path(containerConfig.mounts()[i].host_path().c_str(), path, sizeof(path))) {
            ERROR("Failed to get clean path for mount src path: %s", containerConfig.mounts()[i].host_path().c_str());
            goto error_out;
        }
        tmp->source = util_strdup_s(path);

        if (util_array_append(&(tmp->options), "rbind") != 0) {
            ERROR("Failed to append options");
            goto error_out;
        }

        if (containerConfig.mounts()[i].propagation() == runtime::v1::PROPAGATION_PRIVATE) {
            DEBUG("noop, private is default");
            if (util_array_append(&(tmp->options), "rprivate") != 0) {
                ERROR("Failed to append options");
                goto error_out;
            }
        } else if (containerConfig.mounts()[i].propagation() == runtime::v1::PROPAGATION_BIDIRECTIONAL) {
            if (util_array_append(&(tmp->options), "rshared") != 0) {
                ERROR("Failed to append options");
                goto error_out;
            }
        } else if (containerConfig.mounts()[i].propagation() == runtime::v1::PROPAGATION_HOST_TO_CONTAINER) {
            if (util_array_append(&(tmp->options), "rslave") != 0) {
                ERROR("Failed to append options");
                goto error_out;
            }
        } else {
            WARN("unknown propagation mode for hostPath %s", containerConfig.mounts()[i].host_path().c_str());
            if (util_array_append(&(tmp->options), "rprivate") != 0) {
                ERROR("Failed to append options");
                goto error_out;
            }
        }

        if (containerConfig.mounts()[i].readonly()) {
            if (util_array_append(&(tmp->options), "ro") != 0) {
                ERROR("Failed to append options");
                goto error_out;
            }
        } else {
            if (util_array_append(&(tmp->options), "rw") != 0) {
                ERROR("Failed to append options");
                goto error_out;
            }
        }

        tmp->type = util_strdup_s("bind");

        con.mounts[i] = tmp;
        tmp = nullptr;
        con.mounts_len++;
    }
    return true;

error_out:
    free_nri_mount(tmp);
    return false;
}

static auto MountPointsElementToNRI(container_config_v2_common_config_mount_points *mp, nri_container &con) -> bool
{
    size_t i, len;
    nri_mount *tmp = nullptr;

    if (mp == nullptr || mp->len == 0) {
        return true;
    }
    len = mp->len;

    con.mounts = (nri_mount **)util_smart_calloc_s(sizeof(nri_mount *), len);
    if (con.mounts == nullptr) {
        ERROR("Out of memory");
        return false;
    }

    for (i = 0; i < len; i++) {
        tmp = (nri_mount *)util_common_calloc_s(sizeof(nri_mount));
        char path[PATH_MAX] = { 0 };

        if (!util_clean_path(mp->values[i]->destination, path, sizeof(path))) {
            ERROR("Failed to get clean path for mount dest path: %s", mp->values[i]->destination);
            goto error_out;
        }
        tmp->destination = util_strdup_s(path);

        if (!util_clean_path(mp->values[i]->source, path, sizeof(path))) {
            ERROR("Failed to get clean path for mount src path: %s", mp->values[i]->source);
            goto error_out;
        }
        tmp->source = util_strdup_s(path);

        if (util_array_append(&(tmp->options), "rbind") != 0) {
            ERROR("Failed to append options");
            goto error_out;
        }
        if (util_array_append(&(tmp->options), mp->values[i]->propagation) != 0) {
            ERROR("Failed to append options");
            goto error_out;
        }

        if (mp->values[i]->rw) {
            if (util_array_append(&(tmp->options), "rw") != 0) {
                ERROR("Failed to append options");
                goto error_out;
            }
        } else {
            if (util_array_append(&(tmp->options), "ro") != 0) {
                ERROR("Failed to append options");
                goto error_out;
            }
        }

        tmp->type = util_strdup_s("bind");
        con.mounts[i] = tmp;
        con.mounts_len++;
        tmp = nullptr;
    }

    return true;

error_out:
    free_nri_mount(tmp);
    return false;
}

// container info is incomplete because container in excution is not created
auto ContainerToNRIByConConfig(const runtime::v1::ContainerConfig &containerConfig, nri_container &con) -> bool
{
    // todo: can not get container id and state from containerConfig
    if (containerConfig.has_metadata() && !containerConfig.metadata().name().empty()) {
        con.name = util_strdup_s(containerConfig.metadata().name().c_str());
    }

    Errors tmpError;

    con.labels = Transform::ProtobufMapToJsonMapForString(containerConfig.labels(), tmpError);
    if (con.labels == nullptr) {
        ERROR("Failed to transform labels to nri for con : %s, : %s", con.name, tmpError.GetMessage().c_str());
        return false;
    }

    con.annotations = Transform::ProtobufMapToJsonMapForString(containerConfig.annotations(), tmpError);
    if (con.annotations == nullptr) {
        ERROR("Failed to transform annotations to nri for con : %s, : %s", con.name, tmpError.GetMessage().c_str());
        return false;
    }

    con.args = Transform::RepeatedPtrFieldToCharArray(containerConfig.args());
    if (con.args == nullptr) {
        ERROR("Failed to transform args to nri for con : %s, : %s", con.name, tmpError.GetMessage().c_str());
        return false;
    }
    con.args_len = containerConfig.args_size();

    auto envVect = CRIHelpersV1::GenerateEnvList(containerConfig.envs());
    con.env = Transform::StringVectorToCharArray(envVect);
    if (con.env == nullptr) {
        ERROR("Failed to transform env to nri for con : %s", con.name);
        return false;
    }
    con.env_len = containerConfig.envs_size();

    if (!CRIMountArrToNRI(containerConfig, con)) {
        ERROR("Failed to transform mounts to nri for con : %s", con.name);
        return false;
    }
    return true;

    // todo: can not get container hooks and pid from containerConfig
}

// container info is incomplete because container in excution is not created
auto ContainerToNRIByID(const std::string &id, nri_container &con) -> bool
{
    container_t *cont = nullptr;
    bool ret = false;

    cont = containers_store_get(id.c_str());
    if (cont == nullptr || cont->common_config == nullptr) {
        ERROR("No such container:%s", id.c_str());
        goto out;
    }

    con.id = util_strdup_s(id.c_str());

    con.name = util_strdup_s(cont->common_config->name);

    con.labels = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if (con.labels == nullptr) {
        ERROR("Out of memory");
        goto out;
    }
    con.annotations = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if (con.annotations == nullptr) {
        ERROR("Out of memory");
        goto out;
    }
    // state
    if (dup_json_map_string_string(cont->common_config->config->labels, con.labels) != 0) {
        ERROR("Failed to copy labels for con: %s", cont->common_config->name);
        goto out;
    }
    if (dup_json_map_string_string(cont->common_config->config->annotations, con.annotations) != 0) {
        ERROR("Failed to copy labels for con: %s", cont->common_config->name);
        goto out;
    }

    con.args = util_copy_array_by_len(cont->common_config->args, cont->common_config->args_len);
    if (cont->common_config->args_len != 0 && con.args == nullptr) {
        ERROR("Failed to copy args for con: %s", cont->common_config->name);
        goto out;
    }
    con.args_len = cont->common_config->args_len;

    con.env = util_copy_array_by_len(cont->common_config->config->env, cont->common_config->config->env_len);
    if (cont->common_config->config->env_len != 0 && con.env == nullptr) {
        ERROR("Failed to copy env for con: %s", cont->common_config->name);
        goto out;
    }
    con.env_len = cont->common_config->config->env_len;

    if (!MountPointsElementToNRI(cont->common_config->mount_points, con)) {
        ERROR("Failed to transform mounts to nri for con : %s", con.name);
        goto out;
    }

    // todo: can convert hostconfig's hook_spec to nri spec

    con.pid = container_state_get_pid(cont->state);
    if (con.pid < 0) {
        ERROR("Container %s pid %d invalid", cont->common_config->name, con.pid);
        goto out;
    }

    con.pod_sandbox_id = util_strdup_s(cont->common_config->sandbox_info->id);
    ret = true;

out:
    container_unref(cont);
    return ret;
}

auto LinuxResourcesFromNRI(const nri_linux_resources *src, runtime::v1::LinuxContainerResources &resources) -> bool
{
    if (src == nullptr) {
        return false;
    }

    if (src->memory != nullptr) {
        resources.set_memory_limit_in_bytes(*src->memory->limit);
        resources.set_oom_score_adj(DefaultOOMScoreAdj);
    }

    if (src->cpu != nullptr) {
        if (src->cpu->shares != nullptr) {
            resources.set_cpu_shares(*src->cpu->shares);
        }
        if (src->cpu->quota != nullptr) {
            resources.set_cpu_quota(*src->cpu->quota);
        }
        if (src->cpu->period != nullptr) {
            resources.set_cpu_period(*src->cpu->period);
        }

        resources.set_cpuset_cpus(src->cpu->cpus);
        resources.set_cpuset_mems(src->cpu->mems);
    }

    if (src->hugepage_limits != nullptr && src->hugepage_limits_len > 0) {
        for (size_t i = 0; i < src->hugepage_limits_len; i++) {
            if (src->hugepage_limits[i] != nullptr) {
                auto limit = resources.add_hugepage_limits();
                limit->set_page_size(src->hugepage_limits[i]->page_size);
                limit->set_limit(src->hugepage_limits[i]->limit);
            }
        }
    }

    if (src->unified != nullptr) {
        Transform::JsonMapToProtobufMapForString(src->unified, *resources.mutable_unified());
    }

    return true;
}

auto LinuxResourcesToNRI(const runtime::v1::LinuxContainerResources &src) -> nri_linux_resources *
{
    nri_linux_resources *resources = nullptr;

    resources = init_nri_linux_resources();
    if (resources == nullptr) {
        ERROR("Failed to init nri linux resources");
        return nullptr;
    }

    resources->cpu->shares = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
    if (resources->cpu->shares == nullptr) {
        ERROR("Out of memory");
        goto error_out;
    }
    *(resources->cpu->shares) = src.cpu_shares();

    resources->cpu->quota = (int64_t *)util_common_calloc_s(sizeof(int64_t));
    if (resources->cpu->quota == nullptr) {
        ERROR("Out of memory");
        goto error_out;
    }
    *(resources->cpu->quota) = src.cpu_quota();

    resources->cpu->period = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
    if (resources->cpu->period == nullptr) {
        ERROR("Out of memory");
        goto error_out;
    }
    *(resources->cpu->period) = src.cpu_period();

    resources->cpu->cpus = util_strdup_s(src.cpuset_cpus().c_str());
    resources->cpu->mems = util_strdup_s(src.cpuset_mems().c_str());

    resources->memory->limit = (int64_t *)util_common_calloc_s(sizeof(int64_t));
    if (resources->memory->limit == nullptr) {
        ERROR("Out of memory");
        goto error_out;
    }
    *(resources->memory->limit) = src.memory_limit_in_bytes();

    resources->hugepage_limits = (nri_hugepage_limit **)util_smart_calloc_s(sizeof(nri_hugepage_limit *),
                                                                            src.hugepage_limits_size());
    if (resources->hugepage_limits == nullptr) {
        ERROR("Out of memory");
        goto error_out;
    }

    for (int i = 0; i < src.hugepage_limits_size(); i++) {
        resources->hugepage_limits[i] = (nri_hugepage_limit *)util_common_calloc_s(sizeof(nri_hugepage_limit));
        if (resources->hugepage_limits[i] == nullptr) {
            ERROR("Out of memory");
            goto error_out;
        }
        resources->hugepage_limits[i]->page_size = util_strdup_s(src.hugepage_limits(i).page_size().c_str());
        resources->hugepage_limits[i]->limit = src.hugepage_limits(i).limit();
        resources->hugepage_limits_len++;
    }

    return resources;

error_out:
    free_nri_linux_resources(resources);
    resources = nullptr;
    return resources;
}

auto PodSandboxesToNRI(const std::vector<std::shared_ptr<sandbox::Sandbox>> &arrs,
                       std::vector<nri_pod_sandbox *> &pods) -> bool
{
    size_t i = 0;
    for (i = 0; i < arrs.size(); i++) {
        nri_pod_sandbox *pod = (nri_pod_sandbox *)util_common_calloc_s(sizeof(nri_pod_sandbox));
        if (pod == nullptr) {
            ERROR("Out of memory");
            return false;
        }
        if (!PodSandboxToNRI(arrs[i], *pod)) {
            ERROR("Failed to transform pod to nri for pod : %s", arrs[i]->GetName().c_str());
            return false;
        }
        pods.push_back(pod);
    }

    return true;
}

auto ContainersToNRI(std::vector<std::unique_ptr<runtime::v1::Container>> &containers,
                     std::vector<nri_container *> &cons) -> bool
{
    size_t i = 0;
    for (i = 0; i < containers.size(); i++) {
        nri_container *con = (nri_container *)util_common_calloc_s(sizeof(nri_container));
        if (con == nullptr) {
            ERROR("Out of memory");
            return false;
        }
        if (!ContainerToNRIByID(containers[i].get()->id(), *con)) {
            ERROR("Failed to transform container to nri for container : %s", containers[i]->metadata().name().c_str());
            return false;
        }
        cons.push_back(con);
    }

    return true;
}