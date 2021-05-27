/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-12-15
 * Description: provide cri container manager service function implementation
 *********************************************************************************/

#include "cri_container_manager_service_impl.h"
#include "cri_helpers.h"
#include "utils.h"
#include "errors.h"
#include "isula_libutils/log.h"
#include "isula_libutils/container_stop_request.h"
#include "naming.h"
#include "path.h"
#include "service_container_api.h"
#include "request_cache.h"
#include "url.h"
#include "ws_server.h"

namespace CRI {
auto ContainerManagerServiceImpl::GetContainerOrSandboxRuntime(const std::string &realID, Errors &error) -> std::string
{
    std::string runtime;
    if (m_cb == nullptr || m_cb->container.get_runtime == nullptr) {
        error.SetError("Unimplemented callback");
        return runtime;
    }
    container_get_runtime_response *response { nullptr };

    if (m_cb->container.get_runtime(realID.c_str(), &response) != 0) {
        if (response != nullptr && response->errmsg != nullptr) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call get id callback");
        }
        goto cleanup;
    }

    if (response->runtime != nullptr) {
        runtime = response->runtime;
    }

cleanup:
    free_container_get_runtime_response(response);
    return runtime;
}

auto ContainerManagerServiceImpl::PackCreateContainerHostConfigDevices(
    const runtime::v1alpha2::ContainerConfig &containerConfig, host_config *hostconfig, Errors &error) -> int
{
    int ret { 0 };

    if (containerConfig.devices_size() == 0) {
        return 0;
    }
    if (static_cast<size_t>(containerConfig.devices_size()) > SIZE_MAX / sizeof(host_config_devices_element *)) {
        error.Errorf("Invalid device size");
        return -1;
    }
    hostconfig->devices = (host_config_devices_element **)util_common_calloc_s(containerConfig.devices_size() *
                                                                               sizeof(host_config_devices_element *));
    if (hostconfig->devices == nullptr) {
        error.Errorf("Out of memory");
        ret = -1;
        goto out;
    }
    for (int i = 0; i < containerConfig.devices_size(); i++) {
        hostconfig->devices[i] =
            (host_config_devices_element *)util_common_calloc_s(sizeof(host_config_devices_element));
        if (hostconfig->devices[i] == nullptr) {
            ret = -1;
            goto out;
        }
        hostconfig->devices[i]->path_on_host = util_strdup_s(containerConfig.devices(i).host_path().c_str());
        hostconfig->devices[i]->path_in_container = util_strdup_s(containerConfig.devices(i).container_path().c_str());
        hostconfig->devices[i]->cgroup_permissions = util_strdup_s(containerConfig.devices(i).permissions().c_str());
        hostconfig->devices_len++;
    }
out:
    return ret;
}

auto ContainerManagerServiceImpl::PackCreateContainerHostConfigSecurityContext(
    const runtime::v1alpha2::ContainerConfig &containerConfig, host_config *hostconfig, Errors &error) -> int
{
    if (!containerConfig.linux().has_security_context()) {
        return 0;
    }
    // security Opt Separator Change Version : k8s v1.23.0 (Corresponds to docker 1.11.x)
    // New version '=' , old version ':', iSulad cri is based on v18.09, so iSulad cri use new version separator
    const char securityOptSep { '=' };
    std::vector<std::string> securityOpts = CRIHelpers::GetSecurityOpts(
                                                containerConfig.linux().security_context().seccomp_profile_path(), securityOptSep, error);
    if (error.NotEmpty()) {
        error.Errorf("failed to generate security options for container %s", containerConfig.metadata().name().c_str());
        return -1;
    }
    if (!securityOpts.empty()) {
        char **tmp_security_opt = nullptr;
        if (securityOpts.size() > (SIZE_MAX / sizeof(char *)) - hostconfig->security_opt_len) {
            error.Errorf("Out of memory");
            return -1;
        }
        size_t newSize = (hostconfig->security_opt_len + securityOpts.size()) * sizeof(char *);
        size_t oldSize = hostconfig->security_opt_len * sizeof(char *);
        int ret = util_mem_realloc((void **)(&tmp_security_opt), newSize, (void *)hostconfig->security_opt, oldSize);
        if (ret != 0) {
            error.Errorf("Out of memory");
            return -1;
        }
        hostconfig->security_opt = tmp_security_opt;
        for (const auto &securityOpt : securityOpts) {
            hostconfig->security_opt[hostconfig->security_opt_len] = util_strdup_s(securityOpt.c_str());
            hostconfig->security_opt_len++;
        }
    }
    return 0;
}

auto ContainerManagerServiceImpl::GenerateCreateContainerHostConfig(
    const runtime::v1alpha2::ContainerConfig &containerConfig, Errors &error) -> host_config *
{
    host_config *hostconfig = (host_config *)util_common_calloc_s(sizeof(host_config));
    if (hostconfig == nullptr) {
        error.SetError("Out of memory");
        return nullptr;
    }
    // iSulad: limit the number of threads in container
    if (containerConfig.annotations().count("cgroup.pids.max") != 0) {
        long long int converted = -1;
        int ret = util_safe_llong(containerConfig.annotations().at("cgroup.pids.max").c_str(), &converted);
        if (ret != 0) {
            error.SetError("Cgroup.pids.max is not a valid numeric string");
            goto cleanup;
        }
        hostconfig->pids_limit = converted;
    }
    CRIHelpers::GenerateMountBindings(containerConfig.mounts(), hostconfig, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    if (PackCreateContainerHostConfigDevices(containerConfig, hostconfig, error) != 0) {
        error.SetError("Failed to pack devices to host config");
        goto cleanup;
    }

    if (PackCreateContainerHostConfigSecurityContext(containerConfig, hostconfig, error) != 0) {
        error.SetError("Failed to security context to host config");
        goto cleanup;
    }

    return hostconfig;

cleanup:
    free_host_config(hostconfig);
    return nullptr;
}

void ContainerManagerServiceImpl::MakeContainerConfig(const runtime::v1alpha2::ContainerConfig &config,
                                                      container_config *cConfig, Errors &error)
{
    if (config.command_size() > 0) {
        if (static_cast<size_t>(config.command_size()) > SIZE_MAX / sizeof(char *)) {
            error.SetError("Invalid command size");
            return;
        }
        cConfig->entrypoint = (char **)util_common_calloc_s(config.command_size() * sizeof(char *));
        if (cConfig->entrypoint == nullptr) {
            error.SetError("Out of memory");
            return;
        }
        for (int i = 0; i < config.command_size(); i++) {
            cConfig->entrypoint[i] = util_strdup_s(config.command(i).c_str());
            cConfig->entrypoint_len++;
        }
    }

    if (config.args_size() > 0) {
        if (static_cast<size_t>(config.args_size()) > SIZE_MAX / sizeof(char *)) {
            error.SetError("Invalid argument size");
            return;
        }
        cConfig->cmd = (char **)util_common_calloc_s(config.args_size() * sizeof(char *));
        if (cConfig->cmd == nullptr) {
            error.SetError("Out of memory");
            return;
        }
        for (int i = 0; i < config.args_size(); i++) {
            cConfig->cmd[i] = util_strdup_s(config.args(i).c_str());
            cConfig->cmd_len++;
        }
    }

    if (config.envs_size() > 0) {
        if (static_cast<size_t>(config.envs_size()) > SIZE_MAX / sizeof(char *)) {
            error.SetError("Invalid env size");
            return;
        }
        cConfig->env = (char **)util_common_calloc_s(config.envs_size() * sizeof(char *));
        if (cConfig->env == nullptr) {
            error.SetError("Out of memory");
            return;
        }
        auto envVect = CRIHelpers::GenerateEnvList(config.envs());
        for (size_t i = 0; i < envVect.size(); i++) {
            cConfig->env[i] = util_strdup_s(envVect.at(i).c_str());
            cConfig->env_len++;
        }
    }

    if (!config.working_dir().empty()) {
        cConfig->working_dir = util_strdup_s(config.working_dir().c_str());
    }
}

auto ContainerManagerServiceImpl::GenerateCreateContainerCustomConfig(
    const std::string &realPodSandboxID, const runtime::v1alpha2::ContainerConfig &containerConfig,
    const runtime::v1alpha2::PodSandboxConfig &podSandboxConfig, Errors &error) -> container_config *
{
    container_config *custom_config = (container_config *)util_common_calloc_s(sizeof(container_config));
    if (custom_config == nullptr) {
        error.SetError("Out of memory");
        goto cleanup;
    }
    custom_config->labels = CRIHelpers::MakeLabels(containerConfig.labels(), error);
    if (error.NotEmpty()) {
        goto cleanup;
    }
    if (append_json_map_string_string(custom_config->labels, CRIHelpers::Constants::CONTAINER_TYPE_LABEL_KEY.c_str(),
                                      CRIHelpers::Constants::CONTAINER_TYPE_LABEL_CONTAINER.c_str()) != 0) {
        error.SetError("Append map string string failed");
        goto cleanup;
    }

    custom_config->annotations = CRIHelpers::MakeAnnotations(containerConfig.annotations(), error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    if (!podSandboxConfig.log_directory().empty() || !containerConfig.log_path().empty()) {
        std::string logpath = podSandboxConfig.log_directory() + "/" + containerConfig.log_path();
        char real_logpath[PATH_MAX] { 0 };
        if (util_clean_path(logpath.c_str(), real_logpath, sizeof(real_logpath)) == nullptr) {
            ERROR("Failed to clean path: %s", logpath.c_str());
            error.Errorf("Failed to clean path: %s", logpath.c_str());
            goto cleanup;
        }

        if (append_json_map_string_string(custom_config->labels,
                                          CRIHelpers::Constants::CONTAINER_LOGPATH_LABEL_KEY.c_str(),
                                          real_logpath) != 0) {
            error.SetError("Append map string string failed");
            goto cleanup;
        }
    }

    if (append_json_map_string_string(custom_config->annotations,
                                      CRIHelpers::Constants::CONTAINER_TYPE_ANNOTATION_KEY.c_str(),
                                      CRIHelpers::Constants::CONTAINER_TYPE_ANNOTATION_CONTAINER.c_str()) != 0) {
        error.SetError("Append map string string failed");
        goto cleanup;
    }
    if (append_json_map_string_string(custom_config->annotations,
                                      CRIHelpers::Constants::SANDBOX_ID_ANNOTATION_KEY.c_str(),
                                      realPodSandboxID.c_str()) != 0) {
        error.SetError("Append map string string failed");
        goto cleanup;
    }

    if (append_json_map_string_string(custom_config->labels, CRIHelpers::Constants::SANDBOX_ID_LABEL_KEY.c_str(),
                                      realPodSandboxID.c_str()) != 0) {
        error.SetError("Append map string string failed");
        goto cleanup;
    }
    MakeContainerConfig(containerConfig, custom_config, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }
    return custom_config;

cleanup:
    free_container_config(custom_config);
    return nullptr;
}

container_create_request *
ContainerManagerServiceImpl::GenerateCreateContainerRequest(const std::string &realPodSandboxID,
                                                            const runtime::v1alpha2::ContainerConfig &containerConfig,
                                                            const runtime::v1alpha2::PodSandboxConfig &podSandboxConfig,
                                                            const std::string &podSandboxRuntime, Errors &error)
{
    struct parser_context ctx {
        OPT_GEN_SIMPLIFY, 0
    };
    parser_error perror { nullptr };

    container_create_request *request = (container_create_request *)util_common_calloc_s(sizeof(*request));
    if (request == nullptr) {
        error.SetError("Out of memory");
        return nullptr;
    }

    std::string cname = CRINaming::MakeContainerName(podSandboxConfig, containerConfig);
    request->id = util_strdup_s(cname.c_str());

    if (!podSandboxRuntime.empty()) {
        request->runtime = util_strdup_s(podSandboxRuntime.c_str());
    }

    if (!containerConfig.image().image().empty()) {
        request->image = util_strdup_s(containerConfig.image().image().c_str());
    }

    container_config *custom_config { nullptr };

    host_config *hostconfig = GenerateCreateContainerHostConfig(containerConfig, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    if (podSandboxConfig.has_linux() && !podSandboxConfig.linux().cgroup_parent().empty()) {
        hostconfig->cgroup_parent = util_strdup_s(podSandboxConfig.linux().cgroup_parent().c_str());
    }

    custom_config = GenerateCreateContainerCustomConfig(realPodSandboxID, containerConfig, podSandboxConfig, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    CRIHelpers::UpdateCreateConfig(custom_config, hostconfig, containerConfig, realPodSandboxID, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    request->hostconfig = host_config_generate_json(hostconfig, &ctx, &perror);
    if (request->hostconfig == nullptr) {
        error.Errorf("Failed to generate host config json: %s", perror);
        free_container_create_request(request);
        request = nullptr;
        goto cleanup;
    }

    request->customconfig = container_config_generate_json(custom_config, &ctx, &perror);
    if (request->customconfig == nullptr) {
        error.Errorf("Failed to generate custom config json: %s", perror);
        free_container_create_request(request);
        request = nullptr;
        goto cleanup;
    }

cleanup:
    free_host_config(hostconfig);
    free_container_config(custom_config);
    free(perror);
    return request;
}

std::string ContainerManagerServiceImpl::CreateContainer(const std::string &podSandboxID,
                                                         const runtime::v1alpha2::ContainerConfig &containerConfig,
                                                         const runtime::v1alpha2::PodSandboxConfig &podSandboxConfig,
                                                         Errors &error)
{
    std::string response_id;
    std::string podSandboxRuntime;

    if (m_cb == nullptr || m_cb->container.create == nullptr) {
        error.SetError("Unimplemented callback");
        return response_id;
    }
    container_create_request *request { nullptr };
    container_create_response *response { nullptr };

    std::string realPodSandboxID = CRIHelpers::GetRealContainerOrSandboxID(m_cb, podSandboxID, true, error);
    if (error.NotEmpty()) {
        ERROR("Failed to find sandbox id %s: %s", podSandboxID.c_str(), error.GetCMessage());
        error.Errorf("Failed to find sandbox id %s: %s", podSandboxID.c_str(), error.GetCMessage());
        goto cleanup;
    }

    podSandboxRuntime = GetContainerOrSandboxRuntime(realPodSandboxID, error);

    request = GenerateCreateContainerRequest(realPodSandboxID, containerConfig, podSandboxConfig, podSandboxRuntime,
                                             error);
    if (error.NotEmpty()) {
        error.SetError("Failed to generate create container request");
        goto cleanup;
    }

    if (m_cb->container.create(request, &response) != 0) {
        if (response != nullptr && (response->errmsg != nullptr)) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call create container callback");
        }
        goto cleanup;
    }

    response_id = response->id;

cleanup:
    free_container_create_request(request);
    free_container_create_response(response);
    return response_id;
}

void ContainerManagerServiceImpl::CreateContainerLogSymlink(const std::string &containerID, Errors &error)
{
    char *path { nullptr };
    char *realPath { nullptr };

    CRIHelpers::GetContainerLogPath(containerID, &path, &realPath, error);
    if (error.NotEmpty()) {
        error.Errorf("failed to get container %s log path: %s", containerID.c_str(), error.GetCMessage());
        return;
    }
    if (path == nullptr) {
        INFO("Container %s log path isn't specified, will not create the symlink", containerID.c_str());
        goto cleanup;
    }
    if (realPath != nullptr) {
        if (util_path_remove(path) == 0) {
            WARN("Deleted previously existing symlink file: %s", path);
        }
        if (symlink(realPath, path) != 0) {
            error.Errorf("failed to create symbolic link %s to the container log file %s for container %s: %s", path,
                         realPath, containerID.c_str(), strerror(errno));
            goto cleanup;
        }
    } else {
        WARN("Cannot create symbolic link because container log file doesn't exist!");
    }
cleanup:
    free(path);
    free(realPath);
}

void ContainerManagerServiceImpl::StartContainer(const std::string &containerID, Errors &error)
{
    if (containerID.empty()) {
        error.SetError("Invalid empty container id.");
        return;
    }
    std::string realContainerID = CRIHelpers::GetRealContainerOrSandboxID(m_cb, containerID, false, error);
    if (error.NotEmpty()) {
        ERROR("Failed to find container id %s: %s", containerID.c_str(), error.GetCMessage());
        error.Errorf("Failed to find container id %s: %s", containerID.c_str(), error.GetCMessage());
        return;
    }

    if (m_cb == nullptr || m_cb->container.start == nullptr) {
        error.SetError("Unimplemented callback");
        return;
    }

    container_start_response *response { nullptr };
    int ret {};
    container_start_request *request = (container_start_request *)util_common_calloc_s(sizeof(container_start_request));
    if (request == nullptr) {
        error.SetError("Out of memory");
        goto cleanup;
    }
    request->id = util_strdup_s(realContainerID.c_str());

    ret = m_cb->container.start(request, &response, -1, nullptr, nullptr);

    // Create container log symlink for all containers (including failed ones).
    CreateContainerLogSymlink(realContainerID, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    if (ret != 0) {
        if (response != nullptr && response->errmsg != nullptr) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call start container callback");
        }
        goto cleanup;
    }
cleanup:
    free_container_start_request(request);
    free_container_start_response(response);
}

void ContainerManagerServiceImpl::StopContainer(const std::string &containerID, int64_t timeout, Errors &error)
{
    CRIHelpers::StopContainer(m_cb, containerID, timeout, error);
}

void ContainerManagerServiceImpl::RemoveContainer(const std::string &containerID, Errors &error)
{
    CRIHelpers::RemoveContainer(m_cb, containerID, error);
}

void ContainerManagerServiceImpl::ListContainersFromGRPC(const runtime::v1alpha2::ContainerFilter *filter,
                                                         container_list_request **request, Errors &error)
{
    *request = (container_list_request *)util_common_calloc_s(sizeof(container_list_request));
    if (*request == nullptr) {
        error.SetError("Out of memory");
        return;
    }
    (*request)->all = true;

    (*request)->filters = (defs_filters *)util_common_calloc_s(sizeof(defs_filters));
    if ((*request)->filters == nullptr) {
        error.SetError("Out of memory");
        return;
    }
    // Add filter to get only non-sandbox containers
    if (CRIHelpers::FiltersAddLabel((*request)->filters, CRIHelpers::Constants::CONTAINER_TYPE_LABEL_KEY,
                                    CRIHelpers::Constants::CONTAINER_TYPE_LABEL_CONTAINER) != 0) {
        error.SetError("Failed to add filter");
        return;
    }

    if (filter != nullptr) {
        if (!filter->id().empty()) {
            if (CRIHelpers::FiltersAdd((*request)->filters, "id", filter->id()) != 0) {
                error.SetError("Failed to add filter");
                return;
            }
        }
        if (filter->has_state()) {
            if (CRIHelpers::FiltersAdd((*request)->filters, "status",
                                       CRIHelpers::ToIsuladContainerStatus(filter->state())) != 0) {
                error.SetError("Failed to add filter");
                return;
            }
        }
        if (!filter->pod_sandbox_id().empty()) {
            if (CRIHelpers::FiltersAddLabel((*request)->filters, CRIHelpers::Constants::SANDBOX_ID_LABEL_KEY,
                                            filter->pod_sandbox_id()) != 0) {
                error.SetError("Failed to add filter");
                return;
            }
        }

        for (auto &iter : filter->label_selector()) {
            if (CRIHelpers::FiltersAddLabel((*request)->filters, iter.first, iter.second) != 0) {
                error.SetError("Failed to add filter");
                return;
            }
        }
    }
}

void ContainerManagerServiceImpl::ListContainersToGRPC(container_list_response *response,
                                                       std::vector<std::unique_ptr<runtime::v1alpha2::Container>> *pods,
                                                       Errors &error)
{
    for (size_t i {}; i < response->containers_len; i++) {
        std::unique_ptr<runtime::v1alpha2::Container> container(new (std::nothrow) runtime::v1alpha2::Container);
        if (container == nullptr) {
            error.SetError("Out of memory");
            return;
        }

        if (response->containers[i]->id != nullptr) {
            container->set_id(response->containers[i]->id);
        }

        container->set_created_at(response->containers[i]->created);

        if (response->containers[i]->name != nullptr) {
            CRINaming::ParseContainerName(response->containers[i]->name, container->mutable_metadata(), error);
            if (error.NotEmpty()) {
                return;
            }
        }

        CRIHelpers::ExtractLabels(response->containers[i]->labels, *container->mutable_labels());

        CRIHelpers::ExtractAnnotations(response->containers[i]->annotations, *container->mutable_annotations());

        if (response->containers[i]->labels != nullptr) {
            for (size_t j = 0; j < response->containers[i]->labels->len; j++) {
                if (strcmp(response->containers[i]->labels->keys[j],
                           CRIHelpers::Constants::SANDBOX_ID_LABEL_KEY.c_str()) == 0) {
                    container->set_pod_sandbox_id(response->containers[i]->labels->values[j]);
                    break;
                }
            }
        }

        if (response->containers[i]->image != nullptr) {
            runtime::v1alpha2::ImageSpec *image = container->mutable_image();
            image->set_image(response->containers[i]->image);
            std::string imageID =
                CRIHelpers::ToPullableImageID(response->containers[i]->image, response->containers[i]->image_ref);
            container->set_image_ref(imageID);
        }

        runtime::v1alpha2::ContainerState state =
            CRIHelpers::ContainerStatusToRuntime(Container_Status(response->containers[i]->status));
        container->set_state(state);

        pods->push_back(move(container));
    }
}

void ContainerManagerServiceImpl::ListContainers(const runtime::v1alpha2::ContainerFilter *filter,
                                                 std::vector<std::unique_ptr<runtime::v1alpha2::Container>> *containers,
                                                 Errors &error)
{
    if (m_cb == nullptr || m_cb->container.list == nullptr) {
        error.SetError("Unimplemented callback");
        return;
    }

    container_list_response *response { nullptr };
    container_list_request *request { nullptr };
    ListContainersFromGRPC(filter, &request, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    if (m_cb->container.list(request, &response) != 0) {
        if (response != nullptr && response->errmsg != nullptr) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call list container callback");
        }
        goto cleanup;
    }

    ListContainersToGRPC(response, containers, error);

cleanup:
    free_container_list_request(request);
    free_container_list_response(response);
}

auto ContainerManagerServiceImpl::PackContainerStatsFilter(const runtime::v1alpha2::ContainerStatsFilter *filter,
                                                           container_stats_request *request, Errors &error) -> int
{
    if (filter == nullptr) {
        return 0;
    }

    if (!filter->id().empty()) {
        if (CRIHelpers::FiltersAdd(request->filters, "id", filter->id()) != 0) {
            error.SetError("Failed to add filter");
            return -1;
        }
    }
    if (!filter->pod_sandbox_id().empty()) {
        if (CRIHelpers::FiltersAddLabel(request->filters, CRIHelpers::Constants::SANDBOX_ID_LABEL_KEY,
                                        filter->pod_sandbox_id()) != 0) {
            error.SetError("Failed to add filter");
            return -1;
        }
    }

    // Add some label
    if (CRIHelpers::FiltersAddLabel(request->filters, CRIHelpers::Constants::CONTAINER_TYPE_LABEL_KEY,
                                    CRIHelpers::Constants::CONTAINER_TYPE_LABEL_CONTAINER) != 0) {
        error.SetError("Failed to add filter");
        return -1;
    }
    for (auto &iter : filter->label_selector()) {
        if (CRIHelpers::FiltersAddLabel(request->filters, iter.first, iter.second) != 0) {
            error.SetError("Failed to add filter");
            return -1;
        }
    }

    return 0;
}

void ContainerManagerServiceImpl::PackContainerStatsAttributes(
    const char *id, std::unique_ptr<runtime::v1alpha2::ContainerStats> &container, Errors &error)
{
    if (id == nullptr) {
        return;
    }

    container->mutable_attributes()->set_id(id);
    auto status = ContainerStatus(std::string(id), error);
    if (status == nullptr) {
        return;
    }

    if (status->has_metadata()) {
        std::unique_ptr<runtime::v1alpha2::ContainerMetadata> metadata(
            new (std::nothrow) runtime::v1alpha2::ContainerMetadata(status->metadata()));
        if (metadata == nullptr) {
            error.SetError("Out of memory");
            ERROR("Out of memory");
            return;
        }
        container->mutable_attributes()->set_allocated_metadata(metadata.release());
    }
    if (status->labels_size() > 0) {
        auto labels = container->mutable_attributes()->mutable_labels();
        *labels = status->labels();
    }
    if (status->annotations_size() > 0) {
        auto annotations = container->mutable_attributes()->mutable_annotations();
        *annotations = status->annotations();
    }
}

void ContainerManagerServiceImpl::SetFsUsage(const imagetool_fs_info *fs_usage, int64_t timestamp,
                                             std::unique_ptr<runtime::v1alpha2::ContainerStats> &container)
{
    if (fs_usage == nullptr || fs_usage->image_filesystems_len == 0 || fs_usage->image_filesystems[0] == nullptr) {
        container->mutable_writable_layer()->mutable_used_bytes()->set_value(0);
        container->mutable_writable_layer()->mutable_inodes_used()->set_value(0);
        return;
    }

    if (fs_usage->image_filesystems[0]->used_bytes == nullptr) {
        container->mutable_writable_layer()->mutable_used_bytes()->set_value(0);
    } else {
        container->mutable_writable_layer()->mutable_used_bytes()->set_value(
            fs_usage->image_filesystems[0]->used_bytes->value);
    }

    if (fs_usage->image_filesystems[0]->inodes_used == nullptr) {
        container->mutable_writable_layer()->mutable_inodes_used()->set_value(0);
    } else {
        container->mutable_writable_layer()->mutable_inodes_used()->set_value(
            fs_usage->image_filesystems[0]->inodes_used->value);
    }
    container->mutable_writable_layer()->set_timestamp(timestamp);

    if (fs_usage->image_filesystems[0]->fs_id != nullptr &&
        fs_usage->image_filesystems[0]->fs_id->mountpoint != nullptr) {
        container->mutable_writable_layer()->mutable_fs_id()->set_mountpoint(
            fs_usage->image_filesystems[0]->fs_id->mountpoint);
    }
}

void ContainerManagerServiceImpl::PackContainerStatsFilesystemUsage(
    const char *id, const char *image_type, int64_t timestamp,
    std::unique_ptr<runtime::v1alpha2::ContainerStats> &container)
{
    if (id == nullptr || image_type == nullptr) {
        return;
    }

    imagetool_fs_info *fs_usage { nullptr };
    if (im_get_container_filesystem_usage(image_type, id, &fs_usage) != 0) {
        ERROR("Failed to get container filesystem usage");
    }

    SetFsUsage(fs_usage, timestamp, container);
    free_imagetool_fs_info(fs_usage);
}

void ContainerManagerServiceImpl::ContainerStatsToGRPC(
    container_stats_response *response,
    std::vector<std::unique_ptr<runtime::v1alpha2::ContainerStats>> *containerstats, Errors &error)
{
    if (response == nullptr) {
        return;
    }

    for (size_t i {}; i < response->container_stats_len; i++) {
        using ContainerStatsPtr = std::unique_ptr<runtime::v1alpha2::ContainerStats>;
        ContainerStatsPtr container(new (std::nothrow) runtime::v1alpha2::ContainerStats);
        if (container == nullptr) {
            ERROR("Out of memory");
            return;
        }

        PackContainerStatsAttributes(response->container_stats[i]->id, container, error);
        if (error.NotEmpty()) {
            return;
        }

        int64_t timestamp = util_get_now_time_nanos();
        PackContainerStatsFilesystemUsage(response->container_stats[i]->id, response->container_stats[i]->image_type,
                                          timestamp, container);
        if (response->container_stats[i]->mem_used != 0u) {
            uint64_t workingset = response->container_stats[i]->mem_used;
            if (response->container_stats[i]->inactive_file_total < response->container_stats[i]->mem_used) {
                workingset = response->container_stats[i]->mem_used - response->container_stats[i]->inactive_file_total;
            }
            container->mutable_memory()->mutable_working_set_bytes()->set_value(workingset);
            container->mutable_memory()->set_timestamp(timestamp);
        }

        if (response->container_stats[i]->cpu_use_nanos != 0u) {
            container->mutable_cpu()->mutable_usage_core_nano_seconds()->set_value(
                response->container_stats[i]->cpu_use_nanos);
            container->mutable_cpu()->set_timestamp(timestamp);
        }

        containerstats->push_back(move(container));
    }
}

void ContainerManagerServiceImpl::ListContainerStats(
    const runtime::v1alpha2::ContainerStatsFilter *filter,
    std::vector<std::unique_ptr<runtime::v1alpha2::ContainerStats>> *containerstats, Errors &error)
{
    if (m_cb == nullptr || m_cb->container.stats == nullptr) {
        error.SetError("Unimplemented callback");
        return;
    }
    if (containerstats == nullptr) {
        error.SetError("Invalid arguments");
        return;
    }

    container_stats_response *response { nullptr };
    container_stats_request *request = (container_stats_request *)util_common_calloc_s(sizeof(container_stats_request));
    if (request == nullptr) {
        error.SetError("Out of memory");
        goto cleanup;
    }
    request->all = true;

    request->filters = (defs_filters *)util_common_calloc_s(sizeof(defs_filters));
    if (request->filters == nullptr) {
        error.SetError("Out of memory");
        goto cleanup;
    }

    if (PackContainerStatsFilter(filter, request, error) != 0) {
        goto cleanup;
    }

    if (m_cb->container.stats(request, &response) != 0) {
        if (response != nullptr && response->errmsg != nullptr) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call stats container callback");
        }
        goto cleanup;
    }
    ContainerStatsToGRPC(response, containerstats, error);

cleanup:
    free_container_stats_request(request);
    free_container_stats_response(response);
}

void ContainerManagerServiceImpl::PackContainerImageToStatus(
    container_inspect *inspect, std::unique_ptr<runtime::v1alpha2::ContainerStatus> &contStatus, Errors &error)
{
    if (inspect->config == nullptr) {
        return;
    }

    if (inspect->config->image != nullptr) {
        contStatus->mutable_image()->set_image(inspect->config->image);
    }

    contStatus->set_image_ref(CRIHelpers::ToPullableImageID(inspect->config->image, inspect->config->image_ref));
    return;
}

void ContainerManagerServiceImpl::UpdateBaseStatusFromInspect(
    container_inspect *inspect, int64_t &createdAt, int64_t &startedAt, int64_t &finishedAt,
    std::unique_ptr<runtime::v1alpha2::ContainerStatus> &contStatus)
{
    runtime::v1alpha2::ContainerState state { runtime::v1alpha2::CONTAINER_UNKNOWN };
    std::string reason;
    std::string message;
    int32_t exitCode { 0 };

    if (inspect->state == nullptr) {
        goto pack_status;
    }

    if (inspect->state->running) {
        // Container is running
        state = runtime::v1alpha2::CONTAINER_RUNNING;
    } else {
        // Container is not running.
        if (finishedAt != 0) { // Case 1
            state = runtime::v1alpha2::CONTAINER_EXITED;
            if (inspect->state->exit_code == 0) {
                reason = "Completed";
            } else {
                reason = "Error";
            }
        } else if (inspect->state->exit_code != 0) { // Case 2
            state = runtime::v1alpha2::CONTAINER_EXITED;
            finishedAt = createdAt;
            startedAt = createdAt;
            reason = "ContainerCannotRun";
        } else { // Case 3
            state = runtime::v1alpha2::CONTAINER_CREATED;
        }
        if (inspect->state->error != nullptr) {
            message = inspect->state->error;
        }
        exitCode = (int32_t)inspect->state->exit_code;
    }

pack_status:
    contStatus->set_exit_code(exitCode);
    contStatus->set_state(state);
    contStatus->set_created_at(createdAt);
    contStatus->set_started_at(startedAt);
    contStatus->set_finished_at(finishedAt);
    contStatus->set_reason(reason);
    contStatus->set_message(message);
}

void ContainerManagerServiceImpl::PackLabelsToStatus(container_inspect *inspect,
                                                     std::unique_ptr<runtime::v1alpha2::ContainerStatus> &contStatus)
{
    if (inspect->config == nullptr || inspect->config->labels == nullptr) {
        return;
    }
    CRIHelpers::ExtractLabels(inspect->config->labels, *contStatus->mutable_labels());
    CRIHelpers::ExtractAnnotations(inspect->config->annotations, *contStatus->mutable_annotations());
    for (size_t i = 0; i < inspect->config->labels->len; i++) {
        if (strcmp(inspect->config->labels->keys[i], CRIHelpers::Constants::CONTAINER_LOGPATH_LABEL_KEY.c_str()) == 0) {
            contStatus->set_log_path(inspect->config->labels->values[i]);
            break;
        }
    }
}

void ContainerManagerServiceImpl::ConvertMountsToStatus(container_inspect *inspect,
                                                        std::unique_ptr<runtime::v1alpha2::ContainerStatus> &contStatus)
{
    for (size_t i = 0; i < inspect->mounts_len; i++) {
        runtime::v1alpha2::Mount *mount = contStatus->add_mounts();
        mount->set_host_path(inspect->mounts[i]->source);
        mount->set_container_path(inspect->mounts[i]->destination);
        mount->set_readonly(!inspect->mounts[i]->rw);
        if (inspect->mounts[i]->propagation == nullptr || strcmp(inspect->mounts[i]->propagation, "rprivate") == 0) {
            mount->set_propagation(runtime::v1alpha2::PROPAGATION_PRIVATE);
        } else if (strcmp(inspect->mounts[i]->propagation, "rslave") == 0) {
            mount->set_propagation(runtime::v1alpha2::PROPAGATION_HOST_TO_CONTAINER);
        } else if (strcmp(inspect->mounts[i]->propagation, "rshared") == 0) {
            mount->set_propagation(runtime::v1alpha2::PROPAGATION_BIDIRECTIONAL);
        }
        // Note: Can't set SeLinuxRelabel
    }
}

void ContainerManagerServiceImpl::ContainerStatusToGRPC(container_inspect *inspect,
                                                        std::unique_ptr<runtime::v1alpha2::ContainerStatus> &contStatus,
                                                        Errors &error)
{
    if (inspect->id != nullptr) {
        contStatus->set_id(inspect->id);
    }

    int64_t createdAt {};
    int64_t startedAt {};
    int64_t finishedAt {};
    CRIHelpers::GetContainerTimeStamps(inspect, &createdAt, &startedAt, &finishedAt, error);
    if (error.NotEmpty()) {
        return;
    }
    contStatus->set_created_at(createdAt);
    contStatus->set_started_at(startedAt);
    contStatus->set_finished_at(finishedAt);

    if (inspect->name != nullptr) {
        CRINaming::ParseContainerName(inspect->name, contStatus->mutable_metadata(), error);
        if (error.NotEmpty()) {
            return;
        }
    }
    PackContainerImageToStatus(inspect, contStatus, error);
    UpdateBaseStatusFromInspect(inspect, createdAt, startedAt, finishedAt, contStatus);
    PackLabelsToStatus(inspect, contStatus);
    ConvertMountsToStatus(inspect, contStatus);
}

std::unique_ptr<runtime::v1alpha2::ContainerStatus>
ContainerManagerServiceImpl::ContainerStatus(const std::string &containerID, Errors &error)
{
    if (containerID.empty()) {
        error.SetError("Empty pod sandbox id");
        return nullptr;
    }

    std::string realContainerID = CRIHelpers::GetRealContainerOrSandboxID(m_cb, containerID, false, error);
    if (error.NotEmpty()) {
        ERROR("Failed to find container id %s: %s", containerID.c_str(), error.GetCMessage());
        error.Errorf("Failed to find container id %s: %s", containerID.c_str(), error.GetCMessage());
        return nullptr;
    }

    container_inspect *inspect = CRIHelpers::InspectContainer(realContainerID, error, false);
    if (error.NotEmpty()) {
        return nullptr;
    }
    if (inspect == nullptr) {
        error.SetError("Get null inspect");
        return nullptr;
    }
    using ContainerStatusPtr = std::unique_ptr<runtime::v1alpha2::ContainerStatus>;
    ContainerStatusPtr contStatus(new (std::nothrow) runtime::v1alpha2::ContainerStatus);
    if (contStatus == nullptr) {
        error.SetError("Out of memory");
        return nullptr;
    }

    ContainerStatusToGRPC(inspect, contStatus, error);

    free_container_inspect(inspect);
    return contStatus;
}

void ContainerManagerServiceImpl::UpdateContainerResources(const std::string &containerID,
                                                           const runtime::v1alpha2::LinuxContainerResources &resources,
                                                           Errors &error)
{
    if (containerID.empty()) {
        error.SetError("Invalid empty container id.");
        return;
    }
    std::string realContainerID = CRIHelpers::GetRealContainerOrSandboxID(m_cb, containerID, false, error);
    if (error.NotEmpty()) {
        ERROR("Failed to find container id %s: %s", containerID.c_str(), error.GetCMessage());
        error.Errorf("Failed to find container id %s: %s", containerID.c_str(), error.GetCMessage());
        return;
    }

    if (m_cb == nullptr || m_cb->container.update == nullptr) {
        error.SetError("Unimplemented callback");
        return;
    }

    container_update_request *request { nullptr };
    container_update_response *response { nullptr };
    host_config *hostconfig { nullptr };
    parser_error perror { nullptr };
    struct parser_context ctx {
        OPT_GEN_SIMPLIFY, 0
    };
    request = (container_update_request *)util_common_calloc_s(sizeof(container_update_request));
    if (request == nullptr) {
        error.SetError("Out of memory");
        goto cleanup;
    }
    request->name = util_strdup_s(realContainerID.c_str());

    hostconfig = (host_config *)util_common_calloc_s(sizeof(host_config));
    if (hostconfig == nullptr) {
        error.SetError("Out of memory");
        goto cleanup;
    }

    hostconfig->cpu_period = resources.cpu_period();
    hostconfig->cpu_quota = resources.cpu_quota();
    hostconfig->cpu_shares = resources.cpu_shares();
    hostconfig->memory = resources.memory_limit_in_bytes();
    if (!resources.cpuset_cpus().empty()) {
        hostconfig->cpuset_cpus = util_strdup_s(resources.cpuset_cpus().c_str());
    }
    if (!resources.cpuset_mems().empty()) {
        hostconfig->cpuset_mems = util_strdup_s(resources.cpuset_mems().c_str());
    }

    request->host_config = host_config_generate_json(hostconfig, &ctx, &perror);
    if (request->host_config == nullptr) {
        error.Errorf("Failed to generate host config json: %s", perror);
        goto cleanup;
    }
    INFO("hostconfig: %s", request->host_config);

    if (m_cb->container.update(request, &response) != 0) {
        if (response != nullptr && response->errmsg != nullptr) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call update container callback");
        }
    }
cleanup:
    free_container_update_request(request);
    free_container_update_response(response);
    free_host_config(hostconfig);
    free(perror);
}

void ContainerManagerServiceImpl::ExecSyncFromGRPC(const std::string &containerID,
                                                   const google::protobuf::RepeatedPtrField<std::string> &cmd,
                                                   int64_t timeout, container_exec_request **request, Errors &error)
{
    if (timeout < 0) {
        error.SetError("Exec timeout cannot be negative.");
        return;
    }

    *request = (container_exec_request *)util_common_calloc_s(sizeof(container_exec_request));
    if (*request == nullptr) {
        error.SetError("Out of memory");
        return;
    }
    (*request)->tty = false;
    (*request)->attach_stdin = false;
    (*request)->attach_stdout = true;
    (*request)->attach_stderr = true;
    (*request)->timeout = timeout;
    (*request)->container_id = util_strdup_s(containerID.c_str());
    if (!cmd.empty()) {
        if ((size_t)cmd.size() > INT_MAX / sizeof(char *)) {
            error.SetError("Too many cmd args");
            return;
        }
        (*request)->argv = (char **)util_common_calloc_s(cmd.size() * sizeof(char *));
        if ((*request)->argv == nullptr) {
            error.SetError("Out of memory");
            return;
        }
        for (int i = 0; i < cmd.size(); i++) {
            (*request)->argv[i] = util_strdup_s(cmd[i].c_str());
            (*request)->argv_len++;
        }
    }

    (*request)->suffix = CRIHelpers::GenerateExecSuffix();
    if ((*request)->suffix == nullptr) {
        error.SetError("Failed to generate exec suffix(id)");
        return;
    }
}

static auto WriteToString(void *context, const void *data, size_t len) -> ssize_t
{
    if (len == 0) {
        return 0;
    }

    std::string *str = reinterpret_cast<std::string *>(context);

    str->append(reinterpret_cast<const char *>(data), len);
    return (ssize_t)len;
}

void ContainerManagerServiceImpl::ExecSync(const std::string &containerID,
                                           const google::protobuf::RepeatedPtrField<std::string> &cmd, int64_t timeout,
                                           runtime::v1alpha2::ExecSyncResponse *reply, Errors &error)
{
    struct io_write_wrapper StdoutstringWriter = { 0 };
    struct io_write_wrapper StderrstringWriter = { 0 };

    if (m_cb == nullptr || m_cb->container.exec == nullptr) {
        error.SetError("Unimplemented callback");
        return;
    }

    if (containerID.empty()) {
        error.SetError("Invalid empty container id.");
        return;
    }

    std::string realContainerID = CRIHelpers::GetRealContainerOrSandboxID(m_cb, containerID, false, error);
    if (error.NotEmpty()) {
        ERROR("Failed to find container id %s: %s", containerID.c_str(), error.GetCMessage());
        error.Errorf("Failed to find container id %s: %s", containerID.c_str(), error.GetCMessage());
        return;
    }

    container_exec_response *response { nullptr };
    container_exec_request *request { nullptr };
    ExecSyncFromGRPC(realContainerID, cmd, timeout, &request, error);
    if (error.NotEmpty()) {
        goto cleanup;
    }

    StdoutstringWriter.context = (void *)reply->mutable_stdout();
    StdoutstringWriter.write_func = WriteToString;

    StderrstringWriter.context = (void *)reply->mutable_stderr();
    StderrstringWriter.write_func = WriteToString;
    if (m_cb->container.exec(request, &response, -1, &StdoutstringWriter, &StderrstringWriter) != 0) {
        if (response != nullptr && response->errmsg != nullptr) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call exec container callback");
        }
        goto cleanup;
    }
    reply->set_exit_code((::google::protobuf::uint32)(response->exit_code));

cleanup:
    free_container_exec_request(request);
    free_container_exec_response(response);
}

auto ContainerManagerServiceImpl::BuildURL(const std::string &method, const std::string &token) -> std::string
{
    url::URLDatum url;
    url.SetPathWithoutEscape("/cri/" + method + "/" + token);
    WebsocketServer *server = WebsocketServer::GetInstance();
    url::URLDatum wsurl = server->GetWebsocketUrl();
    return wsurl.ResolveReference(&url)->String();
}

auto ContainerManagerServiceImpl::InspectContainerState(const std::string &Id, Errors &err) -> container_inspect_state *
{
    container_inspect_state *inspect_data { nullptr };

    inspect_data = inspect_container_state((const char *)Id.c_str(), 0);
    if (inspect_data == nullptr) {
        err.Errorf("Failed to call inspect service %s", Id.c_str());
    }

    return inspect_data;
}

auto ContainerManagerServiceImpl::ValidateExecRequest(const runtime::v1alpha2::ExecRequest &req, Errors &error) -> int
{
    if (req.container_id().empty()) {
        error.SetError("missing required container id!");
        return -1;
    }
    std::string realContainerID = CRIHelpers::GetRealContainerOrSandboxID(m_cb, req.container_id(), false, error);
    if (error.NotEmpty()) {
        ERROR("Failed to find container id %s: %s", req.container_id().c_str(), error.GetCMessage());
        error.Errorf("Failed to find container id %s: %s", req.container_id().c_str(), error.GetCMessage());
        return -1;
    }

    container_inspect_state *state = InspectContainerState(realContainerID, error);
    if (error.NotEmpty()) {
        ERROR("Failed to inspect container id %s: %s state", req.container_id().c_str(), error.GetCMessage());
        error.Errorf("Failed to inspect container id %s: %s state", req.container_id().c_str(), error.GetCMessage());
        return -1;
    }
    bool running = state != nullptr && state->running;
    bool paused = state != nullptr && state->paused;
    free_container_inspect_state(state);
    if (!running) {
        ERROR("Container is not running: %s", req.container_id().c_str());
        error.Errorf("Container is not running: %s", req.container_id().c_str());
        return -1;
    }

    if (paused) {
        ERROR("Container %s is paused, unpause the container before exec", req.container_id().c_str());
        error.Errorf("Container %s is paused, unpause the container before exec", req.container_id().c_str());
        return -1;
    }

    if (req.tty() && req.stderr()) {
        error.SetError("tty and stderr cannot both be true!");
        return -1;
    }
    if (!req.stdin() && !req.stdout() && !req.stderr()) {
        error.SetError("one of stdin, stdout, or stderr must be set!");
        return -1;
    }
    return 0;
}

void ContainerManagerServiceImpl::Exec(const runtime::v1alpha2::ExecRequest &req, runtime::v1alpha2::ExecResponse *resp,
                                       Errors &error)
{
    if (ValidateExecRequest(req, error) != 0) {
        return;
    }
    RequestCache *cache = RequestCache::GetInstance();
    std::string token = cache->InsertExecRequest(req);
    if (token.empty()) {
        error.SetError("failed to get a unique token!");
        return;
    }
    std::string url = BuildURL("exec", token);
    resp->set_url(url);
}

auto ContainerManagerServiceImpl::ValidateAttachRequest(const runtime::v1alpha2::AttachRequest &req, Errors &error)
-> int
{
    if (req.container_id().empty()) {
        error.SetError("missing required container id!");
        return -1;
    }
    (void)CRIHelpers::GetRealContainerOrSandboxID(m_cb, req.container_id(), false, error);
    if (error.NotEmpty()) {
        ERROR("Failed to find container id %s: %s", req.container_id().c_str(), error.GetCMessage());
        error.Errorf("Failed to find container id %s: %s", req.container_id().c_str(), error.GetCMessage());
        return -1;
    }

    if (req.tty() && req.stderr()) {
        error.SetError("tty and stderr cannot both be true!");
        return -1;
    }
    if (!req.stdin() && !req.stdout() && !req.stderr()) {
        error.SetError("one of stdin, stdout, and stderr must be set");
        return -1;
    }
    return 0;
}

void ContainerManagerServiceImpl::Attach(const runtime::v1alpha2::AttachRequest &req,
                                         runtime::v1alpha2::AttachResponse *resp, Errors &error)
{
    if (ValidateAttachRequest(req, error) != 0) {
        return;
    }
    if (resp == nullptr) {
        error.SetError("Empty attach response arguments");
        return;
    }
    RequestCache *cache = RequestCache::GetInstance();
    std::string token = cache->InsertAttachRequest(req);
    if (token.empty()) {
        error.SetError("failed to get a unique token!");
        return;
    }
    std::string url = BuildURL("attach", token);
    resp->set_url(url);
}
} // namespace CRI
