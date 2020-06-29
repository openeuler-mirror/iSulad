/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide grpc container service private functions
 ******************************************************************************/
#include "grpc_containers_service.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "error.h"

int ContainerServiceImpl::version_request_from_grpc(const VersionRequest *grequest, container_version_request **request)
{
    container_version_request *tmpreq = nullptr;

    tmpreq = (container_version_request *)util_common_calloc_s(sizeof(container_version_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::version_response_to_grpc(const container_version_response *response,
                                                   VersionResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }
    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    if (response->version != nullptr) {
        gresponse->set_version(response->version);
    }
    if (response->git_commit != nullptr) {
        gresponse->set_git_commit(response->git_commit);
    }
    if (response->build_time != nullptr) {
        gresponse->set_build_time(response->build_time);
    }
    if (response->root_path != nullptr) {
        gresponse->set_root_path(response->root_path);
    }

    return 0;
}

int ContainerServiceImpl::info_request_from_grpc(const InfoRequest *grequest, host_info_request **request)
{
    host_info_request *tmpreq = (host_info_request *)util_common_calloc_s(sizeof(host_info_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::info_response_to_grpc(const host_info_response *response, InfoResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    if (response->version != nullptr) {
        gresponse->set_version(response->version);
    }
    gresponse->set_containers_num((::google::protobuf::uint32)response->containers_num);

    gresponse->set_c_running((::google::protobuf::uint32)response->c_running);

    gresponse->set_c_paused((::google::protobuf::uint32)response->c_paused);

    gresponse->set_c_stopped((::google::protobuf::uint32)response->c_stopped);

    gresponse->set_images_num(response->images_num);

    if (pack_os_info_to_grpc(response, gresponse)) {
        return -1;
    }

    if (response->logging_driver != nullptr) {
        gresponse->set_logging_driver(response->logging_driver);
    }

    if (response->isulad_root_dir != nullptr) {
        gresponse->set_isulad_root_dir(response->isulad_root_dir);
    }

    gresponse->set_total_mem(response->total_mem);

    if (pack_proxy_info_to_grpc(response, gresponse)) {
        return -1;
    }

    if (pack_driver_info_to_grpc(response, gresponse)) {
        return -1;
    }

    return 0;
}

int ContainerServiceImpl::create_request_from_grpc(const CreateRequest *grequest, container_create_request **request)
{
    container_create_request *tmpreq = nullptr;

    tmpreq = (container_create_request *)util_common_calloc_s(sizeof(container_create_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }
    if (!grequest->rootfs().empty()) {
        tmpreq->rootfs = util_strdup_s(grequest->rootfs().c_str());
    }
    if (!grequest->image().empty()) {
        tmpreq->image = util_strdup_s(grequest->image().c_str());
    }
    if (!grequest->runtime().empty()) {
        tmpreq->runtime = util_strdup_s(grequest->runtime().c_str());
    }
    if (!grequest->hostconfig().empty()) {
        tmpreq->hostconfig = util_strdup_s(grequest->hostconfig().c_str());
    }
    if (!grequest->customconfig().empty()) {
        tmpreq->customconfig = util_strdup_s(grequest->customconfig().c_str());
    }

    *request = tmpreq;
    return 0;
}


int ContainerServiceImpl::create_response_to_grpc(const container_create_response *response, CreateResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }
    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }
    return 0;
}

int ContainerServiceImpl::start_request_from_grpc(const StartRequest *grequest, container_start_request **request)
{
    container_start_request *tmpreq = nullptr;

    tmpreq = (container_start_request *)util_common_calloc_s(sizeof(container_start_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    if (!grequest->stdin().empty()) {
        tmpreq->stdin = util_strdup_s(grequest->stdin().c_str());
    }
    if (!grequest->stdout().empty()) {
        tmpreq->stdout = util_strdup_s(grequest->stdout().c_str());
    }
    if (!grequest->stderr().empty()) {
        tmpreq->stderr = util_strdup_s(grequest->stderr().c_str());
    }
    tmpreq->attach_stdin = grequest->attach_stdin();
    tmpreq->attach_stdout = grequest->attach_stdout();
    tmpreq->attach_stderr = grequest->attach_stderr();

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::top_request_from_grpc(const TopRequest *grequest, container_top_request **request)
{
    container_top_request *tmpreq = nullptr;

    tmpreq = (container_top_request *)util_common_calloc_s(sizeof(container_top_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    if (grequest->args_size() > 0) {
        if ((size_t)grequest->args_size() > SIZE_MAX / sizeof(char *)) {
            ERROR("Too many arguments!");
            free_container_top_request(tmpreq);
            return -1;
        }
        tmpreq->args = (char **)util_common_calloc_s(sizeof(char *) * grequest->args_size());
        if (tmpreq->args == nullptr) {
            ERROR("Out of memory");
            free_container_top_request(tmpreq);
            return -1;
        }
        for (int i = 0; i < grequest->args_size(); i++) {
            tmpreq->args[i] = util_strdup_s(grequest->args(i).c_str());
        }
        tmpreq->args_len = (size_t)grequest->args_size();
    }

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::top_response_to_grpc(const container_top_response *response, TopResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }
    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }

    if (response->titles != nullptr) {
        gresponse->set_titles(response->titles);
    }

    for (size_t i = 0; i < response->processes_len; i++) {
        gresponse->add_processes(response->processes[i]);
    }

    return 0;
}

int ContainerServiceImpl::stop_request_from_grpc(const StopRequest *grequest, container_stop_request **request)
{
    container_stop_request *tmpreq = (container_stop_request *)util_common_calloc_s(sizeof(container_stop_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }
    tmpreq->force = grequest->force();
    tmpreq->timeout = grequest->timeout();

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::restart_request_from_grpc(const RestartRequest *grequest, container_restart_request **request)
{
    container_restart_request *tmpreq = (container_restart_request *)util_common_calloc_s(
                                            sizeof(container_restart_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }
    tmpreq->timeout = grequest->timeout();

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::kill_request_from_grpc(const KillRequest *grequest, container_kill_request **request)
{
    container_kill_request *tmpreq = (container_kill_request *)util_common_calloc_s(sizeof(container_kill_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    tmpreq->signal = grequest->signal();

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::delete_request_from_grpc(const DeleteRequest *grequest, container_delete_request **request)
{
    container_delete_request *tmpreq = (container_delete_request *)util_common_calloc_s(
                                           sizeof(container_delete_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }
    tmpreq->force = grequest->force();

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::delete_response_to_grpc(const container_delete_response *response, DeleteResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }
    gresponse->set_cc(response->cc);
    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    return 0;
}

int ContainerServiceImpl::exec_request_from_grpc(const ExecRequest *grequest, container_exec_request **request)
{
    container_exec_request *tmpreq = (container_exec_request *)util_common_calloc_s(sizeof(container_exec_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->container_id().empty()) {
        tmpreq->container_id = util_strdup_s(grequest->container_id().c_str());
    }

    if (!grequest->suffix().empty()) {
        tmpreq->suffix = util_strdup_s(grequest->suffix().c_str());
    }

    tmpreq->tty = grequest->tty();
    tmpreq->attach_stdin = grequest->attach_stdin();
    tmpreq->attach_stdout = grequest->attach_stdout();
    tmpreq->attach_stderr = grequest->attach_stderr();

    if (!grequest->stdin().empty()) {
        tmpreq->stdin = util_strdup_s(grequest->stdin().c_str());
    }
    if (!grequest->stdout().empty()) {
        tmpreq->stdout = util_strdup_s(grequest->stdout().c_str());
    }
    if (!grequest->stderr().empty()) {
        tmpreq->stderr = util_strdup_s(grequest->stderr().c_str());
    }

    if (grequest->argv_size() > 0) {
        if ((size_t)grequest->argv_size() > SIZE_MAX / sizeof(char *)) {
            ERROR("Too many arguments!");
            free_container_exec_request(tmpreq);
            return -1;
        }
        tmpreq->argv = (char **)util_common_calloc_s(sizeof(char *) * grequest->argv_size());
        if (tmpreq->argv == nullptr) {
            ERROR("Out of memory");
            free_container_exec_request(tmpreq);
            return -1;
        }
        for (int i = 0; i < grequest->argv_size(); i++) {
            tmpreq->argv[i] = util_strdup_s(grequest->argv(i).c_str());
        }
        tmpreq->argv_len = grequest->argv_size();
    }

    if (grequest->env_size() > 0) {
        if ((size_t)grequest->argv_size() > SIZE_MAX / sizeof(char *)) {
            ERROR("Too many environmental variables!");
            free_container_exec_request(tmpreq);
            return -1;
        }
        tmpreq->env = (char **)util_common_calloc_s(sizeof(char *) * grequest->env_size());
        if (tmpreq->env == nullptr) {
            ERROR("Out of memory");
            free_container_exec_request(tmpreq);
            return -1;
        }
        for (int i = 0; i < grequest->env_size(); i++) {
            tmpreq->env[i] = util_strdup_s(grequest->env(i).c_str());
        }
        tmpreq->env_len = grequest->env_size();
    }

    if (!grequest->user().empty()) {
        tmpreq->user = util_strdup_s(grequest->user().c_str());
    }
    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::exec_response_to_grpc(const container_exec_response *response, ExecResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    gresponse->set_cc(response->cc);
    gresponse->set_exit_code(response->exit_code);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    return 0;
}

int ContainerServiceImpl::inspect_request_from_grpc(const InspectContainerRequest *grequest,
                                                    container_inspect_request **request)
{
    container_inspect_request *tmpreq = (container_inspect_request *)util_common_calloc_s(
                                            sizeof(container_inspect_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    tmpreq->bformat = grequest->bformat();
    tmpreq->timeout = grequest->timeout();

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::inspect_response_to_grpc(const container_inspect_response *response,
                                                   InspectContainerResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    gresponse->set_cc(response->cc);
    if (response->container_json != nullptr) {
        gresponse->set_containerjson(response->container_json);
    }
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    return 0;
}

int ContainerServiceImpl::list_request_from_grpc(const ListRequest *grequest, container_list_request **request)
{
    size_t len = 0;
    container_list_request *tmpreq = (container_list_request *)util_common_calloc_s(
                                         sizeof(container_list_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    tmpreq->all = grequest->all();
    tmpreq->filters = (defs_filters *)util_common_calloc_s(sizeof(defs_filters));
    if (tmpreq->filters == nullptr) {
        ERROR("Out of memory");
        goto cleanup;
    }

    len = (size_t)grequest->filters_size();
    if (len == 0) {
        *request = tmpreq;
        return 0;
    }
    if (len > SIZE_MAX / sizeof(char *)) {
        ERROR("invalid filters size");
        goto cleanup;
    }
    tmpreq->filters->keys = (char **)util_common_calloc_s(len * sizeof(char *));
    if (tmpreq->filters->keys == nullptr) {
        goto cleanup;
    }
    tmpreq->filters->values = (json_map_string_bool **)util_common_calloc_s(len * sizeof(json_map_string_bool *));
    if (tmpreq->filters->values == nullptr) {
        free(tmpreq->filters->keys);
        tmpreq->filters->keys = nullptr;
        goto cleanup;
    }

    for (auto &iter : grequest->filters()) {
        tmpreq->filters->values[tmpreq->filters->len] = (json_map_string_bool *)
                                                        util_common_calloc_s(sizeof(json_map_string_bool));
        if (tmpreq->filters->values[tmpreq->filters->len] == nullptr) {
            ERROR("Out of memory");
            goto cleanup;
        }
        if (append_json_map_string_bool(tmpreq->filters->values[tmpreq->filters->len],
                                        iter.second.empty() ? "" : iter.second.c_str(), true)) {
            free(tmpreq->filters->values[tmpreq->filters->len]);
            tmpreq->filters->values[tmpreq->filters->len] = nullptr;
            ERROR("Append failed");
            goto cleanup;
        }
        tmpreq->filters->keys[tmpreq->filters->len] = util_strdup_s(iter.first.empty() ? "" : iter.first.c_str());
        tmpreq->filters->len++;
    }

    *request = tmpreq;
    return 0;
cleanup:
    free_container_list_request(tmpreq);
    return -1;
}

int ContainerServiceImpl::list_response_to_grpc(const container_list_response *response, ListResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    for (size_t i = 0; i < response->containers_len; i++) {
        Container *container = gresponse->add_containers();
        if (response->containers[i]->id != nullptr) {
            container->set_id(response->containers[i]->id);
        }
        if (response->containers[i]->name != nullptr) {
            container->set_name(response->containers[i]->name);
        }
        if (response->containers[i]->pid != 0) {
            container->set_pid(response->containers[i]->pid);
        }
        container->set_status((ContainerStatus)response->containers[i]->status);
        if (response->containers[i]->image != nullptr) {
            container->set_image(response->containers[i]->image);
        }
        if (response->containers[i]->command != nullptr) {
            container->set_command(response->containers[i]->command);
        }
        container->set_exit_code(response->containers[i]->exit_code);
        container->set_restartcount(response->containers[i]->restartcount);
        if (response->containers[i]->startat != nullptr) {
            container->set_startat(response->containers[i]->startat);
        }
        if (response->containers[i]->finishat != nullptr) {
            container->set_finishat(response->containers[i]->finishat);
        }
        if (response->containers[i]->runtime != nullptr) {
            container->set_runtime(response->containers[i]->runtime);
        }
        if (response->containers[i]->health_state != nullptr) {
            container->set_health_state(response->containers[i]->health_state);
        }
        container->set_created(response->containers[i]->created);
    }
    return 0;
}

int ContainerServiceImpl::pause_request_from_grpc(const PauseRequest *grequest, container_pause_request **request)
{
    container_pause_request *tmpreq = (container_pause_request *)util_common_calloc_s(sizeof(container_pause_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::resume_request_from_grpc(const ResumeRequest *grequest, container_resume_request **request)
{
    container_resume_request *tmpreq = (container_resume_request *)util_common_calloc_s(
                                           sizeof(container_resume_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::container_rename_request_from_grpc(const RenameRequest *grequest,
                                                             struct isulad_container_rename_request **request)
{
    struct isulad_container_rename_request *tmpreq = (struct isulad_container_rename_request *)util_common_calloc_s(
                                                         sizeof(struct isulad_container_rename_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->oldname().empty()) {
        tmpreq->old_name = util_strdup_s(grequest->oldname().c_str());
    }

    if (!grequest->newname().empty()) {
        tmpreq->new_name = util_strdup_s(grequest->newname().c_str());
    }

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::container_rename_response_to_grpc(const struct isulad_container_rename_response *response,
                                                            RenameResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }

    return 0;
}

int ContainerServiceImpl::container_resize_request_from_grpc(const ResizeRequest *grequest,
                                                             struct isulad_container_resize_request **request)
{
    struct isulad_container_resize_request *tmpreq = (struct isulad_container_resize_request *)util_common_calloc_s(
                                                         sizeof(struct isulad_container_resize_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    if (!grequest->suffix().empty()) {
        tmpreq->suffix = util_strdup_s(grequest->suffix().c_str());
    }

    tmpreq->height = grequest->height();

    tmpreq->width = grequest->width();

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::container_resize_response_to_grpc(const struct isulad_container_resize_response *response,
                                                            ResizeResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }

    return 0;
}

int ContainerServiceImpl::update_request_from_grpc(const UpdateRequest *grequest, container_update_request **request)
{
    container_update_request *tmpreq = (container_update_request *)util_common_calloc_s(
                                           sizeof(container_update_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->name = util_strdup_s(grequest->id().c_str());
    }

    if (!grequest->hostconfig().empty()) {
        tmpreq->host_config = util_strdup_s(grequest->hostconfig().c_str());
    }

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::update_response_to_grpc(const container_update_response *response, UpdateResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    gresponse->set_cc(response->cc);
    if (response->id != nullptr) {
        gresponse->set_id(response->id);
    }
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    return 0;
}

int ContainerServiceImpl::stats_request_from_grpc(const StatsRequest *grequest, container_stats_request **request)
{
    container_stats_request *tmpreq = (container_stats_request *)util_common_calloc_s(sizeof(container_stats_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (grequest->containers_size() > 0) {
        tmpreq->containers = (char **)util_common_calloc_s(grequest->containers_size() * sizeof(char *));
        if (tmpreq->containers == nullptr) {
            ERROR("Out of memory");
            free_container_stats_request(tmpreq);
            return -1;
        }
        for (int i = 0; i < grequest->containers_size(); i++) {
            tmpreq->containers[i] = util_strdup_s(grequest->containers(i).c_str());
            tmpreq->containers_len++;
        }
    }

    tmpreq->all = grequest->all();

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::stats_response_to_grpc(const container_stats_response *response, StatsResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    if (response->container_stats && response->container_stats_len) {
        for (size_t i = 0; i < response->container_stats_len; i++) {
            containers::Container_info *stats = gresponse->add_containers();
            if (response->container_stats[i]->id != nullptr) {
                stats->set_id(response->container_stats[i]->id);
            }
            stats->set_pids_current(response->container_stats[i]->pids_current);
            stats->set_cpu_use_nanos(response->container_stats[i]->cpu_use_nanos);
            stats->set_cpu_system_use(response->container_stats[i]->cpu_system_use);
            stats->set_online_cpus(response->container_stats[i]->online_cpus);
            stats->set_blkio_read(response->container_stats[i]->blkio_read);
            stats->set_blkio_write(response->container_stats[i]->blkio_write);
            stats->set_mem_used(response->container_stats[i]->mem_used);
            stats->set_mem_limit(response->container_stats[i]->mem_limit);
            stats->set_kmem_used(response->container_stats[i]->kmem_used);
            stats->set_kmem_limit(response->container_stats[i]->kmem_limit);
        }
    }
    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    return 0;
}

int ContainerServiceImpl::wait_request_from_grpc(const WaitRequest *grequest, container_wait_request **request)
{
    container_wait_request *tmpreq = (container_wait_request *)util_common_calloc_s(sizeof(container_wait_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    tmpreq->condition = grequest->condition();

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::wait_response_to_grpc(const container_wait_response *response, WaitResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    gresponse->set_cc(response->cc);
    gresponse->set_exit_code(response->exit_code);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    return 0;
}

int ContainerServiceImpl::events_request_from_grpc(const EventsRequest *grequest,
                                                   struct isulad_events_request **request)
{
    struct isulad_events_request *tmpreq = (struct isulad_events_request *)util_common_calloc_s(
                                               sizeof(struct isulad_events_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    tmpreq->storeonly = grequest->storeonly();

    if (grequest->has_since()) {
        protobuf_timestamp_from_grpc(&tmpreq->since, grequest->since());
    }

    if (grequest->has_until()) {
        protobuf_timestamp_from_grpc(&tmpreq->until, grequest->until());
    }

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::copy_from_container_request_from_grpc(
    const CopyFromContainerRequest *grequest, struct isulad_copy_from_container_request **request)
{
    struct isulad_copy_from_container_request *tmpreq = (struct isulad_copy_from_container_request *)util_common_calloc_s(
                                                            sizeof(isulad_copy_from_container_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    if (!grequest->runtime().empty()) {
        tmpreq->runtime = util_strdup_s(grequest->runtime().c_str());
    }

    if (!grequest->srcpath().empty()) {
        tmpreq->srcpath = util_strdup_s(grequest->srcpath().c_str());
    }

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::remote_exec_request_from_stream(ServerContext *context,
                                                          container_exec_request **request, std::string &errmsg)
{
    const std::multimap<grpc::string_ref, grpc::string_ref> init_metadata = context->client_metadata();
    auto iter = init_metadata.find("isulad-remote-exec");
    if (iter != init_metadata.end()) {
        char *err = nullptr;
        std::string json = std::string(iter->second.data(), iter->second.length());
        *request = container_exec_request_parse_data(json.c_str(), nullptr, &err);
        if (*request == nullptr) {
            errmsg = "Invalid remote exec container json: ";
            errmsg += (err != nullptr) ? err : "unknown";
            free(err);
            return -1;
        }
    } else {
        errmsg = "No metadata 'isulad-remote-exec' received";
        return -1;
    }
    return 0;
}

void ContainerServiceImpl::add_exec_trailing_metadata(ServerContext *context, container_exec_response *response)
{
    if (response == nullptr) {
        context->AddTrailingMetadata("cc", std::to_string((int)ISULAD_ERR_MEMOUT));
        return;
    }
    context->AddTrailingMetadata("cc", std::to_string(response->cc));
    context->AddTrailingMetadata("exit_code", std::to_string(response->exit_code));
    if (response->errmsg != nullptr) {
        context->AddTrailingMetadata("errmsg", response->errmsg);
    }
}

int ContainerServiceImpl::attach_request_from_stream(
    const std::multimap<grpc::string_ref, grpc::string_ref> &metadata,
    container_attach_request **request)
{
    container_attach_request *tmpreq = (container_attach_request *)util_common_calloc_s(
                                           sizeof(container_attach_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    std::multimap<grpc::string_ref, grpc::string_ref>::const_iterator std_kv;
    std_kv = metadata.find("container-id");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->container_id = util_strdup_s(std::string(std_kv->second.data(), std_kv->second.length()).c_str());

    std_kv = metadata.find("attach-stdin");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->attach_stdin = (std::string(std_kv->second.data(), std_kv->second.length()) == "true");

    std_kv = metadata.find("attach-stdout");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->attach_stdout = (std::string(std_kv->second.data(), std_kv->second.length()) == "true");

    std_kv = metadata.find("attach-stderr");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->attach_stderr = (std::string(std_kv->second.data(), std_kv->second.length()) == "true");

    *request = tmpreq;
    return 0;
cleanup:
    free_container_attach_request(tmpreq);
    return -1;
}

void ContainerServiceImpl::add_attach_trailing_metadata(ServerContext *context, container_attach_response *response)
{
    if (response == nullptr) {
        context->AddTrailingMetadata("cc", std::to_string((int)ISULAD_ERR_MEMOUT));
        return;
    }
    context->AddTrailingMetadata("cc", std::to_string(response->cc));

    if (response->errmsg != nullptr) {
        context->AddTrailingMetadata("errmsg", response->errmsg);
    }
}

int ContainerServiceImpl::remote_start_request_from_stream(
    const std::multimap<grpc::string_ref, grpc::string_ref> &metadata, container_start_request **request)
{
    container_start_request *tmpreq = (container_start_request *)util_common_calloc_s(sizeof(container_start_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    std::multimap<grpc::string_ref, grpc::string_ref>::const_iterator std_kv;
    std_kv = metadata.find("container-id");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->id = util_strdup_s(std::string(std_kv->second.data(), std_kv->second.length()).c_str());

    std_kv = metadata.find("attach-stdin");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->attach_stdin = (std::string(std_kv->second.data(), std_kv->second.length()) == "true");

    std_kv = metadata.find("attach-stdout");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->attach_stdout = (std::string(std_kv->second.data(), std_kv->second.length()) == "true");

    std_kv = metadata.find("attach-stderr");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->attach_stderr = (std::string(std_kv->second.data(), std_kv->second.length()) == "true");

    *request = tmpreq;
    return 0;
cleanup:
    free_container_start_request(tmpreq);
    return -1;
}

void ContainerServiceImpl::add_start_trailing_metadata(ServerContext *context, container_start_response *response)
{
    if (response == nullptr) {
        context->AddTrailingMetadata("cc", std::to_string((int)ISULAD_ERR_MEMOUT));
        return;
    }
    context->AddTrailingMetadata("cc", std::to_string(response->cc));

    if (response->errmsg != nullptr) {
        context->AddTrailingMetadata("errmsg", response->errmsg);
    }
}

int ContainerServiceImpl::export_request_from_grpc(const ExportRequest *grequest, container_export_request **request)
{
    container_export_request *tmpreq = (container_export_request *)util_common_calloc_s(
                                           sizeof(container_export_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    if (!grequest->file().empty()) {
        tmpreq->file = util_strdup_s(grequest->file().c_str());
    }

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::pack_os_info_to_grpc(const host_info_response *response, InfoResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    if (response->kversion != nullptr) {
        gresponse->set_kversion(response->kversion);
    }

    if (response->os_type != nullptr) {
        gresponse->set_os_type(response->os_type);
    }

    if (response->architecture != nullptr) {
        gresponse->set_architecture(response->architecture);
    }

    if (response->nodename != nullptr) {
        gresponse->set_nodename(response->nodename);
    }

    gresponse->set_cpus((::google::protobuf::uint32)response->cpus);

    if (response->operating_system != nullptr) {
        gresponse->set_operating_system(response->operating_system);
    }

    if (response->cgroup_driver != nullptr) {
        gresponse->set_cgroup_driver(response->cgroup_driver);
    }

    if (response->huge_page_size != nullptr) {
        gresponse->set_huge_page_size(response->huge_page_size);
    }

    return 0;
}

int ContainerServiceImpl::pack_proxy_info_to_grpc(const host_info_response *response, InfoResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    if (response->http_proxy != nullptr) {
        gresponse->set_http_proxy(response->http_proxy);
    }

    if (response->https_proxy != nullptr) {
        gresponse->set_https_proxy(response->https_proxy);
    }

    if (response->no_proxy != nullptr) {
        gresponse->set_no_proxy(response->no_proxy);
    }

    return 0;
}

int ContainerServiceImpl::pack_driver_info_to_grpc(const host_info_response *response, InfoResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    if (response->driver_name != nullptr) {
        gresponse->set_driver_name(response->driver_name);
    }

    if (response->driver_status != nullptr) {
        gresponse->set_driver_status(response->driver_status);
    }

    return 0;
}
