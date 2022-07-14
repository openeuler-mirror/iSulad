/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Start: 2022-06-24
 * Description: implement grpc container list service functions
 ******************************************************************************/
#include "list_service.h"

void ContainerListService::SetThreadName()
{
    SetOperationThreadName("ContList");
}

Status ContainerListService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_list");
}

bool ContainerListService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.list != nullptr;
}

int ContainerListService::FillRequestFromgRPC(const ListRequest *request, void *contReq)
{
    size_t len;
    container_list_request *tmpreq { nullptr };

    tmpreq = static_cast<container_list_request *>(util_common_calloc_s(sizeof(container_list_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    tmpreq->all = request->all();
    tmpreq->filters = (defs_filters *)util_common_calloc_s(sizeof(defs_filters));
    if (tmpreq->filters == nullptr) {
        ERROR("Out of memory");
        goto cleanup;
    }

    len = (size_t)request->filters_size();
    if (len == 0) {
        *static_cast<container_list_request **>(contReq) = tmpreq;
        return 0;
    }

    tmpreq->filters->keys = static_cast<char **>(util_smart_calloc_s(sizeof(char *), len));
    if (tmpreq->filters->keys == nullptr) {
        goto cleanup;
    }
    tmpreq->filters->values =
        static_cast<json_map_string_bool **>(util_smart_calloc_s(sizeof(json_map_string_bool *), len));
    if (tmpreq->filters->values == nullptr) {
        free(tmpreq->filters->keys);
        tmpreq->filters->keys = nullptr;
        goto cleanup;
    }

    for (auto &iter : request->filters()) {
        tmpreq->filters->values[tmpreq->filters->len] =
            static_cast<json_map_string_bool *>(util_common_calloc_s(sizeof(json_map_string_bool)));
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

    *static_cast<container_list_request **>(contReq) = tmpreq;
    return 0;

cleanup:
    free_container_list_request(tmpreq);
    return -1;
}

void ContainerListService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.list(static_cast<container_list_request *>(containerReq),
                             static_cast<container_list_response **>(containerRes));
}

void ContainerListService::FillResponseTogRPC(void *containerRes, ListResponse *gresponse)
{
    const container_list_response *response = static_cast<const container_list_response *>(containerRes);

    ResponseToGrpc(response, gresponse);

    for (size_t i { 0 }; i < response->containers_len; ++i) {
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
        container->set_status(static_cast<ContainerStatus>(response->containers[i]->status));
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
}

void ContainerListService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_list_request(static_cast<container_list_request *>(containerReq));
    free_container_list_response(static_cast<container_list_response *>(containerRes));
}