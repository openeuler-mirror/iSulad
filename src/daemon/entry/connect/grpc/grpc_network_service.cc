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
 * Author: zhangxiaoyu
 * Create: 2020-09-11
 * Description: provide grpc network functions
 ******************************************************************************/
#include "grpc_network_service.h"

#include <iostream>
#include <memory>
#include <string>
#include <unistd.h>
#include "grpc_server_tls_auth.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "error.h"

using namespace network;

int NetworkServiceImpl::create_request_from_grpc(const NetworkCreateRequest *grequest, network_create_request **request)
{
    auto *tmpreq = static_cast<network_create_request *>(util_common_calloc_s(sizeof(network_create_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->name().empty()) {
        tmpreq->name = util_strdup_s(grequest->name().c_str());
    }
    if (!grequest->driver().empty()) {
        tmpreq->driver = util_strdup_s(grequest->driver().c_str());
    }
    if (!grequest->gateway().empty()) {
        tmpreq->gateway = util_strdup_s(grequest->gateway().c_str());
    }
    tmpreq->internal = grequest->internal();
    if (!grequest->subnet().empty()) {
        tmpreq->subnet = util_strdup_s(grequest->subnet().c_str());
    }

    *request = tmpreq;
    return 0;
}

void NetworkServiceImpl::create_response_to_grpc(const network_create_response *response,
                                                 NetworkCreateResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_EXEC);
        return;
    }
    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    if (response->name != nullptr) {
        gresponse->set_name(response->name);
    }
}

Status NetworkServiceImpl::Create(ServerContext *context, const NetworkCreateRequest *request,
                                  NetworkCreateResponse *reply)
{
    int tret;
    service_executor_t *cb = nullptr;
    network_create_response *network_res = nullptr;
    network_create_request *network_req = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "network_create");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->network.create == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = create_request_from_grpc(request, &network_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    (void)cb->network.create(network_req, &network_res);
    create_response_to_grpc(network_res, reply);

    free_network_create_request(network_req);
    free_network_create_response(network_res);

    return Status::OK;
}

int NetworkServiceImpl::inspect_request_from_grpc(const NetworkInspectRequest *grequest,
                                                  network_inspect_request **request)
{
    auto *tmpreq = static_cast<network_inspect_request *>(util_common_calloc_s(sizeof(network_inspect_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->name().empty()) {
        tmpreq->name = util_strdup_s(grequest->name().c_str());
    }

    *request = tmpreq;
    return 0;
}

void NetworkServiceImpl::inspect_response_to_grpc(const network_inspect_response *response,
                                                  NetworkInspectResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_EXEC);
        return;
    }

    gresponse->set_cc(response->cc);
    if (response->network_json != nullptr) {
        gresponse->set_networkjson(response->network_json);
    }
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
}

Status NetworkServiceImpl::Inspect(ServerContext *context, const NetworkInspectRequest *request,
                                   NetworkInspectResponse *reply)
{
    int tret;
    service_executor_t *cb = nullptr;
    network_inspect_request *network_req = nullptr;
    network_inspect_response *network_res = nullptr;

    Status status = GrpcServerTlsAuth::auth(context, "network_inspect");
    if (!status.ok()) {
        return status;
    }

    cb = get_service_executor();
    if (cb == nullptr || cb->network.inspect == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = inspect_request_from_grpc(request, &network_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    (void)cb->network.inspect(network_req, &network_res);
    inspect_response_to_grpc(network_res, reply);

    free_network_inspect_request(network_req);
    free_network_inspect_response(network_res);

    return Status::OK;
}

int NetworkServiceImpl::list_request_from_grpc(const NetworkListRequest *grequest, network_list_request **request)
{
    size_t len = 0;
    auto *tmpreq = static_cast<network_list_request *>(util_common_calloc_s(sizeof(network_list_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    len = static_cast<size_t>(grequest->filters_size());
    if (len == 0) {
        *request = tmpreq;
        return 0;
    }

    tmpreq->filters = static_cast<defs_filters *>(util_common_calloc_s(sizeof(defs_filters)));
    if (tmpreq->filters == nullptr) {
        ERROR("Out of memory");
        goto cleanup;
    }

    tmpreq->filters->keys = static_cast<char **>(util_smart_calloc_s(sizeof(char *), len));
    if (tmpreq->filters->keys == nullptr) {
        ERROR("Out of memory");
        goto cleanup;
    }
    tmpreq->filters->values = static_cast<json_map_string_bool **>(util_smart_calloc_s(sizeof(json_map_string_bool *),
                                                                                       len));
    if (tmpreq->filters->values == nullptr) {
        free(tmpreq->filters->keys);
        tmpreq->filters->keys = nullptr;
        ERROR("Out of memory");
        goto cleanup;
    }

    for (auto &iter : grequest->filters()) {
        tmpreq->filters->values[tmpreq->filters->len] = static_cast<json_map_string_bool *>
                                                        (util_common_calloc_s(sizeof(json_map_string_bool)));
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
    free_network_list_request(tmpreq);
    return -1;
}

void NetworkServiceImpl::list_response_to_grpc(const network_list_response *response, NetworkListResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_EXEC);
        return;
    }

    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    for (size_t i = 0; i < response->networks_len; i++) {
        NetworkInfo *network = gresponse->add_networks();
        if (response->networks[i]->name != nullptr) {
            network->set_name(response->networks[i]->name);
        }
        if (response->networks[i]->version != nullptr) {
            network->set_version(response->networks[i]->version);
        }
        if (response->networks[i]->plugins == nullptr) {
            continue;
        }
        for (size_t j = 0; j < response->networks[i]->plugins_len; j++) {
            network->add_plugins(response->networks[i]->plugins[j]);
        }
    }
}

Status NetworkServiceImpl::List(ServerContext *context, const NetworkListRequest *request, NetworkListResponse *reply)
{
    int tret;
    service_executor_t *cb = nullptr;
    network_list_request *network_req = nullptr;
    network_list_response *network_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "network_list");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->network.list == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = list_request_from_grpc(request, &network_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    (void)cb->network.list(network_req, &network_res);
    list_response_to_grpc(network_res, reply);

    free_network_list_request(network_req);
    free_network_list_response(network_res);

    return Status::OK;
}

int NetworkServiceImpl::remove_request_from_grpc(const NetworkRemoveRequest *grequest, network_remove_request **request)
{
    auto *tmpreq = static_cast<network_remove_request *>(util_common_calloc_s(sizeof(network_remove_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->name().empty()) {
        tmpreq->name = util_strdup_s(grequest->name().c_str());
    }

    *request = tmpreq;
    return 0;
}

void NetworkServiceImpl::remove_response_to_grpc(const network_remove_response *response,
                                                 NetworkRemoveResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_EXEC);
        return;
    }
    gresponse->set_cc(response->cc);
    if (response->name != nullptr) {
        gresponse->set_name(response->name);
    }
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
}

Status NetworkServiceImpl::Remove(ServerContext *context, const NetworkRemoveRequest *request,
                                  NetworkRemoveResponse *reply)
{
    int tret;
    service_executor_t *cb = nullptr;
    network_remove_request *network_req = nullptr;
    network_remove_response *network_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "network_remove");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->network.remove == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = remove_request_from_grpc(request, &network_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    (void)cb->network.remove(network_req, &network_res);
    remove_response_to_grpc(network_res, reply);

    free_network_remove_request(network_req);
    free_network_remove_response(network_res);

    return Status::OK;
}
