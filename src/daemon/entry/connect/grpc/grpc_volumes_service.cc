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
 * Author: wangfengtu
 * Create: 2020-09-02
 * Description: provide grpc volume functions
 ******************************************************************************/

#include "grpc_volumes_service.h"

#include <unistd.h>
#include <iostream>
#include <memory>
#include <new>
#include <string>

#include "isula_libutils/log.h"
#include "utils.h"
#include "grpc_server_tls_auth.h"

int VolumeServiceImpl::volume_list_request_from_grpc(const ListVolumeRequest *grequest,
                                                     volume_list_volume_request **request)
{
    auto *tmpreq = static_cast<volume_list_volume_request *>(util_common_calloc_s(sizeof(volume_list_volume_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    *request = tmpreq;

    return 0;
}

int VolumeServiceImpl::volume_list_response_to_grpc(volume_list_volume_response *response,
                                                    ListVolumeResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }

    for (size_t i {}; i < response->volumes_len; i++) {
        auto *volume = gresponse->add_volumes();
        if (response->volumes[i]->driver != nullptr) {
            volume->set_driver(response->volumes[i]->driver);
        }
        if (response->volumes[i]->name != nullptr) {
            volume->set_name(response->volumes[i]->name);
        }
    }

    return 0;
}

int VolumeServiceImpl::volume_remove_request_from_grpc(const RemoveVolumeRequest *grequest,
                                                       volume_remove_volume_request **request)
{
    auto *tmpreq =
        static_cast<volume_remove_volume_request *>(util_common_calloc_s(sizeof(volume_remove_volume_request)));
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

int VolumeServiceImpl::volume_prune_request_from_grpc(const PruneVolumeRequest *grequest,
                                                      volume_prune_volume_request **request)
{
    auto *tmpreq =
        static_cast<volume_prune_volume_request *>(util_common_calloc_s(sizeof(volume_prune_volume_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    *request = tmpreq;

    return 0;
}

int VolumeServiceImpl::volume_prune_response_to_grpc(volume_prune_volume_response *response,
                                                     PruneVolumeResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return 0;
    }

    gresponse->set_cc(response->cc);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }

    for (size_t i {}; i < response->volumes_len; i++) {
        gresponse->add_volumes(response->volumes[i]);
    }

    return 0;
}

Status VolumeServiceImpl::List(ServerContext *context, const ListVolumeRequest *request, ListVolumeResponse *reply)
{
    auto status = GrpcServerTlsAuth::auth(context, "volume_list");
    if (!status.ok()) {
        return status;
    }
    auto *cb = get_service_executor();
    if (cb == nullptr || cb->volume.list == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    volume_list_volume_request *volume_req = nullptr;
    int tret = volume_list_request_from_grpc(request, &volume_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    volume_list_volume_response *volume_res = nullptr;
    int ret = cb->volume.list(volume_req, &volume_res);
    tret = volume_list_response_to_grpc(volume_res, reply);
    free_volume_list_volume_request(volume_req);
    free_volume_list_volume_response(volume_res);
    if (tret != 0) {
        reply->set_errmsg(util_strdup_s(errno_to_error_message(ISULAD_ERR_INTERNAL)));
        reply->set_cc(ISULAD_ERR_INPUT);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }

    return Status::OK;
}

Status VolumeServiceImpl::Remove(ServerContext *context, const RemoveVolumeRequest *request,
                                 RemoveVolumeResponse *reply)
{
    auto status = GrpcServerTlsAuth::auth(context, "volume_remove");
    if (!status.ok()) {
        return status;
    }
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr || cb->volume.remove == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    volume_remove_volume_request *volume_req = nullptr;
    int tret = volume_remove_request_from_grpc(request, &volume_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    volume_remove_volume_response *volume_res = nullptr;
    int ret = cb->volume.remove(volume_req, &volume_res);
    tret = response_to_grpc(volume_res, reply);
    free_volume_remove_volume_request(volume_req);
    free_volume_remove_volume_response(volume_res);
    if (tret != 0) {
        reply->set_errmsg(util_strdup_s(errno_to_error_message(ISULAD_ERR_INTERNAL)));
        reply->set_cc(ISULAD_ERR_INPUT);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }

    return Status::OK;
}

Status VolumeServiceImpl::Prune(ServerContext *context, const PruneVolumeRequest *request, PruneVolumeResponse *reply)
{
    auto status = GrpcServerTlsAuth::auth(context, "volume_prune");
    if (!status.ok()) {
        return status;
    }
    service_executor_t *cb = get_service_executor();
    if (cb == nullptr || cb->volume.prune == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }
    volume_prune_volume_request *volume_req = nullptr;
    int tret = volume_prune_request_from_grpc(request, &volume_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    volume_prune_volume_response *volume_res = nullptr;
    int ret = cb->volume.prune(volume_req, &volume_res);
    tret = volume_prune_response_to_grpc(volume_res, reply);
    free_volume_prune_volume_request(volume_req);
    free_volume_prune_volume_response(volume_res);
    if (tret != 0) {
        reply->set_errmsg(util_strdup_s(errno_to_error_message(ISULAD_ERR_INTERNAL)));
        reply->set_cc(ISULAD_ERR_INPUT);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }

    return Status::OK;
}
