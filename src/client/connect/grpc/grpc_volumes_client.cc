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
 * Create: 2020-09-04
 * Description: provide grpc volume service functions
 ******************************************************************************/
#include "grpc_volumes_client.h"

#include <string>

#include "api.grpc.pb.h"
#include "client_base.h"
#include "volumes.grpc.pb.h"
#include "utils.h"

using namespace volume;

using grpc::ClientContext;
using grpc::Status;

class VolumeList : public ClientBase<VolumeService, VolumeService::Stub, isula_list_volume_request, ListVolumeRequest,
                                     isula_list_volume_response, ListVolumeResponse> {
public:
    explicit VolumeList(void *args)
            : ClientBase(args)
    {
    }
    ~VolumeList() = default;
    VolumeList(const VolumeList &) = delete;
    VolumeList &operator=(const VolumeList &) = delete;

    auto response_from_grpc(ListVolumeResponse *gresponse, isula_list_volume_response *response) -> int override
    {
        int num = gresponse->volumes_size();
        if (num <= 0) {
            response->volumes = nullptr;
            response->volumes_len = 0;
            response->server_errono = gresponse->cc();
            if (!gresponse->errmsg().empty()) {
                response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
            }
            return 0;
        }

        response->volumes_len = 0;

        if (static_cast<size_t>(num) > SIZE_MAX / sizeof(struct isula_volume_info)) {
            ERROR("Too many volume");
            response->cc = ISULAD_ERR_MEMOUT;
            return -1;
        }
        auto *volumes = static_cast<struct isula_volume_info *>(
                util_smart_calloc_s(sizeof(struct isula_volume_info), static_cast<size_t>(num)));
        if (volumes == nullptr) {
            ERROR("out of memory");
            response->cc = ISULAD_ERR_MEMOUT;
            return -1;
        }

        for (int i {}; i < num; i++) {
            const Volume &volume = gresponse->volumes(i);
            const char *driver = !volume.driver().empty() ? volume.driver().c_str() : "-";
            volumes[i].driver = util_strdup_s(driver);
            const char *name = !volume.name().empty() ? volume.name().c_str() : "-";
            volumes[i].name = util_strdup_s(name);
        }

        response->volumes = volumes;
        response->volumes_len = static_cast<size_t>(num);
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const ListVolumeRequest &req, ListVolumeResponse *reply) -> Status override
    {
        return stub_->List(context, req, reply);
    }
};

class VolumeRemove : public ClientBase<VolumeService, VolumeService::Stub, isula_remove_volume_request,
                                       RemoveVolumeRequest, isula_remove_volume_response, RemoveVolumeResponse> {
public:
    explicit VolumeRemove(void *args)
            : ClientBase(args)
    {
    }
    ~VolumeRemove() = default;
    VolumeRemove(const VolumeRemove &) = delete;
    VolumeRemove &operator=(const VolumeRemove &) = delete;

    auto request_to_grpc(const isula_remove_volume_request *request, RemoveVolumeRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_name(request->name);
        }

        return 0;
    }

    auto response_from_grpc(RemoveVolumeResponse *gresponse, isula_remove_volume_response *response) -> int override
    {
        response->server_errono = static_cast<uint32_t>(gresponse->cc());

        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const RemoveVolumeRequest &req) -> int override
    {
        if (req.name().empty()) {
            ERROR("Missing volume name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const RemoveVolumeRequest &req, RemoveVolumeResponse *reply)
            -> Status override
    {
        return stub_->Remove(context, req, reply);
    }
};

class VolumePrune : public ClientBase<VolumeService, VolumeService::Stub, isula_prune_volume_request,
                                      PruneVolumeRequest, isula_prune_volume_response, PruneVolumeResponse> {
public:
    explicit VolumePrune(void *args)
            : ClientBase(args)
    {
    }
    ~VolumePrune() = default;
    VolumePrune(const VolumePrune &) = delete;
    VolumePrune &operator=(const VolumePrune &) = delete;

    auto response_from_grpc(PruneVolumeResponse *gresponse, isula_prune_volume_response *response) -> int override
    {
        auto size = gresponse->volumes_size();
        if (size != 0) {
            response->volumes = static_cast<char **>(util_common_calloc_s(sizeof(char *) * size));
            if (response->volumes == nullptr) {
                return -1;
            }

            for (int i {}; i < size; i++) {
                response->volumes[i] = util_strdup_s(gresponse->volumes(i).c_str());
                response->volumes_len++;
            }
        }

        response->server_errono = static_cast<uint32_t>(gresponse->cc());

        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const PruneVolumeRequest &req, PruneVolumeResponse *reply) -> Status override
    {
        return stub_->Prune(context, req, reply);
    }
};

auto grpc_volumes_client_ops_init(isula_connect_ops *ops) -> int
{
    if (ops == nullptr) {
        return -1;
    }

    ops->volume.list = container_func<isula_list_volume_request, isula_list_volume_response, VolumeList>;
    ops->volume.remove = container_func<isula_remove_volume_request, isula_remove_volume_response, VolumeRemove>;
    ops->volume.prune = container_func<isula_prune_volume_request, isula_prune_volume_response, VolumePrune>;

    return 0;
}
