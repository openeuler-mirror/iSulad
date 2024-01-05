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

#ifndef DAEMON_ENTRY_CONNECT_GRPC_GRPC_VOLUMES_SERVICE_H
#define DAEMON_ENTRY_CONNECT_GRPC_GRPC_VOLUMES_SERVICE_H

#include <grpc++/grpc++.h>

#include "volumes.grpc.pb.h"
#include "callback.h"
#include "error.h"

using grpc::ServerContext;
using grpc::Status;

// Implement of volume service
class VolumeServiceImpl final : public volume::VolumeService::Service {
public:
    VolumeServiceImpl() = default;
    VolumeServiceImpl(const VolumeServiceImpl &) = delete;
    VolumeServiceImpl &operator=(const VolumeServiceImpl &) = delete;
    virtual ~VolumeServiceImpl() = default;

    Status List(ServerContext *context, const volume::ListVolumeRequest *request, volume::ListVolumeResponse *reply) override;

    Status Remove(ServerContext *context, const volume::RemoveVolumeRequest *request, volume::RemoveVolumeResponse *reply) override;

    Status Prune(ServerContext *context, const volume::PruneVolumeRequest *request, volume::PruneVolumeResponse *reply) override;

private:
    template <class T1, class T2>
    int response_to_grpc(const T1 *response, T2 *gresponse)
    {
        if (response == nullptr) {
            gresponse->set_cc(ISULAD_ERR_MEMOUT);
            return 0;
        }
        gresponse->set_cc(response->cc);
        if (response->errmsg != nullptr) {
            gresponse->set_errmsg(response->errmsg);
        }
        return 0;
    }

    int volume_list_request_from_grpc(const volume::ListVolumeRequest*, volume_list_volume_request**);

    int volume_list_response_to_grpc(volume_list_volume_response *response, volume::ListVolumeResponse *gresponse);

    int volume_remove_request_from_grpc(const volume::RemoveVolumeRequest *grequest, volume_remove_volume_request **request);

    int volume_prune_request_from_grpc(const volume::PruneVolumeRequest *grequest, volume_prune_volume_request **request);

    int volume_prune_response_to_grpc(volume_prune_volume_response *response, volume::PruneVolumeResponse *gresponse);
};

#endif // DAEMON_ENTRY_CONNECT_GRPC_GRPC_VOLUMES_SERVICE_H

