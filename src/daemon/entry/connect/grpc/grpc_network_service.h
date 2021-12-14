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
 * Author: zhangxiaoyu
 * Create: 2020-09-11
 * Description: provide grpc network functions
 ******************************************************************************/
#ifndef DAEMON_ENTRY_CONNECT_GRPC_GRPC_NETWORK_SERVICE_H
#define DAEMON_ENTRY_CONNECT_GRPC_GRPC_NETWORK_SERVICE_H

#ifdef ENABLE_NATIVE_NETWORK
#include <grpc++/grpc++.h>
#include "callback.h"
#include "network.grpc.pb.h"
#include "error.h"

using namespace network;

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerReaderWriter;
using grpc::ServerWriter;
using grpc::Status;
using grpc::StatusCode;

// Implement of network service
class NetworkServiceImpl final : public NetworkService::Service {
public:
    NetworkServiceImpl() = default;
    NetworkServiceImpl(const NetworkServiceImpl &) = delete;
    NetworkServiceImpl &operator=(const NetworkServiceImpl &) = delete;
    virtual ~NetworkServiceImpl() = default;

    Status Create(ServerContext *context, const NetworkCreateRequest *request, NetworkCreateResponse *reply) override;

    Status Inspect(ServerContext *context, const NetworkInspectRequest *request, NetworkInspectResponse *reply) override;

    Status List(ServerContext *context, const NetworkListRequest *request, NetworkListResponse *reply) override;

    Status Remove(ServerContext *context, const NetworkRemoveRequest *request, NetworkRemoveResponse *reply) override;

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

    int create_request_from_grpc(const NetworkCreateRequest *grequest, network_create_request **request);

    void create_response_to_grpc(const network_create_response *response, NetworkCreateResponse *gresponse);

    int inspect_request_from_grpc(const NetworkInspectRequest *grequest, network_inspect_request **request);

    void inspect_response_to_grpc(const network_inspect_response *response, NetworkInspectResponse *gresponse);

    int list_request_from_grpc(const NetworkListRequest *grequest, network_list_request **request);

    void list_response_to_grpc(const network_list_response *response, NetworkListResponse *gresponse);

    int remove_request_from_grpc(const NetworkRemoveRequest *grequest, network_remove_request **request);

    void remove_response_to_grpc(const network_remove_response *response, NetworkRemoveResponse *gresponse);
};

#endif

#endif // DAEMON_ENTRY_CONNECT_GRPC_GRPC_NETWORK_SERVICE_H
