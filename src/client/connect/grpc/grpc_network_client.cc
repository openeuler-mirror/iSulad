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
 * Create: 2020-09-07
 * Description: provide grpc network client functions
 ******************************************************************************/
#include "grpc_network_client.h"

#include <string>
#include "client_base.h"
#include "network.grpc.pb.h"

using namespace network;

using grpc::ClientContext;
using grpc::ClientReader;
using grpc::ClientReaderWriter;
using grpc::Status;
using grpc::StatusCode;

class NetworkCreate : public
    ClientBase<NetworkService, NetworkService::Stub, isula_network_create_request, NetworkCreateRequest,
    isula_network_create_response, NetworkCreateResponse> {
public:
    explicit NetworkCreate(void *args)
        : ClientBase(args)
    {
    }
    ~NetworkCreate() = default;

    auto request_to_grpc(const isula_network_create_request *request, NetworkCreateRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_name(request->name);
        }
        if (request->driver != nullptr) {
            grequest->set_driver(request->driver);
        }
        if (request->gateway != nullptr) {
            grequest->set_gateway(request->gateway);
        }

        grequest->set_internal(request->internal);

        if (request->subnet != nullptr) {
            grequest->set_subnet(request->subnet);
        }

        return 0;
    }

    auto response_from_grpc(NetworkCreateResponse *gresponse, isula_network_create_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }
        if (!gresponse->path().empty()) {
            response->path = util_strdup_s(gresponse->path().c_str());
        }
        return 0;
    }

    auto grpc_call(ClientContext *context, const NetworkCreateRequest &req, NetworkCreateResponse *reply) -> Status override
    {
        return stub_->Create(context, req, reply);
    }
};

auto grpc_network_client_ops_init(isula_connect_ops *ops) -> int
{
    if (ops == nullptr) {
        return -1;
    }
    // implement following interface
    ops->network.create = container_func<isula_network_create_request, isula_network_create_response, NetworkCreate>;

    return 0;
}

