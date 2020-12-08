/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2019-12-19
 * Description: provide grpc client mock
 ******************************************************************************/

#include "grpc_client_mock.h"

namespace {
MockGrpcClient *g_grpc_client_mock = nullptr;
}

void GrpcClient_SetMock(MockGrpcClient* mock)
{
    g_grpc_client_mock = mock;
}

int grpc_ops_init(isula_connect_ops *ops)
{
    if (g_grpc_client_mock != nullptr) {
        return g_grpc_client_mock->GrpcOpsInit(ops);
    }
    return 0;
}

