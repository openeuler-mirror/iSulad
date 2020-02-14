/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * Description: grpc client mock
 * Author: wujing
 * Create: 2019-12-19
 */
#include "grpc_client_mock.h"

namespace {
MockGrpcClient *g_grpc_client_mock = NULL;
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

