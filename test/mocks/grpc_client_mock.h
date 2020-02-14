/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * Description: grpc client mock
 * Author: wujing
 * Create: 2019-12-19
 */

#ifndef GRPC_CLIENT_MOCK_H_
#define GRPC_CLIENT_MOCK_H_

#include <gmock/gmock.h>
#include "grpc_client.h"

class MockGrpcClient {
public:
    virtual ~MockGrpcClient() = default;
    MOCK_METHOD1(GrpcOpsInit, int(isula_connect_ops *ops));
};

void GrpcClient_SetMock(MockGrpcClient* mock);

#endif  // GRPC_CLIENT_MOCK_H_
