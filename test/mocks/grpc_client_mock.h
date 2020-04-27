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
