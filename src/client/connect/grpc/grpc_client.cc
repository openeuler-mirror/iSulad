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
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide grpc ops functions
 ******************************************************************************/

#include "grpc_client.h"
#include "grpc_containers_client.h"
#include "grpc_images_client.h"
#include "grpc_volumes_client.h"

#ifdef ENABLE_NATIVE_NETWORK
#include "grpc_network_client.h"
#endif

int grpc_ops_init(isula_connect_ops *ops)
{
    if (ops == nullptr) {
        return -1;
    }

    if (grpc_containers_client_ops_init(ops) != 0) {
        return -1;
    }
    if (grpc_images_client_ops_init(ops) != 0) {
        return -1;
    }
    if (grpc_volumes_client_ops_init(ops) != 0) {
        return -1;
    }

#ifdef ENABLE_NATIVE_NETWORK
    if (grpc_network_client_ops_init(ops)) {
        return -1;
    }
#endif

    return 0;
}

