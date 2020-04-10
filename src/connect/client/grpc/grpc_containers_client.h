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
 * Description: provide container grpc client definition
 ******************************************************************************/
#ifndef __GRPC_CONTAINERS_CLIENT_H
#define __GRPC_CONTAINERS_CLIENT_H

#include "isula_connect.h"

#ifdef __cplusplus
extern "C" {
#endif

int grpc_containers_client_ops_init(isula_connect_ops *ops);

#ifdef __cplusplus
}
#endif

#endif

