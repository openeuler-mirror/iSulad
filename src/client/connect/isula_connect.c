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
 * Author: maoweiyong
 * Create: 2018-11-08
 * Description: provide isula connect command definition
 ******************************************************************************/
#include "isula_connect.h"

#include <string.h>


#ifdef GRPC_CONNECTOR
#include "grpc_client.h"
#else
#include "rest_client.h"
#endif

static isula_connect_ops g_connect_ops;

/* connect client ops init */
int connect_client_ops_init(void)
{
    (void)memset(&g_connect_ops, 0, sizeof(g_connect_ops));
#ifdef GRPC_CONNECTOR
    if (grpc_ops_init(&g_connect_ops)) {
        return -1;
    }
#else
    if (rest_ops_init(&g_connect_ops)) {
        return -1;
    }
#endif
    return 0;
}

/* get connect client ops */
isula_connect_ops *get_connect_client_ops(void)
{
    return &g_connect_ops;
}

