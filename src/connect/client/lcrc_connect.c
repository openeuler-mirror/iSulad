/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: maoweiyong
 * Create: 2018-11-08
 * Description: provide lcrc connect command definition
 ******************************************************************************/
#include "lcrc_connect.h"

#include "securec.h"

#ifdef GRPC_CONNECTOR
#include "grpc_client.h"
#else
#include "rest_client.h"
#endif

static lcrc_connect_ops g_connect_ops;

/* connect client ops init */
int connect_client_ops_init(void)
{
    errno_t ret;
    ret = memset_s(&g_connect_ops, sizeof(g_connect_ops), 0, sizeof(g_connect_ops));
    if (ret != EOK) {
        return -1;
    }
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
lcrc_connect_ops *get_connect_client_ops(void)
{
    return &g_connect_ops;
}
