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
 * Description: provide rest client
 ******************************************************************************/
#include "rest_client.h"
#include "rest_containers_client.h"
#include "rest_images_client.h"

#ifdef ENABLE_NATIVE_NETWORK
#include "rest_network_client.h"
#endif

int rest_ops_init(isula_connect_ops *ops)
{
    if (ops == NULL) {
        return -1;
    }

    /* Add all operator api at here */
    if (rest_containers_client_ops_init(ops) != 0) {
        return -1;
    }
    if (rest_images_client_ops_init(ops) != 0) {
        return -1;
    }

#ifdef ENABLE_NATIVE_NETWORK
    if (rest_network_client_ops_init(ops) != 0) {
        return -1;
    }
#endif

    return 0;
}

