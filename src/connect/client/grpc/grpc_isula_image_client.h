/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
* Author: liuhao
* Create: 2019-07-12
* Description: provide isula connect command definition
*******************************************************************************/
#ifndef __GRPC_ISULA_IMAGE_CONNECT_H
#define __GRPC_ISULA_IMAGE_CONNECT_H

#include "isula_image_connect.h"

#ifdef __cplusplus
extern "C" {
#endif

int grpc_isula_image_client_ops_init(isula_image_ops *ops);

#ifdef __cplusplus
}
#endif

#endif /* __GRPC_ISULA_IMAGE_CONNECT_H */
