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
* Create: 2019-09-5
* Description: isula containers list operator implement
*******************************************************************************/
#ifndef __OCI_REMOTE_CONTAINERS_LIST_H
#define __OCI_REMOTE_CONTAINERS_LIST_H

#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int isula_list_containers(json_map_string_bool **containers);

#ifdef __cplusplus
}
#endif

#endif
