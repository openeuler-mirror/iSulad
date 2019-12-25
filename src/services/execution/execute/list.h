/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container list callback function definition
 ******************************************************************************/

#ifndef __EXECUTION_CONTAINER_LIST_CB_H_
#define __EXECUTION_CONTAINER_LIST_CB_H_

#include "callback.h"

#ifdef __cplusplus
extern "C" {
#endif

int dup_json_map_string_string(const json_map_string_string *src, json_map_string_string *dest);

int container_list_cb(const container_list_request *request, container_list_response **response);

#ifdef __cplusplus
}
#endif

#endif

