/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: haozi007
 * Create: 2020-12-25
 * Description: provide common function definition for network module
 ******************************************************************************/
#ifndef NETWORK_MODULE_TOOLS_H
#define NETWORK_MODULE_TOOLS_H

#include "network_api.h"
#include "libcni_result_type.h"

#ifdef __cplusplus
extern "C" {
#endif

bool network_api_result_list_append(struct network_api_result *result, network_api_result_list *list);

struct network_api_result *network_parse_to_api_result(const char *name, const char *interface,
                                                       const struct cni_opt_result *cni_result);

#ifdef __cplusplus
}
#endif

#endif
