/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhangxiaoyu
 * Create: 2020-10-31
 * Description: provide network callback function definition
 *******************************************************************************/

#ifndef DAEMON_MODULES_API_NETWORK_CONFIG_H
#define DAEMON_MODULES_API_NETWORK_CONFIG_H

#include "filters.h"
#include "isula_libutils/network_create_request.h"
#include "isula_libutils/network_create_response.h"
#include "isula_libutils/network_network_info.h"

extern const char *g_default_driver;

int network_config_bridge_create(const network_create_request *request, network_create_response **response);

int network_config_inspect(const char *name, char **network_json);

int network_config_list(const struct filters_args *filters, network_network_info ***networks, size_t *networks_len);

#endif // DAEMON_MODULES_API_NETWORK_CONFIG_H
