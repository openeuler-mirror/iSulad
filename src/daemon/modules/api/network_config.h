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

#include "isula_libutils/network_create_request.h"
#include "isula_libutils/network_create_response.h"

extern const char *default_driver;

int bridge_network_config_create(const network_create_request *request, network_create_response **response);

#endif // DAEMON_MODULES_API_NETWORK_CONFIG_H
