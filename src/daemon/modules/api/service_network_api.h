/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhangxiaoyu
 * Create: 2020-12-30
 * Description: provide container supervisor definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_API_SERVICE_NETWORK_API_H
#define DAEMON_MODULES_API_SERVICE_NETWORK_API_H

#include <stdbool.h>

#include "container_unix.h"
#include "network_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int prepare_network(container_t *cont);

int remove_network(container_t *cont);

bool network_store_container_list_add(container_t *cont);

void set_container_skip_remove_network(container_t *cont);

void reset_container_skip_remove_network(container_t *cont);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_MODULES_API_SERVICE_NETWORK_API_H
