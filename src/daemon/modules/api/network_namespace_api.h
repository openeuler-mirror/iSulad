/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: chengzeruizhi
 * Create: 2021-10-19
 * Description: provide network namespace definition
 *********************************************************************************/

#ifndef DAEMON_MODULES_API_NETWORK_NAMESPACE_API_H
#define DAEMON_MODULES_API_NETWORK_NAMESPACE_API_H

#include <stdbool.h>

#include "container_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int remove_network_namespace(const char *netns);

#ifdef ENABLE_NATIVE_NETWORK
int prepare_network_namespace(const bool post_prepare_network, const int pid, const char *netns_path);
#endif

// TODO: need to merge
char *get_sandbox_key(const container_inspect *inspect_data);
#ifdef ENABLE_NATIVE_NETWORK
char *get_netns_path(const char *sandbox_key, const bool attach);
#endif

#ifdef __cplusplus
}
#endif

#endif // DAEMON_MODULES_API_NETWORK_NAMESPACE_API_H
