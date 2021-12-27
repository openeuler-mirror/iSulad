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

#ifndef UTILS_CUTILS_NETWORK_NAMESPACE_H
#define UTILS_CUTILS_NETWORK_NAMESPACE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

int prepare_network_namespace(const char *netns_path, const bool post_prepare_network, const int pid);

int remove_network_namespace(const char *netns);

int create_network_namespace_file(const char *netns_path);

int remove_network_namespace_file(const char *netns_path);

#ifdef __cplusplus
}
#endif

#endif // UTILS_CUTILS_NETWORK_NAMESPACE_H
