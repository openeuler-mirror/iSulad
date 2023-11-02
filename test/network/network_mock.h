/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: define network mock method
 * Author: liuxu
 * Create: 2023-10-30
 */

#include <isula_libutils/cni_cached_info.h>
#include <isula_libutils/cni_net_conf_list.h>
#include <isula_libutils/cni_array_of_strings.h>

cni_cached_info *invoke_network_get_cached_info(char *cache_path);

cni_net_conf_list *invoke_network_get_cni_net_conf_list_from_cached_info(cni_cached_info *info);

cni_array_of_strings_container *invoke_network_get_aliases_from_cached_info(cni_cached_info *info);