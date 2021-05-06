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

#ifndef DAEMON_MODULES_NETWORK_ADAPTOR_NATIVE_H
#define DAEMON_MODULES_NETWORK_ADAPTOR_NATIVE_H

#include "network_api.h"

int native_init(const char *conf_dir, const char **bin_paths, const size_t bin_paths_len);

bool native_ready();

void native_destory();

int native_attach_networks(const network_api_conf *conf, network_api_result_list *result);

int native_detach_networks(const network_api_conf *conf, network_api_result_list *result);

bool native_network_exist(const char *name);

int native_config_create(const network_create_request *request, char **name, uint32_t *cc);

int native_config_inspect(const char *name, char **network_json);

int native_config_list(const struct filters_args *filters, network_network_info ***networks, size_t *networks_len);

int native_config_remove(const char *name, char **res_name);

int native_network_add_container_list(const char *network_name, const char *cont_id);

#endif // DAEMON_MODULES_NETWORK_ADAPTOR_NATIVE_H
