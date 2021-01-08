/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: haozi007
 * Create: 2020-12-05
 * Description: provide cni network functions
 *********************************************************************************/
#ifndef NETWORK_ADAPTOR_CRI_API_H
#define NETWORK_ADAPTOR_CRI_API_H

#include "network_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int adaptor_cni_init_confs(const char *conf_dir, const char **bin_paths, const size_t bin_paths_len);

int adaptor_cni_update_confs();

bool adaptor_cni_check_inited();

int adaptor_cni_setup(const network_api_conf *conf, network_api_result_list *result);

int adaptor_cni_teardown(const network_api_conf *conf, network_api_result_list *result);

int adaptor_cni_check(const network_api_conf *conf, network_api_result_list *result);

#ifdef __cplusplus
}
#endif

#endif

