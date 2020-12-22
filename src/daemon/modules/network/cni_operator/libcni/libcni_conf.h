/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2019-04-25
 * Description: provide conf function definition
 *********************************************************************************/

#ifndef CLIBCNI_CONF_H
#define CLIBCNI_CONF_H

#include "isula_libutils/cni_net_conf_list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct network_config {
    cni_net_conf *network;

    char *bytes;
};

struct network_config_list {
    cni_net_conf_list *list;

    char *bytes;
};

void free_network_config(struct network_config *config);

void free_network_config_list(struct network_config_list *conf_list);

struct network_config *conf_from_bytes(const char *conf_str);

struct network_config *conf_from_file(const char *filename);

struct network_config_list *conflist_from_bytes(const char *json_str);

struct network_config_list *conflist_from_file(const char *filename);

struct network_config_list *conflist_from_conf(const struct network_config *conf);

int conf_files(const char *dir, const char * const *extensions, size_t ext_len, char ***result);

#ifdef __cplusplus
}
#endif

#endif
