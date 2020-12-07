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
#ifndef NETWORK_ADAPTOR_CNI_API_H
#define NETWORK_ADAPTOR_CNI_API_H

#include <isula_libutils/json_common.h>
#include "map.h"

#ifdef __cplusplus
extern "C" {
#endif

struct attach_net_conf {
    char *name;
    char *interface;
};

typedef struct adaptor_cni_config_t {
    char *name;
    char *ns;
    char *pod_id;
    char *netns_path;
    char *default_interface;

    struct attach_net_conf **extral_nets;
    size_t extral_nets_len;

    // external args;
    json_map_string_string *args;

    // extention configs: map<string, string>
    map_t *annotations;
} adaptor_cni_config;

bool adaptor_cni_init(const char *cache_dir, const char *conf_dir, const char* const *bin_paths, size_t bin_paths_len);

int adaptor_cni_update_confs();

bool check_cni_inited();

int adaptor_cni_setup(const adaptor_cni_config *conf);

int adaptor_cni_teardown(const adaptor_cni_config *conf);

void free_attach_net_conf(struct attach_net_conf *ptr);

void free_adaptor_cni_config(adaptor_cni_config *conf);

#ifdef __cplusplus
}
#endif

#endif

