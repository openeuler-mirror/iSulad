/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: gaohuatao
 * Create: 2020-11-09
 * Description: provide CNI network manager function definition
 ******************************************************************************/
#ifndef NET_MANAGER_API_H
#define NET_MANAGER_API_H

#include "map.h"
#include "libcni_api.h"

#ifdef __cplusplus
extern "C" {
#endif

// The key of cni_args map in struct cni_manager 
#define CNI_ARGS_BANDWIDTH_KEY "bandwidth"
#define CNI_ARGS_PORTMAPPING_KEY "portMappings"
#define CNI_ARGS_IPRANGES_KEY "ipRanges"

// cni_manager holds cniNetworkPlugin and podNetwork infos
struct cni_manager {
    char *id;
    char *netns_path;
    char *ifname;
    json_map_string_string *cni_args;

    // map str str to append to cni_network_list_conf
    map_t *annotations;
};

int cni_manager_store_init(const char *cache_dir, const char *conf_path, const char* const *bin_paths,
                           size_t bin_paths_len);

int attach_loopback(const char *id, const char *netns);

int detach_loopback(const char *id, const char *netns);

void free_cni_manager(struct cni_manager *manager);

int cri_get_conflist_from_dir(struct cni_network_list_conf ***store, size_t *res_len);

int cri_update_confist_from_dir();

int cri_attach_network_plane(const struct cni_manager *manager, const char *net_list_conf_str, struct result **result);

int cri_detach_network_plane(const struct cni_manager *manager, const char *net_list_conf_str, struct result **result);


int isula_update_confist_from_dir();

int isula_attach_network_plane(const struct cni_manager *manager, const char *net_name, struct result **result);

int isula_detach_network_plane(const struct cni_manager *manager, const char *net_name, struct result **result);



#ifdef __cplusplus
}
#endif

#endif
