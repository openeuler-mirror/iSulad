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
#ifndef DAEMON_MODULE_NETWORK_API_H
#define DAEMON_MODULE_NETWORK_API_H

#include <isula_libutils/json_common.h>
#include <isula_libutils/network_create_request.h>
#include <isula_libutils/network_create_response.h>
#include <isula_libutils/network_network_info.h>
#include "filters.h"
#include "map.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CONFIG_FILE_COUNT 1024
// support network type
#define NETWOKR_API_TYPE_NATIVE "native"
#define NETWOKR_API_TYPE_CRI "cri"

struct attach_net_conf {
    char *name;
    char *interface;
};

typedef struct network_api_conf_t {
    char *name;
    char *ns;
    char *pod_id;
    char *netns_path;
    char *default_interface;

    // attach network panes config
    struct {
        struct attach_net_conf **extral_nets;
        size_t extral_nets_len;
    };

    // external args;
    json_map_string_string *args;

    // extention configs: map<string, string>
    map_t *annotations;
} network_api_conf;

struct network_api_result {
    char *name;
    char *interface;

    char **ips;
    size_t ips_len;
    char *mac;
};

typedef struct network_api_result_list_t {
    struct network_api_result **items;
    size_t len;
    size_t cap;
} network_api_result_list;

void free_network_api_result(struct network_api_result *ptr);

void free_network_api_result_list(network_api_result_list *ptr);

void free_attach_net_conf(struct attach_net_conf *ptr);

void free_network_api_conf(network_api_conf *ptr);

bool network_module_init(const char *network_plugin, const char *cache_dir, const char *conf_dir, const char* bin_path);

int network_module_attach(const network_api_conf *conf, const char *type, network_api_result_list **result);

int network_module_detach(const network_api_conf *conf, const char *type);

int network_module_conf_create(const char *type, const network_create_request *request,
                               network_create_response **response);

int network_module_conf_inspect(const char *type, const char *name, char **network_json);

int network_module_conf_list(const char *type, const struct filters_args *filters, network_network_info ***networks,
                             size_t *networks_len);

int network_module_conf_rm(const char *type, const char *name, char **res_name);

bool network_module_check(const char *type);

int network_module_update(const char *type);

void network_module_exit();

int network_module_insert_portmapping(const char *val, network_api_conf *conf);

int network_module_insert_bandwith(const char *val, network_api_conf *conf);

int network_module_insert_iprange(const char *val, network_api_conf *conf);

int network_module_exist(const char *type, const char *name);

#ifdef __cplusplus
}
#endif

#endif

