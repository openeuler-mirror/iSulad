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
 * Description: provide cni function definition
 *********************************************************************************/
#ifndef CLIBCNI_API_H
#define CLIBCNI_API_H

#include <sys/types.h>

#include "version.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cni_port_mapping {
    int32_t host_port;
    int32_t container_port;
    char *protocol;
    char *host_ip;
};

struct runtime_conf {
    char *container_id;
    char *netns;
    char *ifname;
    char *(*args)[2];
    size_t args_len;

    struct cni_port_mapping **p_mapping;
    size_t p_mapping_len;
};

struct cni_network_conf {
    char *name;
    char *type;
    char *bytes;
};

struct cni_network_list_conf {
    size_t plugin_len;
    char *first_plugin_name;
    char *first_plugin_type;
    char *name;
    char *bytes;
};

int cni_add_network_list(const char *net_list_conf_str, const struct runtime_conf *rc, char **paths,
                         struct result **pret, char **err);

int cni_add_network(const char *cni_net_conf_str, const struct runtime_conf *rc, char **paths,
                    struct result **add_result,
                    char **err);

int cni_del_network_list(const char *net_list_conf_str, const struct runtime_conf *rc, char **paths, char **err);

int cni_del_network(const char *cni_net_conf_str, const struct runtime_conf *rc, char **paths, char **err);

int cni_get_version_info(const char *plugin_type, char **paths, struct plugin_info **pinfo, char **err);

int cni_conf_files(const char *dir, const char **extensions, size_t ext_len, char ***result, char **err);

int cni_conf_from_file(const char *filename, struct cni_network_conf **config, char **err);

int cni_conflist_from_bytes(const char *bytes, struct cni_network_list_conf **list, char **err);

int cni_conflist_from_file(const char *filename, struct cni_network_list_conf **list, char **err);

int cni_conflist_from_conf(const struct cni_network_conf *cni_net_conf,
                           struct cni_network_list_conf **cni_net_conf_list,
                           char **err);

void free_cni_network_conf(struct cni_network_conf *val);

void free_cni_network_list_conf(struct cni_network_list_conf *val);

void free_cni_port_mapping(struct cni_port_mapping *val);

void free_runtime_conf(struct runtime_conf *rc);

#ifdef __cplusplus
}
#endif

#endif

