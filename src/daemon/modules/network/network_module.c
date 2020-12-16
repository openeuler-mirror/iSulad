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
 * Description: provide network apis
 *********************************************************************************/
#include "network_api.h"

#include<isula_libutils/log.h>

#include "adaptor_cri.h"
#include "manager.h"
#include "utils_string.h"
#include "utils_array.h"
#include "utils.h"

#define DEFAULT_CNI_CONFIG_FILES_DIR "/etc/cni/net.d"
#define DEFAULT_CNI_BIN_FILES_DIR "/opt/cni/bin"

struct net_ops {
    int (*init)(void);
    int (*attach)(const network_api_conf *conf, network_api_result_list *result);
    int (*detach)(const network_api_conf *conf, network_api_result_list *result);
    bool (*check)(void);
    int (*update)(void);
    int (*destroy)(void);
};

struct net_type {
    const char *type;
    const struct net_ops *ops;
};

static const struct net_ops g_cri_ops = {
    .init = adaptor_cni_update_confs,
    .attach = adaptor_cni_setup,
    .detach = adaptor_cni_teardown,
    .check = adaptor_cni_check_inited,
    .update = adaptor_cni_update_confs,
    .destroy = NULL,
};

static const struct net_ops g_native_ops = {
    .init = NULL,
    .attach = NULL,
    .detach = NULL,
    .check = NULL,
    .update = NULL,
    .destroy = NULL,
};

static const struct net_type g_nets[] = {
    {
        .type = NETWOKR_API_TYPE_CRI,
        .ops = &g_cri_ops,
    },
    {
        .type = NETWOKR_API_TYPE_NATIVE,
        .ops = &g_native_ops,
    },
};

static const size_t g_numnets = sizeof(g_nets) / sizeof(struct net_type);

static const struct net_type *get_net_by_type(const char *type)
{
    size_t i;

    if (type == NULL) {
        return NULL;
    }

    for (i = 0; i < g_numnets; i++) {
        if (strcmp(type, g_nets[i].type) == 0) {
            return &g_nets[i];
        }
    }

    WARN("Do not support network type: %s", type);
    return NULL;
}

bool network_module_init(const char *network_plugin, const char *cache_dir, const char *conf_dir, const char* bin_path)
{
    size_t i;
    const char *use_bin_path = bin_path != NULL ? bin_path : DEFAULT_CNI_BIN_FILES_DIR;
    const char *use_conf_dir = conf_dir != NULL ? conf_dir : DEFAULT_CNI_CONFIG_FILES_DIR;
    char **bin_paths = NULL;
    size_t bin_paths_len;
    bool ret = true;

    bin_paths = util_string_split(use_bin_path, ';');
    bin_paths_len = util_array_len((const char **)bin_paths);
    if (cni_manager_store_init(cache_dir, use_conf_dir, (const char **)bin_paths, bin_paths_len) != 0) {
        ERROR("init cni manager failed");
        ret = false;
        goto out;
    }

    for (i = 0; i < g_numnets; i++) {
        if (g_nets[i].ops->init == NULL) {
            continue;
        }
        if (strcmp(g_nets[i].type, NETWOKR_API_TYPE_CRI) == 0 && network_plugin == NULL) {
            continue;
        }
        if (g_nets[i].ops->init() != 0) {
            ERROR("init network: %s failed", g_nets[i].type);
            ret = false;
            goto out;
        }
    }

out:
    util_free_array_by_len(bin_paths, bin_paths_len);
    return ret;
}

static inline int do_annotation_insert(const char *key, const char *val, network_api_conf *conf)
{
    if (val == NULL) {
        return 0;
    }

    if (!map_replace(conf->annotations, (void *)key, (void *)val)) {
        ERROR("add %s into annotation failed", key);
        return -1;
    }

    return 0;
}

int network_module_insert_portmapping(const char *val, network_api_conf *conf)
{
    return do_annotation_insert(CNI_ARGS_PORTMAPPING_KEY, val, conf);
}

int network_module_insert_bandwith(const char *val, network_api_conf *conf)
{
    return do_annotation_insert(CNI_ARGS_PORTMAPPING_KEY, val, conf);
}

int network_module_insert_iprange(const char *val, network_api_conf *conf)
{
    return do_annotation_insert(CNI_ARGS_IPRANGES_KEY, val, conf);
}

int network_module_attach(const network_api_conf *conf, const char *type, network_api_result_list **result)
{
    const struct net_type *pnet = NULL;
    int ret = 0;

    if (conf == NULL || result == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    pnet = get_net_by_type(type);
    if (pnet == NULL) {
        ERROR("Unsupport net type: %s", type);
        return -1;
    }

    if (conf->extral_nets_len >= SIZE_MAX - 1) {
        ERROR("Too large extral networks to attach");
        return -1;
    }

    *result = util_common_calloc_s(sizeof(network_api_result_list));
    if (*result == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    (*result)->items = util_smart_calloc_s(sizeof(struct network_api_result *), conf->extral_nets_len + 1);
    if ((*result)->items == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    (*result)->cap = conf->extral_nets_len + 1;

    ret = pnet->ops->attach(conf, *result);
    if (ret != 0) {
        free_network_api_result_list(*result);
        *result = NULL;
        ERROR("do attach to network panes failed");
    }

    return ret;
}

int network_module_detach(const network_api_conf *conf, const char *type)
{
    const struct net_type *pnet = NULL;

    if (conf == NULL) {
        ERROR("Empty network config to attach");
        return -1;
    }

    pnet = get_net_by_type(type);
    if (pnet == NULL) {
        ERROR("Unsupport net type: %s", type);
        return -1;
    }

    return pnet->ops->detach(conf, NULL);
}

int network_module_check(const char *type)
{
    const struct net_type *pnet = NULL;

    pnet = get_net_by_type(type);
    if (pnet == NULL) {
        ERROR("Unsupport net type: %s", type);
        return -1;
    }

    return pnet->ops->check();
}

int network_module_update(const char *type)
{
    const struct net_type *pnet = NULL;

    pnet = get_net_by_type(type);
    if (pnet == NULL) {
        ERROR("Unsupport net type: %s", type);
        return -1;
    }

    return pnet->ops->update();
}

void network_module_exit()
{
    size_t i;

    for (i = 0; i < g_numnets; i++) {
        if (g_nets[i].ops->destroy == NULL) {
            continue;
        }
        g_nets[i].ops->destroy();
    }
}

void free_attach_net_conf(struct attach_net_conf *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free(ptr->name);
    ptr->name = NULL;
    free(ptr->interface);
    ptr->interface = NULL;
    free(ptr);
}

void free_network_api_conf(network_api_conf *conf)
{
    size_t i;

    if (conf == NULL) {
        return;
    }
    free(conf->name);
    conf->name = NULL;
    free(conf->ns);
    conf->ns = NULL;
    free(conf->pod_id);
    conf->pod_id = NULL;
    free(conf->netns_path);
    conf->netns_path = NULL;
    free(conf->default_interface);
    conf->default_interface = NULL;
    free_json_map_string_string(conf->args);
    conf->args = NULL;
    map_free(conf->annotations);
    conf->annotations = NULL;
    for (i = 0; i < conf->extral_nets_len; i++) {
        free_attach_net_conf(conf->extral_nets[i]);
    }
    free(conf->extral_nets);
    conf->extral_nets = NULL;
    conf->extral_nets_len = 0;

    free(conf);
}

void free_network_api_result(struct network_api_result *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->name);
    ptr->name = NULL;
    free(ptr->interface);
    ptr->interface = NULL;
    free(ptr->mac);
    ptr->mac = NULL;
    util_free_array_by_len(ptr->ips, ptr->ips_len);
    ptr->ips = NULL;
    ptr->ips_len = 0;
    free(ptr);
}

void free_network_api_result_list(network_api_result_list *ptr)
{
    size_t i;

    if (ptr == NULL) {
        return;
    }

    for (i = 0; i < ptr->len; i++) {
        free_network_api_result(ptr->items[i]);
        ptr->items[i] = NULL;
    }
    free(ptr->items);
    ptr->items = NULL;

    ptr->len = 0;
    ptr->cap = 0;
    free(ptr);
}
