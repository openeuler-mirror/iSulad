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

#include "network_tools.h"
#include "adaptor_cri.h"
#ifdef ENABLE_NATIVE_NETWORK
#include "adaptor_native.h"
#endif
#include "cni_operate.h"
#include "utils_string.h"
#include "utils_array.h"
#include "utils_network.h"
#include "utils.h"

#define DEFAULT_CNI_CONFIG_FILES_DIR "/etc/cni/net.d"
#define DEFAULT_CNI_BIN_FILES_DIR "/opt/cni/bin"


struct net_ops {
    int (*init)(const char *conf_dir, const char **bin_paths, const size_t bin_paths_len);

    // operators for network plane
    int (*attach)(const network_api_conf *conf, network_api_result_list *result);
    int (*check)(const network_api_conf *conf, network_api_result_list *result);
    int (*detach)(const network_api_conf *conf, network_api_result_list *result);

    // operators for network configs
    int (*conf_create)(const network_create_request *request, char **name, uint32_t *cc);
    int (*conf_inspect)(const char *name, char **network_json);
    int (*conf_list)(const struct filters_args *filters, network_network_info ***networks, size_t *networks_len);
    int (*conf_rm)(const char *name, char **res_name);

    bool (*ready)(void);
    int (*update)(void);

    bool (*exist)(const char *name);

    int (*add_cont)(const char *network_name, const char *cont_id);

    void (*destroy)(void);
};

struct net_type {
    const char *type;
    const struct net_ops *ops;
};

static const struct net_ops g_cri_ops = {
    .init = adaptor_cni_init_confs,
    .attach = adaptor_cni_setup,
    .check = adaptor_cni_check,
    .detach = adaptor_cni_teardown,
    .conf_create = NULL,
    .conf_inspect = NULL,
    .conf_list = NULL,
    .conf_rm = NULL,
    .ready = adaptor_cni_check_inited,
    .update = adaptor_cni_update_confs,
    .exist = NULL,
    .add_cont = NULL,
    .destroy = NULL,
};

#ifdef ENABLE_NATIVE_NETWORK
static const struct net_ops g_native_ops = {
    .init = native_init,
    .attach = native_attach_networks,
    .check = NULL,
    .detach = native_detach_networks,
    .conf_create = native_config_create,
    .conf_inspect = native_config_inspect,
    .conf_list = native_config_list,
    .conf_rm = native_config_remove,
    .ready = native_ready,
    .update = NULL,
    .exist = native_network_exist,
    .add_cont = native_network_add_container_list,
    .destroy = native_destory,
};
#endif

static const struct net_type g_nets[] = {
    {
        .type = NETWOKR_API_TYPE_CRI,
        .ops = &g_cri_ops,
    },
#ifdef ENABLE_NATIVE_NETWORK
    {
        .type = NETWOKR_API_TYPE_NATIVE,
        .ops = &g_native_ops,
    },
#endif
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
        if (g_nets[i].ops->init(use_conf_dir, (const char **)bin_paths, bin_paths_len) != 0) {
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

    if (conf == NULL) {
        ERROR("invalid argument");
        return -1;
    }

    if (conf->annotations == NULL) {
        conf->annotations = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);;
    }

    if (conf->annotations == NULL) {
        ERROR("Out of memory");
        return -1;
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
    return do_annotation_insert(CNI_ARGS_BANDWIDTH_KEY, val, conf);
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

    EVENT("Event: {Object: network, Type: attaching, Target: %s}", conf->pod_id);

    pnet = get_net_by_type(type);
    if (pnet == NULL || pnet->ops->attach == NULL) {
        ERROR("net type: %s unsupported attach", type);
        return -1;
    }

    if (conf->extral_nets_len > MAX_NETWORK_CONFIG_FILE_COUNT) {
        ERROR("Too large extral networks to attach");
        return -1;
    }
    *result = util_common_calloc_s(sizeof(network_api_result_list));
    if (*result == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    ret = pnet->ops->attach(conf, *result);
    if (ret != 0) {
        free_network_api_result_list(*result);
        *result = NULL;
        ERROR("do attach to network planes failed");
    }
    EVENT("Event: {Object: network, Type: attached, Target: %s}", conf->pod_id);

    return ret;
}

int network_module_check(const network_api_conf *conf, const char *type, network_api_result_list **result)
{
    const struct net_type *pnet = NULL;
    int ret = 0;

    if (conf == NULL || result == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    EVENT("Event: {Object: network, Type: checking, Target: %s}", conf->pod_id);

    pnet = get_net_by_type(type);
    if (pnet == NULL || pnet->ops->check == NULL) {
        ERROR("net type: %s unsupported check", type);
        return -1;
    }

    if (conf->extral_nets_len > MAX_NETWORK_CONFIG_FILE_COUNT) {
        ERROR("Too large extral networks to attach");
        return -1;
    }
    *result = util_common_calloc_s(sizeof(network_api_result_list));
    if (*result == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    ret = pnet->ops->check(conf, *result);
    if (ret != 0) {
        free_network_api_result_list(*result);
        *result = NULL;
        ERROR("do check to network panes failed");
    }
    EVENT("Event: {Object: network, Type: checked, Target: %s}", conf->pod_id);

    return ret;
}

int network_module_detach(const network_api_conf *conf, const char *type)
{
    const struct net_type *pnet = NULL;
    int ret = 0;

    if (conf == NULL) {
        ERROR("Empty network config to attach");
        return -1;
    }

    EVENT("Event: {Object: network, Type: detaching, Target: %s}", conf->pod_id);

    pnet = get_net_by_type(type);
    if (pnet == NULL || pnet->ops->detach == NULL) {
        ERROR("net type: %s, unsupported detach", type);
        return -1;
    }

    ret = pnet->ops->detach(conf, NULL);

    EVENT("Event: {Object: network, Type: detached, Target: %s}", conf->pod_id);
    return ret;
}

int network_module_conf_create(const char *type, const network_create_request *request, char **name, uint32_t *cc)
{
    const struct net_type *pnet = NULL;
    int ret = 0;

    if (request == NULL || name == NULL || cc == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    pnet = get_net_by_type(type);
    if (pnet == NULL || pnet->ops->conf_create == NULL) {
        ERROR("Type: %s net, unsupported config create", type);
        return -1;
    }

    ret = pnet->ops->conf_create(request, name, cc);

    return ret;
}

int network_module_conf_inspect(const char *type, const char *name, char **network_json)
{
    const struct net_type *pnet = NULL;
    int ret = 0;

    if (name == NULL || network_json == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    pnet = get_net_by_type(type);
    if (pnet == NULL || pnet->ops->conf_inspect == NULL) {
        ERROR("Type: %s net, unsupported config inspect", type);
        return -1;
    }

    ret = pnet->ops->conf_inspect(name, network_json);

    return ret;
}

int network_module_conf_list(const char *type, const struct filters_args *filters, network_network_info ***networks,
                             size_t *networks_len)
{
    const struct net_type *pnet = NULL;
    int ret = 0;

    if (networks == NULL || networks_len == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    pnet = get_net_by_type(type);
    if (pnet == NULL || pnet->ops->conf_list == NULL) {
        ERROR("Type: %s net, unsupported config list", type);
        return -1;
    }

    ret = pnet->ops->conf_list(filters, networks, networks_len);

    return ret;
}

int network_module_conf_rm(const char *type, const char *name, char **res_name)
{
    const struct net_type *pnet = NULL;
    int ret = 0;

    if (name == NULL || res_name == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    pnet = get_net_by_type(type);
    if (pnet == NULL || pnet->ops->conf_rm == NULL) {
        ERROR("Type: %s net, unsupported config remove", type);
        return -1;
    }

    ret = pnet->ops->conf_rm(name, res_name);

    return ret;
}

bool network_module_ready(const char *type)
{
    const struct net_type *pnet = NULL;

    pnet = get_net_by_type(type);
    if (pnet == NULL) {
        ERROR("Unsupported net type: %s", type);
        return -1;
    }

    return pnet->ops->ready();
}

int network_module_update(const char *type)
{
    const struct net_type *pnet = NULL;

    pnet = get_net_by_type(type);
    if (pnet == NULL) {
        ERROR("Unsupported net type: %s", type);
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
    util_free_array_by_len(ptr->gateway, ptr->ips_len);
    ptr->gateway = NULL;
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

static inline size_t get_list_scale_size(size_t old_size)
{
    if (old_size == 0) {
        return 1;
    }

    if (old_size << 1 > MAX_NETWORK_CONFIG_FILE_COUNT) {
        return MAX_NETWORK_CONFIG_FILE_COUNT;
    }

    return old_size << 1;
}

bool network_api_result_list_append(struct network_api_result *result, network_api_result_list *list)
{
    if (list == NULL) {
        ERROR("Invalid arguments");
        return false;
    }
    if (result == NULL) {
        WARN("Just ignore empty result");
        return true;
    }

    if (list->len < list->cap) {
        list->items[list->len] = result;
        list->len += 1;
        return true;
    }

    {
        DEBUG("result list is full, scale it");
        struct network_api_result **new_items = NULL;
        size_t new_size = get_list_scale_size(list->cap);
        if (list->len > new_size - 1) {
            ERROR("Overflow result list capability");
            return false;
        }

        // list capability less than MAX_NETWORK_CONFIG_FILE_COUNT(1024)
        // so we do not need to check Overflow:
        // new_size * sizeof(*new_items) and list->len * sizeof(*list->items)
        if (util_mem_realloc((void **)&new_items, new_size * sizeof(*new_items), (void *)list->items,
                             list->len * sizeof(*list->items)) != 0) {
            ERROR("Out of memory");
            return false;
        }
        list->items = new_items;
        list->cap = new_size;
        list->items[list->len] = result;
        list->len += 1;
    }

    return true;
}

struct network_api_result *network_parse_to_api_result(const char *name, const char *interface,
                                                       const struct cni_opt_result *cni_result)
{
    struct network_api_result *ret = NULL;

    if (cni_result == NULL) {
        return ret;
    }

    ret = util_common_calloc_s(sizeof(struct network_api_result));
    if (ret == NULL) {
        ERROR("Out of memory");
        return ret;
    }

    if (cni_result->ips_len > 0) {
        size_t i;
        ret->ips = util_smart_calloc_s(sizeof(char *), cni_result->ips_len);
        if (ret->ips == NULL) {
            ERROR("Out of memory");
            free_network_api_result(ret);
            ret = NULL;
            goto out;
        }
        ret->gateway = util_smart_calloc_s(sizeof(char *), cni_result->ips_len);
        if (ret->gateway == NULL) {
            ERROR("Out of memory");
            free_network_api_result(ret);
            ret = NULL;
            goto out;
        }
        for (i = 0; i < cni_result->ips_len; i++) {
            ret->ips[ret->ips_len] = util_ipnet_to_string(cni_result->ips[i]->address);
            if (ret->ips[ret->ips_len] == NULL) {
                WARN("ignore: parse cni result ip failed");
                continue;
            }
            ret->gateway[ret->ips_len] = util_ip_to_string(cni_result->ips[i]->gateway, cni_result->ips[i]->gateway_len);
            if (ret->gateway[ret->ips_len] == NULL) {
                WARN("ignore: parse cni result gateway failed");
                free(ret->ips[ret->ips_len]);
                ret->ips[ret->ips_len] = NULL;
                continue;
            }
            ret->ips_len += 1;
        }
    }

    ret->name = util_strdup_s(name);
    ret->interface = util_strdup_s(interface);
    if (cni_result->interfaces_len > 0) {
        size_t i;
        for (i = 0; i < cni_result->interfaces_len; i++) {
            if (strcmp(cni_result->interfaces[i]->name, interface) != 0) {
                continue;
            }
            ret->mac = util_strdup_s(cni_result->interfaces[i]->mac);
            break;
        }
        if (i == cni_result->interfaces_len) {
            WARN("Cannot find %s mac address", interface);
        }
    }

out:
    return ret;
}

int network_module_exist(const char *type, const char *name)
{
    const struct net_type *pnet = NULL;

    pnet = get_net_by_type(type);
    if (pnet == NULL || pnet->ops->exist == NULL) {
        ERROR("net type: %s, unsupported exist", type);
        return -1;
    }

    return pnet->ops->exist(name);
}

int network_module_container_list_add(const char *type, const char *network_name, const char *cont_id)
{
    const struct net_type *pnet = NULL;

    pnet = get_net_by_type(type);
    if (pnet == NULL || pnet->ops->add_cont == NULL) {
        ERROR("net type: %s, unsupported container list add", type);
        return -1;
    }

    return pnet->ops->add_cont(network_name, cont_id);
}

static int cni_parse_result(const struct network_api_result *item, char **key,
                            defs_map_string_object_networks_element **value)
{
    int ret = 0;
    char **split = NULL;
    char *tmp_key = NULL;
    defs_map_string_object_networks_element *tmp_value = NULL;

    tmp_value = (defs_map_string_object_networks_element *)util_common_calloc_s(sizeof(
                                                                                    defs_map_string_object_networks_element));
    if (tmp_value == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    tmp_key = util_strdup_s(item->name);
    tmp_value->if_name = util_strdup_s(item->interface);
    if (item->ips_len != 0) {
        split = util_string_split_multi(item->ips[0], '/');
        if (split == NULL) {
            ERROR("Failed to split result ip");
            ret = -1;
            goto out;
        }

        if (util_array_len((const char **)split) != 2) {
            ERROR("Invalid IP %s", item->ips[0]);
            ret = -1;
            goto out;
        }

        if (util_validate_ipv4_address(split[0])) {
            ret = util_safe_int(split[1], &tmp_value->ip_prefix_len);
            if (ret != 0) {
                ERROR("Failed to convert ip_prefix_len from string to int");
                goto out;
            }

            tmp_value->ip_address = util_strdup_s(split[0]);
            tmp_value->gateway = util_strdup_s(item->gateway[0]);
        } else if (util_validate_ipv6_address(split[0])) {
            ret = util_safe_int(split[1], &tmp_value->global_i_pv6prefix_len);
            if (ret != 0) {
                ERROR("Failed to convert ip_prefix_len from string to int");
                goto out;
            }

            tmp_value->global_i_pv6address = util_strdup_s(split[0]);
            tmp_value->i_pv6gateway = util_strdup_s(item->gateway[0]);
        }
    }
    tmp_value->mac_address = util_strdup_s(item->mac);

    *key = tmp_key;
    tmp_key = NULL;
    *value = tmp_value;
    tmp_value = NULL;

out:
    util_free_array(split);
    free(tmp_key);
    free_defs_map_string_object_networks_element(tmp_value);
    return ret;
}

int cni_update_container_networks_info(const network_api_result_list *result, const char *id, const char* netns_path,
                                       container_network_settings *network_settings)
{
    int ret = 0;
    size_t i, old_size, new_size;
    defs_map_string_object_networks *networks = network_settings->networks;
    const size_t len = networks->len;

    if (result == NULL || result->items == NULL || result->len == 0) {
        ERROR("Invalid result");
        return -1;
    }

    if (result->len > MAX_NETWORK_CONFIG_FILE_COUNT - len) {
        ERROR("Too many networks for container %s", id);
        return -1;
    }

    old_size = len * sizeof(char *);
    new_size = (len + result->len) * sizeof(char *);
    ret = util_mem_realloc((void **)&networks->keys, new_size, networks->keys, old_size);
    if (ret != 0) {
        ERROR("Out of memory");
        return -1;
    }

    old_size = len * sizeof(defs_map_string_object_networks_element *);
    new_size = (len + result->len) * sizeof(defs_map_string_object_networks_element *);
    ret = util_mem_realloc((void **)&networks->values, new_size, networks->values, old_size);
    if (ret != 0) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < result->len; i++) {
        char *key = NULL;
        defs_map_string_object_networks_element *value = NULL;

        if (result->items[i] == NULL) {
            continue;
        }

        ret = cni_parse_result(result->items[i], &key, &value);
        if (ret != 0) {
            ERROR("Failed to parse network result");
            goto out;
        }

        networks->keys[networks->len] = key;
        networks->values[networks->len] = value;
        (networks->len)++;
    }

    network_settings->sandbox_key = util_strdup_s(netns_path);

out:
    if (ret != 0) {
        for (i = len; i < networks->len; i++) {
            free(networks->keys[i]);
            networks->keys[i] = NULL;
            free_defs_map_string_object_networks_element(networks->values[i]);
            networks->values[i] = NULL;
        }
        networks->len = len;
    }
    return ret;
}