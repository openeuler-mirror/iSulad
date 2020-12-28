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
 * Create: 2020-12-30
 * Description: provide container supervisor functions
 ******************************************************************************/
#define _GNU_SOURCE

#include "service_network_api.h"

#include "utils_network.h"
#include "network_api.h"
#include "err_msg.h"
#include "namespace.h"

bool validate_container_network(const char *network_mode, const char **attach_networks, const size_t len)
{
    size_t i;

    if (!namespace_is_bridge(network_mode)) {
        return true;
    }

    if (attach_networks == NULL || len == 0) {
        return false;
    }

    if (!network_module_check(NETWOKR_API_TYPE_NATIVE)) {
        isulad_set_error_message("No available native network");
        return false;
    }

    for (i = 0; i < len; i++) {
        if (!util_validate_network_name(attach_networks[i])) {
            isulad_set_error_message("Invalid network name:%s", attach_networks[i]);
            return false;
        }

        if (strnlen(attach_networks[i], MAX_NETWORK_NAME_LEN + 1) > MAX_NETWORK_NAME_LEN) {
            isulad_set_error_message("Network name %s too long, max length:%d", attach_networks[i], MAX_NETWORK_NAME_LEN);
            return false;
        }

        if (!network_module_exist(NETWOKR_API_TYPE_NATIVE, attach_networks[i])) {
            isulad_set_error_message("Network %s not found", attach_networks[i]);
            return false;
        }
    }

    return true;
}

static char *get_netns_path(const char *id, const int pid)
{
    int nret = 0;
    char fullpath[PATH_MAX] = { 0 };
    const char *netns_fmt = "/proc/%d/ns/net";

    if (pid == 0) {
        ERROR("cannot find network namespace for the terminated container %s", id);
        return NULL;
    }

    nret = snprintf(fullpath, sizeof(fullpath), netns_fmt, pid);
    if ((size_t)nret >= sizeof(fullpath) || nret < 0) {
        ERROR("Sprint nspath failed");
        return NULL;
    }

    return util_strdup_s(fullpath);
}

static map_t *get_ifname_table(const defs_map_string_object_networks *networks)
{
    // string -> bool
    map_t *ifname_table = NULL;
    size_t i;
    bool val = true;

    ifname_table = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (ifname_table == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (networks == NULL || networks->len == 0) {
        return ifname_table;
    }

    for (i = 0; i < networks->len; i++) {
        if (networks->keys[i] == NULL || networks->values[i] == NULL || networks->values[i]->if_name == NULL) {
            WARN("network %s doesn't have if_name", networks->keys[i] != NULL ? networks->keys[i] : " ");
            continue;
        }

        if (map_search(ifname_table, networks->values[i]->if_name) != NULL) {
            ERROR("ifname %s conflict", networks->values[i]->if_name);
            goto err_out;
        }

        if (!map_replace(ifname_table, (void *)networks->values[i]->if_name, (void *)&val)) {
            ERROR("Failed to insert %s in ifname_table", networks->values[i]->if_name);
            goto err_out;
        }
    }

    return ifname_table;

err_out:
    map_free(ifname_table);
    return NULL;
}

static char *find_ifname(map_t *ifname_table)
{
#define IFNAME_MAX 10000
    int i;
    int nret = 0;
    char fullname[PATH_MAX] = { 0 };
    const char *ifname_fmt = "eth%d";
    bool val = true;

    for (i = 0; i < IFNAME_MAX; i++) {
        nret = snprintf(fullname, sizeof(fullname), ifname_fmt, i);
        if ((size_t)nret >= sizeof(fullname) || nret < 0) {
            ERROR("Sprint nspath failed");
            return NULL;
        }

        if (map_search(ifname_table, fullname) != NULL) {
            continue;
        }

        if (!map_replace(ifname_table, (void *)fullname, (void *)&val)) {
            ERROR("Failed to insert %s in ifname_table", fullname);
            return NULL;
        }

        return util_strdup_s(fullname);
    }

    isulad_set_error_message("Failed to find available ifname");
    ERROR("Failed to find available ifname");
    return NULL;
}

struct attach_net_conf_list {
    struct attach_net_conf **nets;
    size_t len;
};

typedef struct attach_net_conf_list *(*prepare_networks_t)(const container_t *cont);
static struct attach_net_conf_list *prepare_attach_networks(const container_t *cont)
{
    int nret = 0;
    size_t i;
    struct attach_net_conf_list *list = NULL;
    map_t *ifname_table = NULL;
    const char **attach_networks = (const char **)cont->hostconfig->bridge_network;
    const size_t networks_len = cont->hostconfig->bridge_network_len;

    if (attach_networks == NULL || networks_len == 0) {
        ERROR("attach network is none");
        return NULL;
    }

    list = (struct attach_net_conf_list *)util_common_calloc_s(sizeof(struct attach_net_conf));
    if (list == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    list->nets = (struct attach_net_conf **)util_smart_calloc_s(sizeof(struct attach_net_conf *), networks_len);
    if (list->nets == NULL) {
        ERROR("Out of memory");
        nret = -1;
        goto out;
    }

    ifname_table = get_ifname_table(cont->common_config->network_settings->networks);
    if (ifname_table == NULL) {
        ERROR("Get ifname table failed");
        nret = -1;
        goto out;
    }

    for (i = 0; i < networks_len; i++) {
        list->nets[i] = (struct attach_net_conf *)util_common_calloc_s(sizeof(struct attach_net_conf));
        if (list->nets[i] == NULL) {
            ERROR("Out of memory");
            nret = -1;
            goto out;
        }

        list->len++;
        list->nets[i]->name = util_strdup_s(attach_networks[i]);
        list->nets[i]->interface = find_ifname(ifname_table);
        if (list->nets[i]->interface == NULL) {
            ERROR("Failed to find ifname");
            nret = -1;
            goto out;
        }
    }

out:
    if (nret != 0) {
        for (i = 0; i < list->len; i++) {
            free_attach_net_conf(list->nets[i]);
        }
        free(list->nets);
        free(list);
        list = NULL;
    }
    map_free(ifname_table);

    return list;
}

static struct attach_net_conf_list *prepare_detach_networks(const container_t *cont)
{
    int nret = 0;
    size_t i;
    struct attach_net_conf_list *list = NULL;
    const defs_map_string_object_networks *networks = cont->common_config->network_settings->networks;

    list = (struct attach_net_conf_list *)util_common_calloc_s(sizeof(struct attach_net_conf));
    if (list == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    list->nets = (struct attach_net_conf **)util_smart_calloc_s(sizeof(struct attach_net_conf *), networks->len);
    if (list->nets == NULL) {
        ERROR("Out of memory");
        nret = -1;
        goto out;
    }

    for (i = 0; i < networks->len; i++) {
        list->nets[i] = (struct attach_net_conf *)util_common_calloc_s(sizeof(struct attach_net_conf));
        if (list->nets[i] == NULL) {
            ERROR("Out of memory");
            nret = -1;
            goto out;
        }

        list->len++;
        list->nets[i]->name = util_strdup_s(networks->keys[i]);
        list->nets[i]->interface = util_strdup_s(networks->values[i]->if_name);
    }

out:
    if (nret != 0) {
        for (i = 0; i < list->len; i++) {
            free_attach_net_conf(list->nets[i]);
        }
        free(list->nets);
        free(list);
        list = NULL;
    }

    return list;
}

static json_map_string_string * prepare_native_args(const container_t *cont)
{
    json_map_string_string *args = NULL;

    args = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if (args == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (append_json_map_string_string(args, "IgnoreUnknown", "1") != 0) {
        ERROR("Append args tmp failed");
        goto err_out;
    }

    if (append_json_map_string_string(args, "K8S_POD_NAMESPACE", cont->common_config->name) != 0) {
        ERROR("Append args tmp failed");
        goto err_out;
    }

    if (append_json_map_string_string(args, "K8S_POD_NAME", cont->common_config->name) != 0) {
        ERROR("Append args tmp failed");
        goto err_out;
    }

    if (append_json_map_string_string(args, "K8S_POD_INFRA_CONTAINER_ID", cont->common_config->id) != 0) {
        ERROR("Append args tmp failed");
        goto err_out;
    }

    if (cont->hostconfig->ip != NULL && append_json_map_string_string(args, "IP", cont->hostconfig->ip) != 0) {
        ERROR("Append args tmp failed");
        goto err_out;
    }

    if (cont->hostconfig->mac_address != NULL &&
        append_json_map_string_string(args, "MAC", cont->hostconfig->mac_address) != 0) {
        ERROR("Append args tmp failed");
        goto err_out;
    }

    return args;

err_out:
    free_json_map_string_string(args);
    return NULL;
}

static network_api_conf *build_adaptor_native_config(const container_t *cont, prepare_networks_t op)
{
    network_api_conf *config = NULL;
    struct attach_net_conf_list *list = NULL;

    config = util_common_calloc_s(sizeof(network_api_conf));
    if (config == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    config->name = util_strdup_s(cont->common_config->name);
    config->pod_id = util_strdup_s(cont->common_config->id);
    config->netns_path = get_netns_path(cont->common_config->id, cont->state->state->pid);
    if (config->netns_path == NULL) {
        ERROR("Failed to get netns path for container %s", cont->common_config->id);
        goto err_out;
    }

    list = op(cont);
    if (list == NULL) {
        ERROR("Failed to prepare attach/detach networks");
        goto err_out;
    }

    config->extral_nets = list->nets;
    config->extral_nets_len = list->len;
    list->nets = NULL;
    free(list);

    config->args = prepare_native_args(cont);
    if (config->args == NULL) {
        ERROR("Failed to prepare native args");
        goto err_out;
    }

    // TODO: support set portmapping
    config->annotations = NULL;

    return config;

err_out:
    free_network_api_conf(config);
    return NULL;
}

static int parse_result(const struct network_api_result *item, char **key,
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

        tmp_value->ip_address = util_strdup_s(split[0]);
        ret = util_safe_int(split[1], &tmp_value->ip_prefix_len);
        if (ret != 0) {
            ERROR("Failed to convert ip_prefix_len from string to int");
            goto out;
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

static int update_container_networks_info(const network_api_result_list *result, const char *id,
                                          defs_map_string_object_networks *networks)
{
#define MAX_NETWORKS 200
    int ret = 0;
    size_t i, old_size, new_size;
    const size_t len = networks->len;

    if (result == NULL || result->items == NULL || result->len == 0) {
        ERROR("Invalid result");
        return -1;
    }

    if (result->len > MAX_NETWORKS - len) {
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

        ret = parse_result(result->items[i], &key, &value);
        if (ret != 0) {
            ERROR("Failed to parse network result");
            goto out;
        }

        networks->keys[networks->len] = key;
        networks->values[networks->len] = value;
        (networks->len)++;
    }

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

int setup_network(container_t *cont)
{
    int ret = 0;
    network_api_conf *config = NULL;
    network_api_result_list *result = NULL;

    // set up network when network_mode is bridge
    if (!namespace_is_bridge(cont->hostconfig->network_mode)) {
        return 0;
    }

    if (cont->common_config->network_settings == NULL) {
        cont->common_config->network_settings = (container_network_settings *)util_common_calloc_s(sizeof(
                                                                                                       container_network_settings));
        if (cont->common_config->network_settings == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
    }

    if (cont->common_config->network_settings->networks == NULL) {
        cont->common_config->network_settings->networks = (defs_map_string_object_networks *)util_common_calloc_s(sizeof(
                                                                                                                      defs_map_string_object_networks));
        if (cont->common_config->network_settings->networks == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
    }

    config = build_adaptor_native_config(cont, prepare_attach_networks);
    if (config == NULL) {
        ERROR("Failed to build adaptor native config");
        ret = -1;
        goto out;
    }

    ret = network_module_attach(config, NETWOKR_API_TYPE_NATIVE, &result);
    if (ret != 0) {
        ERROR("Failed to attach network");
        goto out;
    }

    container_lock(cont);

    ret = update_container_networks_info(result, cont->common_config->id, cont->common_config->network_settings->networks);
    if (ret != 0) {
        ERROR("Failed to update network setting");
        goto unlock_out;
    }

    ret = container_to_disk(cont);
    if (ret != 0) {
        ERROR("Failed to save container '%s'", cont->common_config->id);
        goto unlock_out;
    }

unlock_out:
    container_unlock(cont);

out:
    free_network_api_conf(config);
    free_network_api_result_list(result);
    return ret;
}

int teardown_network(container_t *cont)
{
    int ret = 0;
    network_api_conf *config = NULL;

    // tear down network when network_mode is bridge
    if (!namespace_is_bridge(cont->hostconfig->network_mode)) {
        return 0;
    }

    if (cont->common_config->network_settings == NULL || cont->common_config->network_settings->networks == NULL ||
        cont->common_config->network_settings->networks->len == 0) {
        WARN("Container %s doesn't have any network", cont->common_config->id);
        return 0;
    }

    config = build_adaptor_native_config(cont, prepare_detach_networks);
    if (config == NULL) {
        ERROR("Failed to build adaptor native config");
        ret = -1;
        goto out;
    }

    ret = network_module_detach(config, NETWOKR_API_TYPE_NATIVE);
    if (ret != 0) {
        ERROR("Failed to detach network");
        goto out;
    }

out:
    container_lock(cont);

    free_defs_map_string_object_networks(cont->common_config->network_settings->networks);
    cont->common_config->network_settings->networks = NULL;

    if (container_to_disk(cont) != 0) {
        ERROR("Failed to save container '%s'", cont->common_config->id);
        ret = -1;
    }

    container_unlock(cont);

    free_network_api_conf(config);
    return ret;
}
