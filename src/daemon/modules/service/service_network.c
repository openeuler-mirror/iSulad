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

#include <isula_libutils/cni_anno_port_mappings.h>

#include "utils_network.h"
#include "utils_port.h"
#include "network_api.h"
#include "err_msg.h"
#include "namespace.h"

bool validate_container_network(container_t *cont)
{
    bool ret = false;
    size_t i;

    if (cont == NULL) {
        ERROR("Invalid host config");
        return false;
    }

    container_lock(cont);

    if (!namespace_is_bridge(cont->hostconfig->network_mode)) {
        ret = true;
        goto out;
    }

    if (cont->hostconfig->bridge_network == NULL || cont->hostconfig->bridge_network_len == 0) {
        goto out;
    }

    if (!network_module_ready(NETWOKR_API_TYPE_NATIVE)) {
        isulad_set_error_message("No available native network");
        goto out;
    }

    for (i = 0; i < cont->hostconfig->bridge_network_len; i++) {
        if (!util_validate_network_name(cont->hostconfig->bridge_network[i])) {
            isulad_set_error_message("Invalid network name:%s", cont->hostconfig->bridge_network[i]);
            goto out;
        }

        if (strnlen(cont->hostconfig->bridge_network[i], MAX_NETWORK_NAME_LEN + 1) > MAX_NETWORK_NAME_LEN) {
            isulad_set_error_message("Network name %s too long, max length:%d", cont->hostconfig->bridge_network[i],
                                     MAX_NETWORK_NAME_LEN);
            goto out;
        }

        if (!network_module_exist(NETWOKR_API_TYPE_NATIVE, cont->hostconfig->bridge_network[i])) {
            isulad_set_error_message("Network %s not found", cont->hostconfig->bridge_network[i]);
            goto out;
        }
    }

    ret = true;

out:
    container_unlock(cont);
    return ret;
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

    ifname_table = get_ifname_table(cont->network_settings->networks);
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
    const defs_map_string_object_networks *networks = cont->network_settings->networks;

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
struct host_ports_validator {
    map_t *udp_ports;
    map_t *tcp_ports;
    map_t *stcp_ports;
};

/* memory store map kvfree */
static void valid_port_map_kvfree(void *key, void *value)
{
    free(key);

    map_free((map_t *)value);
}

static int do_parse_host_port_key(const char *key, char **proto, int *container_port)
{
    char **parts = NULL;
    int ret = 0;

    if (key == NULL) {
        ERROR("empty container port key");
        return -1;
    }
    parts = util_string_split(key, '/');
    if (parts == NULL || util_array_len((const char **)parts) != 2) {
        ERROR("invalid container port key: %s", key);
        ret = -1;
        goto out;
    }
    if (util_safe_int(parts[0], container_port) != 0) {
        ERROR("invalid container port key: %s", key);
        ret = -1;
        goto out;
    }
    *proto = parts[1];
    parts[1] = NULL;

out:
    util_free_array(parts);
    return ret;
}

static int get_random_port_with_retry()
{
#define  MAX_RETRY 15
    size_t j;
    int ret = -1;

    for (j = 0; j < MAX_RETRY; j++) {
        ret = util_get_random_port();
        if (ret > 0) {
            return ret;
        }
    }

    return -1;
}

static int do_append_host_port(const char *key, const char *host_ip, int host_port, struct host_ports_validator *valid,
                               cni_anno_port_mappings_container *result)
{
    const char *default_host_ip = "0.0.0.0";
    // string -> map_t<int, int>
    map_t *work = NULL;
    // int -> int
    map_t *tmp = NULL;
    char *proto = NULL;
    int container_port;
    int *found_port;
    cni_anno_port_mappings_element *elem = NULL;
    int ret = 0;

    // unset host port, get a useful port
    if (host_port == 0) {
        host_port = get_random_port_with_retry();
        DEBUG("get random port: %d", host_port);
    }

    if (!is_valid_port(host_port)) {
        ERROR("Invalid container port: %d", container_port);
        ret = -1;
        goto out;
    }

    if (do_parse_host_port_key(key, &proto, &container_port) != 0) {
        return -1;
    }

    if (!is_valid_port(container_port)) {
        ERROR("Invalid container port: %d", container_port);
        ret = -1;
        goto out;
    }

    if (proto == NULL || strcasecmp(proto, "udp") == 0) {
        work = valid->udp_ports;
    } else if (strcasecmp(proto, "tcp") == 0) {
        work = valid->tcp_ports;
    } else {
        work = valid->stcp_ports;
    }

    host_ip = host_ip != NULL ? host_ip : default_host_ip;

    tmp = map_search(work, (void *)host_ip);
    if (tmp == NULL) {
        tmp = map_new(MAP_INT_INT, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
        if (tmp == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        if (!map_replace(work, (void *)host_ip, (void *)tmp)) {
            ERROR("update host key: %s failed", host_ip);
            ret = -1;
            goto out;
        }
    }

    found_port = map_search(tmp, (void *)&host_port);
    if (found_port != NULL && *found_port == container_port) {
        ERROR("Conflicting port mapping container --> host: (%d --> %d)", container_port, host_port);
        ret = -1;
        goto out;
    }

    if (!map_replace(tmp, (void *)&host_port, (void *)&container_port)) {
        ERROR("update host port: %d --> %d failed", host_port, container_port);
        ret = -1;
        goto out;
    }

    elem = util_common_calloc_s(sizeof(cni_anno_port_mappings_element));
    if (elem == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    elem->host_ip = util_strdup_s(host_ip);
    elem->container_port = container_port;
    elem->host_port = host_port;
    elem->protocol = proto;
    proto = NULL;
    result->items[result->len] = elem;
    result->len += 1;

out:
    free(proto);
    return ret;
}

static int do_merge_portbindings(defs_map_string_object_port_bindings *port_bindings, map_t *port_set,
                                 struct host_ports_validator *valid, cni_anno_port_mappings_container *result)
{
    size_t i, j;
    bool flag = true;
    int host_port;

    for (i = 0; i < port_bindings->len; i++) {
        if (map_search(port_set, (void *)port_bindings->keys[i]) != NULL) {
            DEBUG("conflict container port mapping: %s, just ignore.", port_bindings->keys[i]);
            continue;
        }
        if (!map_replace(port_set, (void *)port_bindings->keys[i], (void *)&flag)) {
            ERROR("insert %s into port set failed", port_bindings->keys[i]);
            return -1;
        }
        for (j = 0; j < port_bindings->values[i]->element->host_len; j++) {
            network_port_binding_host_element *elem = port_bindings->values[i]->element->host[j];
            host_port = 0;
            if (util_valid_str(elem->host_port) && util_safe_int(elem->host_port, &host_port) != 0) {
                ERROR("invalid key: %s with host port: %s", port_bindings->keys[i], elem->host_port);
                return -1;
            }
            if (do_append_host_port(port_bindings->keys[i], elem->host_ip, host_port, valid, result) != 0) {
                return -1;
            }
        }
    }

    return 0;
}

static int do_merge_expose_ports(defs_map_string_object *exposed, map_t *port_set, struct host_ports_validator *valid,
                                 cni_anno_port_mappings_container *result)
{
    size_t i;
    bool flag = true;

    for (i = 0; i < exposed->len; i++) {
        if (map_search(port_set, (void *)exposed->keys[i]) != NULL) {
            WARN("port %s has set by port binding, just ignore.", exposed->keys[i]);
            continue;
        }
        if (!map_replace(port_set, (void *)exposed->keys[i], (void *)&flag)) {
            ERROR("Insert port: %s into set failed", exposed->keys[i]);
            return -1;
        }

        if (do_append_host_port(exposed->keys[i], NULL, 0, valid, result) != 0) {
            return -1;
        }
    }

    return 0;
}

// parse exposed_ports and portbindings to cni portmapping json
static int do_set_portmapping_for_setup(const host_config *hostconfig, const container_config *cont_spec,
                                        network_api_conf *config, cni_anno_port_mappings_container **merged_ports)
{
    struct host_ports_validator validate = { 0 };
    size_t i;
    cni_anno_port_mappings_container *cni_ports = NULL;
    size_t cni_ports_max_len = 0;
    // string --> bool
    map_t *port_set = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error jerr = NULL;
    char *cni_portmap_str = NULL;
    int ret = 0;

    // port bindings keys had merged into exposed ports, so just check it.
    if (cont_spec->exposed_ports == NULL || cont_spec->exposed_ports->len == 0) {
        return 0;
    }

    cni_ports = util_common_calloc_s(sizeof(cni_anno_port_mappings_container));
    if (cni_ports == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    cni_ports_max_len = cont_spec->exposed_ports->len;

    port_set = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (port_set == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    validate.udp_ports = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, valid_port_map_kvfree);
    if (validate.udp_ports == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    validate.tcp_ports = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, valid_port_map_kvfree);
    if (validate.tcp_ports == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    validate.stcp_ports = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, valid_port_map_kvfree);
    if (validate.stcp_ports == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (hostconfig->port_bindings != NULL) {
        for (i = 0; i < hostconfig->port_bindings->len; i++) {
            // port_bindings every key add to exposed ports, so we need decrease 1
            cni_ports_max_len += hostconfig->port_bindings->values[i]->element->host_len - 1;
        }
    }

    cni_ports->items = util_smart_calloc_s(sizeof(cni_anno_port_mappings_element *), cni_ports_max_len);
    if (cni_ports->items == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (hostconfig->port_bindings != NULL &&
        do_merge_portbindings(hostconfig->port_bindings, port_set, &validate, cni_ports) != 0) {
        ret = -1;
        goto out;
    }

    ret = do_merge_expose_ports(cont_spec->exposed_ports, port_set, &validate, cni_ports);
    if (ret != 0) {
        goto out;
    }

    cni_portmap_str = cni_anno_port_mappings_container_generate_json(cni_ports, &ctx, &jerr);
    if (cni_portmap_str == NULL) {
        ret = -1;
        ERROR("parse cni port mapping failed: %s", jerr);
        goto out;
    }
    DEBUG("get set portmapping: %s", cni_portmap_str);
    if (network_module_insert_portmapping(cni_portmap_str, config) != 0) {
        ret = -1;
        ERROR("set cni port mapping to network module failed");
        goto out;
    }

    *merged_ports = cni_ports;
    cni_ports = NULL;
out:
    map_free(port_set);
    map_free(validate.udp_ports);
    map_free(validate.tcp_ports);
    map_free(validate.stcp_ports);
    free(jerr);
    free(cni_portmap_str);
    free_cni_anno_port_mappings_container(cni_ports);
    return ret;
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
    int ret = 0;
    size_t i, old_size, new_size;
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

static inline void do_free_network_setting_cni_portmapping(container_network_settings *settings)
{
    size_t i;

    for (i = 0; i < settings->cni_ports_len; i++) {
        free_cni_inner_port_mapping(settings->cni_ports[i]);
        settings->cni_ports[i] = NULL;
    }
    free(settings->cni_ports);
    settings->cni_ports = NULL;
}

static int update_container_networks_portmappings(const cni_anno_port_mappings_container *merged_ports,
                                                  container_network_settings *settings)
{
    size_t i;
    cni_inner_port_mapping **tmp_ports = NULL;
    size_t tmp_ports_len = 0;
    int ret = 0;

    if (merged_ports == NULL || merged_ports->len == 0) {
        return 0;
    }

    tmp_ports = util_smart_calloc_s(sizeof(cni_inner_port_mapping *), merged_ports->len);
    if (tmp_ports == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    for (i = 0; i < merged_ports->len; i++) {
        tmp_ports[i] = util_common_calloc_s(sizeof(cni_inner_port_mapping));
        if (tmp_ports[i] == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        tmp_ports[i]->host_port = merged_ports->items[i]->host_port;
        tmp_ports[i]->container_port = merged_ports->items[i]->container_port;
        tmp_ports[i]->protocol = util_strdup_s(merged_ports->items[i]->protocol);
        tmp_ports[i]->host_ip = util_strdup_s(merged_ports->items[i]->host_ip);
        tmp_ports_len++;
    }

    do_free_network_setting_cni_portmapping(settings);

    settings->cni_ports = tmp_ports;
    tmp_ports = NULL;
    settings->cni_ports_len = tmp_ports_len;
    tmp_ports_len = 0;

out:
    for (i = 0; i < tmp_ports_len; i++) {
        free_cni_inner_port_mapping(tmp_ports[i]);
        tmp_ports[i] = NULL;
    }
    free(tmp_ports);
    return ret;
}

int setup_network(container_t *cont)
{
    int ret = 0;
    network_api_conf *config = NULL;
    network_api_result_list *result = NULL;
    cni_anno_port_mappings_container *merged_ports = NULL;

    if (cont == NULL) {
        ERROR("Invalid cont");
        return -1;
    }

    container_lock(cont);

    // set up network when network_mode is bridge
    if (!namespace_is_bridge(cont->hostconfig->network_mode)) {
        goto out;
    }

    if (cont->network_settings == NULL) {
        cont->network_settings = (container_network_settings *)util_common_calloc_s(sizeof(container_network_settings));
        if (cont->network_settings == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
    }

    if (cont->network_settings->networks != NULL && cont->network_settings->networks->len != 0) {
        WARN("Container %s already has networks", cont->common_config->id);
        goto out;
    }

    if (cont->network_settings->networks == NULL) {
        cont->network_settings->networks = (defs_map_string_object_networks *)util_common_calloc_s(sizeof(
                                                                                                       defs_map_string_object_networks));
        if (cont->network_settings->networks == NULL) {
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

    if (do_set_portmapping_for_setup(cont->hostconfig, cont->common_config != NULL ? cont->common_config->config : NULL,
                                     config, &merged_ports) != 0) {
        ret = -1;
        goto out;
    }

    ret = network_module_attach(config, NETWOKR_API_TYPE_NATIVE, &result);
    if (ret != 0) {
        ERROR("Failed to attach network");
        goto out;
    }

    ret = update_container_networks_info(result, cont->common_config->id, cont->network_settings->networks);
    if (ret != 0) {
        ERROR("Failed to update network setting");
        goto out;
    }

    ret = update_container_networks_portmappings(merged_ports, cont->network_settings);
    if (ret != 0) {
        ERROR("Failed to update network portmappings");
        goto out;
    }

    ret = container_network_settings_to_disk(cont);
    if (ret != 0) {
        ERROR("Failed to save container '%s' network settings", cont->common_config->id);
        goto out;
    }

out:
    free_cni_anno_port_mappings_container(merged_ports);
    free_network_api_conf(config);
    free_network_api_result_list(result);
    container_unlock(cont);
    return ret;
}

static int do_set_portmapping_for_teardown(const container_t *cont, network_api_conf *config)
{
    cni_anno_port_mappings_container *cni_ports = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error jerr = NULL;
    char *cni_portmap_str = NULL;
    size_t i;
    int ret = 0;

    if (cont->network_settings == NULL || cont->network_settings->cni_ports_len == 0) {
        return 0;
    }

    cni_ports = util_common_calloc_s(sizeof(cni_anno_port_mappings_container));
    cni_ports->items = util_smart_calloc_s(sizeof(cni_anno_port_mappings_container *),
                                           cont->network_settings->cni_ports_len);
    if (cni_ports->items == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < cont->network_settings->cni_ports_len; i++) {
        cni_ports->items[i] = util_common_calloc_s(sizeof(cni_anno_port_mappings_container));
        if (cni_ports->items[i] == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        cni_ports->items[i]->host_port = cont->network_settings->cni_ports[i]->host_port;
        cni_ports->items[i]->container_port = cont->network_settings->cni_ports[i]->container_port;
        cni_ports->items[i]->protocol = util_strdup_s(cont->network_settings->cni_ports[i]->protocol);
        cni_ports->items[i]->host_ip = util_strdup_s(cont->network_settings->cni_ports[i]->host_ip);
        cni_ports->len += 1;
    }

    cni_portmap_str = cni_anno_port_mappings_container_generate_json(cni_ports, &ctx, &jerr);
    if (cni_portmap_str == NULL) {
        ret = -1;
        ERROR("parse cni port mapping failed: %s", jerr);
        goto out;
    }
    DEBUG("get set portmapping: %s", cni_portmap_str);
    if (network_module_insert_portmapping(cni_portmap_str, config) != 0) {
        ret = -1;
        ERROR("set cni port mapping to network module failed");
        goto out;
    }

out:
    free(jerr);
    free(cni_portmap_str);
    free_cni_anno_port_mappings_container(cni_ports);
    return ret;
}

int teardown_network(container_t *cont)
{
    int ret = 0;
    network_api_conf *config = NULL;

    if (cont == NULL) {
        ERROR("Invalid cont");
        return -1;
    }

    container_lock(cont);

    // tear down network when network_mode is bridge
    if (!namespace_is_bridge(cont->hostconfig->network_mode)) {
        goto out;
    }

    if (cont->network_settings->networks == NULL || cont->network_settings->networks->len == 0) {
        WARN("Container %s doesn't have any network", cont->common_config->id);
        goto out;
    }

    config = build_adaptor_native_config(cont, prepare_detach_networks);
    if (config == NULL) {
        ERROR("Failed to build adaptor native config");
        ret = -1;
        goto out;
    }

    ret = do_set_portmapping_for_teardown(cont, config);
    if (ret != 0) {
        ERROR("Failed to set network port mappings");
        ret = -1;
        goto out;
    }

    ret = network_module_detach(config, NETWOKR_API_TYPE_NATIVE);
    if (ret != 0) {
        ERROR("Failed to detach network");
        goto out;
    }

out:
    free_defs_map_string_object_networks(cont->network_settings->networks);
    cont->network_settings->networks = NULL;

    // clear portmappings
    do_free_network_setting_cni_portmapping(cont->network_settings);

    if (container_network_settings_to_disk(cont) != 0) {
        ERROR("Failed to save container '%s' network settings", cont->common_config->id);
        ret = -1;
    }

    free_network_api_conf(config);

    container_unlock(cont);

    return ret;
}

bool network_store_container_list_add(container_t *cont)
{
    size_t i = 0;
    bool ret = true;
    const defs_map_string_object_networks *obj = NULL;

    if (cont->network_settings == NULL || cont->network_settings->networks == NULL ||
        cont->network_settings->networks->len == 0) {
        return true;
    }

    obj = cont->network_settings->networks;
    for (i = 0; i < obj->len; i++) {
        if (network_module_container_list_add(NETWOKR_API_TYPE_NATIVE, obj->keys[i], cont->common_config->id) != 0) {
            ERROR("Failed to add container %s to native network %s store", cont->common_config->id, obj->keys[i]);
            ret = false;
        }
    }

    return ret;
}
