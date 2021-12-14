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

#include <unistd.h>
#include <isula_libutils/cni_anno_port_mappings.h>

#include "network_namespace_api.h"
#include "utils_network.h"
#include "utils_port.h"
#include "err_msg.h"
#include "namespace.h"
#include "path.h"

#define SHORT_ID_SPACE 12 + 1

static bool validate_network(const defs_map_string_object_networks *networks)
{
    size_t i = 0;

    if (networks == NULL || networks->len == 0 || networks->keys == NULL || networks->values == NULL) {
        return false;
    }

    for (i = 0; i < networks->len; i++) {
        if (!util_validate_network_name(networks->keys[i])) {
            isulad_set_error_message("Invalid network name %s", networks->keys[i]);
            ERROR("Invalid network name %s", networks->keys[i]);
            return false;
        }

        if (!network_module_exist(NETWOKR_API_TYPE_NATIVE, networks->keys[i])) {
            isulad_set_error_message("Network %s not found", networks->keys[i]);
            ERROR("Network %s not found", networks->keys[i]);
            return false;
        }
    }

    return true;
}

struct attach_net_conf_list {
    struct attach_net_conf **nets;
    size_t len;
};

static struct attach_net_conf_list *build_attach_networks(const defs_map_string_object_networks *networks)
{
    int nret = 0;
    size_t i = 0;
    struct attach_net_conf_list *list = NULL;

    if (networks == NULL || networks->len == 0) {
        ERROR("attach network is none");
        return NULL;
    }

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
        if (networks->keys[i] == NULL || networks->values[i] == NULL || networks->values[i]->if_name == NULL) {
            ERROR("Invalid network");
            nret = -1;
            goto out;
        }

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
#define HOST_NAME_MAX_LENGTH 63
    int nret = 0;
    char name[HOST_NAME_MAX_LENGTH + 1] = { 0x00 };
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

    if (strlen(cont->common_config->name) > HOST_NAME_MAX_LENGTH) {
        // set short id as host name
        nret = snprintf(name, SHORT_ID_SPACE, "%s", cont->common_config->id);
        if (nret < 0) {
            ERROR("snprintf name failed, %d", nret);
            goto err_out;
        }
    } else {
        nret = snprintf(name, sizeof(name), "%s", cont->common_config->name);
        if (nret < 0 || (size_t)nret >= sizeof(name)) {
            ERROR("snprintf name failed");
            goto err_out;
        }
    }

    if (append_json_map_string_string(args, "K8S_POD_NAMESPACE", name) != 0) {
        ERROR("Append args tmp failed");
        goto err_out;
    }

    if (append_json_map_string_string(args, "K8S_POD_NAME", name) != 0) {
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
    const char *use_host_ip = NULL;
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

    use_host_ip = host_ip != NULL ? host_ip : default_host_ip;

    tmp = map_search(work, (void *)use_host_ip);
    if (tmp == NULL) {
        tmp = map_new(MAP_INT_INT, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
        if (tmp == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        if (!map_replace(work, (void *)use_host_ip, (void *)tmp)) {
            ERROR("update host key: %s failed", use_host_ip);
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
            if (!util_check_port_free(host_port)) {
                isulad_append_error_message("port '%d' already in use", host_port);
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

static network_api_conf *build_adaptor_native_config(const container_t *cont, const bool attach)
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
    config->netns_path = get_netns_path(cont->network_settings->sandbox_key, attach);
    if (config->netns_path == NULL) {
        ERROR("Failed to get netns path for container %s", cont->common_config->id);
        goto err_out;
    }


    list = build_attach_networks(cont->network_settings->networks);
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

static container_network_settings *dup_contaner_network_settings(const container_network_settings *settings)
{
    char *jstr = NULL;
    container_network_settings *res = NULL;
    parser_error jerr = NULL;

    if (settings == NULL) {
        return NULL;
    }

    jstr = container_network_settings_generate_json(settings, NULL, &jerr);
    if (jstr == NULL) {
        ERROR("Generate network settings failed: %s", jerr);
        goto out;
    }

    free(jerr);
    jerr = NULL;
    res = container_network_settings_parse_data(jstr, NULL, &jerr);
    if (res == NULL) {
        ERROR("Parse network settings failed: %s", jerr);
        goto out;
    }

out:
    free(jerr);
    free(jstr);
    return res;
}

static map_t *get_networks_index_map(const defs_map_string_object_networks *networks)
{
    size_t i = 0;
    map_t *index = NULL;

    index = map_new(MAP_STR_INT, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (index == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (i = 0; i < networks->len; i++) {
        if (networks->keys[i] == NULL) {
            ERROR("Invalid network");
            goto err_out;
        }

        if (map_search(index, networks->keys[i]) != NULL) {
            ERROR("network name %s conflict", networks->keys[i]);
            goto err_out;
        }

        if (!map_replace(index, (void *)networks->keys[i], (void *)&i)) {
            ERROR("Failed to insert ip address %s in map", networks->keys[i]);
            goto err_out;
        }
    }

    return index;

err_out:
    map_free(index);
    return NULL;
}

static int fill_container_network_element(const struct network_api_result *item,
                                          defs_map_string_object_networks_element *value)
{
    int ret = 0;
    char **split = NULL;

    if (item->ips_len == 0) {
        ERROR("No ips for attach network %s", item->name);
        return -1;
    }

    // now only allocate one ip per network
    split = util_string_split_multi(item->ips[0], '/');
    if (split == NULL) {
        ERROR("Failed to split result ip");
        return -1;
    }

    if (util_array_len((const char **)split) != 2) {
        ERROR("Invalid IP %s", item->ips[0]);
        ret = -1;
        goto out;
    }

    if (util_validate_ipv4_address(split[0])) {
        ret = util_safe_int(split[1], &value->ip_prefix_len);
        if (ret != 0) {
            ERROR("Failed to convert ip_prefix_len from string to int");
            goto out;
        }

        value->ip_address = util_strdup_s(split[0]);
        value->gateway = util_strdup_s(item->gateway[0]);
    } else if (util_validate_ipv6_address(split[0])) {
        ret = util_safe_int(split[1], &value->global_i_pv6prefix_len);
        if (ret != 0) {
            ERROR("Failed to convert ip_prefix_len from string to int");
            goto out;
        }

        value->global_i_pv6address = util_strdup_s(split[0]);
        value->i_pv6gateway = util_strdup_s(item->gateway[0]);
    }

    value->mac_address = util_strdup_s(item->mac);

out:
    util_free_array(split);
    return ret;
}

static int update_container_networks_info(const network_api_result_list *result,
                                          defs_map_string_object_networks *networks)
{
    int ret = 0;
    size_t i = 0;
    map_t *index = NULL;

    if (result == NULL || result->items == NULL || result->len == 0) {
        ERROR("Invalid result");
        return -1;
    }

    if (result->len != networks->len) {
        ERROR("result len %lu doesn't match networks len %lu", result->len, networks->len);
        return -1;
    }

    index = get_networks_index_map(networks);
    if (index == NULL) {
        ERROR("Failed to get networks index map");
        return -1;
    }

    for (i = 0; i < result->len; i++) {
        int *j = NULL;

        if (result->items[i] == NULL) {
            ERROR("Invalid result item");
            ret = -1;
            goto out;
        }

        j = map_search(index, result->items[i]->name);
        if (j == NULL) {
            ERROR("Failed to find network %s", result->items[i]->name);
            ret = -1;
            goto out;
        }

        ret = fill_container_network_element(result->items[i], networks->values[*j]);
        if (ret != 0) {
            ERROR("Failed to fill container network element for %s", result->items[i]->name);
            goto out;
        }
    }

out:
    // rollback cont->networksettings->networks by caller
    map_free(index);
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

    settings->cni_ports_len = 0;
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
    // rollback cont->networksettings->networks by caller
    for (i = 0; i < tmp_ports_len; i++) {
        free_cni_inner_port_mapping(tmp_ports[i]);
        tmp_ports[i] = NULL;
    }
    free(tmp_ports);
    return ret;
}

typedef int (*append_content_callback_t)(const char *hostname, defs_map_string_object_networks_element *values,
                                         string_array *array);

static int append_hosts_content(const char *hostname, defs_map_string_object_networks_element *value,
                                string_array *hosts)
{
    int ret = 0;
    int nret = 0;
    size_t size = 0;
    char *tmp_str = NULL;
    const char *ip_address = value->ip_address ? value->ip_address : value->global_i_pv6address;

    if (ip_address == NULL) {
        ERROR("Invalid ip address");
        return -1;
    }

    size = strlen(ip_address) + 1 + strlen(hostname) + 1;
    tmp_str = util_common_calloc_s(size);
    if (tmp_str == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    nret = snprintf(tmp_str, size, "%s %s", ip_address, hostname);
    if (nret < 0 || (size_t)nret >= size) {
        ERROR("snprintf hosts failed");
        ret = -1;
        goto out;
    }

    ret = util_append_string_array(hosts, tmp_str);
    if (ret != 0) {
        ERROR("Failed to append hosts string array");;
        goto out;
    }

out:
    free(tmp_str);
    return ret;
}

static int append_dns_content(const char *hostname, defs_map_string_object_networks_element *value, string_array *dns)
{
    int ret = 0;
    int nret = 0;
    size_t size = 0;
    char *tmp_str = NULL;
    const char *gateway = value->gateway ? value->gateway : value->i_pv6gateway;

    if (gateway == NULL) {
        ERROR("Invalid gateway");
        return -1;
    }

    size = strlen("nameserver") + 1 + strlen(gateway) + 1;
    tmp_str = util_common_calloc_s(size);
    if (tmp_str == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    nret = snprintf(tmp_str, size, "nameserver %s", gateway);
    if (nret < 0 || (size_t)nret >= size) {
        ERROR("snprintf dns failed");
        ret = -1;
        goto out;
    }

    ret = util_append_string_array(dns, tmp_str);
    if (ret != 0) {
        ERROR("Failed to append dns string array");
        goto out;
    }

out:
    free(tmp_str);
    return ret;
}

static int do_update_internal_file(const char *id, const char *file_path,
                                   const defs_map_string_object_networks *networks,
                                   const append_content_callback_t op)
{
    int ret = 0;
    int nret = 0;
    size_t i = 0;
    char *str = NULL;
    char *content = NULL;
    char *tmp_content = NULL;
    string_array *array = NULL;
    char hostname[MAX_HOST_NAME_LEN] = { 0x00 };

    array = (string_array *)util_common_calloc_s(sizeof(string_array));
    if (array == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    nret = snprintf(hostname, SHORT_ID_SPACE, "%s", id);
    if (nret < 0) {
        ERROR("snprintf hostname failed, %d", nret);
        ret = -1;
        goto out;
    }

    if (!util_file_exists(file_path)) {
        ERROR("container %s file %s not exist", id, file_path);
    } else {
        content = util_read_text_file(file_path);
        if (content == NULL) {
            ERROR("read content from file %s failed", file_path);
            isulad_set_error_message("read content from file %s failed", file_path);
            ret = -1;
            goto out;
        }
    }

    for (i = 0; i < networks->len; i++) {
        ret = op(hostname, networks->values[i], array);
        if (ret != 0) {
            ERROR("Failed to op networks");
            goto out;
        }
    }

    str = util_string_join("\n", (const char **)array->items, array->len);
    if (str == NULL) {
        ERROR("Failed to join array string");
        ret = -1;
        goto out;
    }

    tmp_content = util_string_append(str, content);
    free(content);
    content = tmp_content;

    tmp_content = util_string_append("\n", content);
    free(content);
    content = tmp_content;

    ret = util_write_file(file_path, content, strlen(content), NETWORK_MOUNT_FILE_MODE);
    if (ret == 0) {
        goto out;
    }

    if (errno == EROFS) {
        // open in read only file system
        WARN("failed to write file %s in readonly file system", file_path);
        ret = 0;
    } else {
        ERROR("Failed to write file %s: %s", file_path, strerror(errno));
        isulad_set_error_message("Failed to write file %s: %s", file_path, strerror(errno));
        ret = -1;
    }

out:
    free(str);
    free(content);
    util_free_string_array(array);
    return ret;
}

static int drop_internal_file(const container_t *cont);

static int update_internal_file(const container_t *cont)
{
    if (cont->network_settings == NULL || cont->network_settings->networks == NULL ||
        cont->network_settings->networks->len == 0) {
        return 0;
    }

    if (do_update_internal_file(cont->common_config->id, cont->common_config->hosts_path, cont->network_settings->networks,
                                append_hosts_content) != 0) {
        ERROR("Failed to update hosts");
        return -1;
    }

    if (do_update_internal_file(cont->common_config->id, cont->common_config->resolv_conf_path,
                                cont->network_settings->networks, append_dns_content) != 0) {
        ERROR("Failed to update resolv.conf");
        (void)drop_internal_file(cont);
        return -1;
    }

    return 0;
}

static map_t *get_ip_map(const defs_map_string_object_networks *networks)
{
    size_t i = 0;
    bool val = true;
    // string -> bool
    map_t *ip_map = NULL;

    ip_map = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (ip_map == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (i = 0; i < networks->len; i++) {
        char *ip_address = NULL;

        if (networks->keys[i] == NULL || networks->values[i] == NULL) {
            WARN("Network key/value is null");
            continue;
        }

        ip_address = networks->values[i]->ip_address ? networks->values[i]->ip_address :
                     networks->values[i]->global_i_pv6address;
        if (ip_address == NULL) {
            WARN("network %s doesn't have ip address", networks->keys[i]);
            continue;
        }

        if (map_search(ip_map, ip_address) != NULL) {
            ERROR("ip address %s conflict", ip_address);
            goto err_out;
        }

        if (!map_replace(ip_map, (void *)ip_address, (void *)&val)) {
            ERROR("Failed to insert ip address %s in map", ip_address);
            goto err_out;
        }
    }

    return ip_map;

err_out:
    map_free(ip_map);
    return NULL;
}

static map_t *get_gateway_map(const defs_map_string_object_networks *networks)
{
    size_t i = 0;
    bool val = true;
    // string -> bool
    map_t *gateway_map = NULL;

    gateway_map = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (gateway_map == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (i = 0; i < networks->len; i++) {
        char *gateway = NULL;

        if (networks->keys[i] == NULL || networks->values[i] == NULL) {
            WARN("Network key/value is null");
            continue;
        }

        gateway = networks->values[i]->gateway ? networks->values[i]->gateway :  networks->values[i]->i_pv6gateway;
        if (gateway == NULL) {
            WARN("network %s doesn't have gateway", networks->keys[i]);
            continue;
        }

        if (map_search(gateway_map, gateway) != NULL) {
            ERROR("ip address %s conflict", gateway);
            goto err_out;
        }

        if (!map_replace(gateway_map, (void *)gateway, (void *)&val)) {
            ERROR("Failed to insert ip address %s in map", gateway);
            goto err_out;
        }
    }

    return gateway_map;

err_out:
    map_free(gateway_map);
    return NULL;
}

typedef bool (*checker_callback_t)(const char *hostname, const map_t *ip_map, const char **hosts);

bool hosts_checker(const char *hostname, const map_t *ip_map, const char **hosts)
{
    return strcmp(hostname, hosts[1]) == 0 && map_search(ip_map, (void *)hosts[0]) != NULL;
}

bool dns_checker(const char *hostname, const map_t *gateway_map, const char **dns)
{
    return strcmp("nameserver", dns[0]) == 0 && map_search(gateway_map, (void *)dns[1]) != NULL;
}

static int drop_file_content(const char *line, const char *hostname, const map_t *map, string_array *array,
                             const checker_callback_t checker)
{
    int ret = 0;
    char *tmp_line = NULL;
    char **splits = NULL;

    tmp_line = util_strdup_s(line);
    util_trim_newline(tmp_line);
    tmp_line = util_trim_space(tmp_line);

    if (tmp_line[0] == '#') {
        goto append_out;
    }

    splits = util_string_split(tmp_line, ' ');
    if (splits == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (util_array_len((const char **)splits) < 2) {
        goto append_out;
    }

    if (checker(hostname, map, (const char **)splits)) {
        goto out;
    }

append_out:
    ret = util_append_string_array(array, line);
    if (ret != 0) {
        ERROR("Failed to append string array");
    }

out:
    free(tmp_line);
    util_free_array(splits);
    return ret;
}

static int do_drop_internal_file(const char *id, const char *file_path, const defs_map_string_object_networks *networks,
                                 const map_t *map, const checker_callback_t checker)
{
    int ret = 0;
    int nret = 0;
    char *str = NULL;
    FILE *fp = NULL;
    size_t length = 0;
    char *pline = NULL;
    char hostname[MAX_HOST_NAME_LEN] = { 0x00 };
    string_array *array = NULL;

    if (!util_file_exists(file_path)) {
        ERROR("container %s file %s not exist", id, file_path);
        isulad_set_error_message("container %s file %s not exist", id, file_path);
        return -1;
    }

    nret = snprintf(hostname, SHORT_ID_SPACE, "%s", id);
    if (nret < 0) {
        ERROR("snprintf hostname failed, %d", nret);
        return -1;
    }

    array = (string_array *)util_common_calloc_s(sizeof(string_array));
    if (array == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    fp = util_fopen(file_path, "a+");
    if (fp == NULL) {
        if (errno == EROFS) {
            WARN("failed to open file %s in readonly file system", file_path);
            goto out;
        } else {
            ERROR("Failed to open %s: %s", file_path, strerror(errno));
            isulad_set_error_message("Failed to open %s: %s", file_path, strerror(errno));
            ret = -1;
            goto out;
        }
    }

    while (getline(&pline, &length, fp) != -1) {
        if (pline == NULL) {
            ERROR("get %s content failed", file_path);
            ret = -1;
            goto out;
        }
        ret = drop_file_content(pline, hostname, map, array, checker);
        if (ret != 0) {
            ERROR("Failed to drop file content");
            goto out;
        }
    }

    if (array->items == NULL || array->len == 0) {
        str = util_strdup_s("#\n");
    } else {
        str = util_string_join("", (const char **)array->items, array->len);
        if (str == NULL) {
            ERROR("Failed to join array string");
            ret = -1;
            goto out;
        }
    }

    ret = util_write_file(file_path, str, strlen(str), NETWORK_MOUNT_FILE_MODE);
    if (ret != 0) {
        ERROR("Failed to write file %s: %s", file_path, strerror(errno));
        isulad_set_error_message("Failed to write file %s: %s", file_path, strerror(errno));
        goto out;
    }

out:
    free(str);
    free(pline);
    if (fp != NULL) {
        fclose(fp);
    }
    util_free_string_array(array);
    return ret;
}

static int drop_internal_file(const container_t *cont)
{
    int ret = 0;
    map_t *ip_map = NULL;
    map_t *gateway_map = NULL;

    if (cont->network_settings == NULL || cont->network_settings->networks == NULL ||
        cont->network_settings->networks->len == 0) {
        return 0;
    }

    ip_map = get_ip_map(cont->network_settings->networks);
    if (ip_map == NULL) {
        ERROR("Failed to get ip map");
        return -1;
    }

    gateway_map = get_gateway_map(cont->network_settings->networks);
    if (gateway_map == NULL) {
        ERROR("Failed to get gateway map");
        ret = -1;
        goto out;
    }

    if (do_drop_internal_file(cont->common_config->id, cont->common_config->hosts_path, cont->network_settings->networks,
                              ip_map, hosts_checker) != 0) {
        ERROR("Failed to drop hosts in hosts file");
        ret = -1;
        goto out;
    }

    if (do_drop_internal_file(cont->common_config->id, cont->common_config->resolv_conf_path,
                              cont->network_settings->networks, gateway_map, dns_checker) != 0) {
        ERROR("Failed to drop dns in resolv.conf");
        ret = -1;
        goto out;
    }

out:
    map_free(ip_map);
    map_free(gateway_map);
    return ret;
}

static int update_container_network_settings(container_t *cont, const cni_anno_port_mappings_container *merged_ports,
                                             const network_api_result_list *result)
{
    int ret = 0;
    bool to_disk = false;
    container_network_settings *backup = NULL;

    backup = dup_contaner_network_settings(cont->network_settings);
    if (backup == NULL) {
        ERROR("Failed to dup container network settings");
        return -1;
    }

    ret = update_container_networks_info(result, cont->network_settings->networks);
    if (ret != 0) {
        ERROR("Failed to update network setting");
        goto out;
    }

    ret = update_container_networks_portmappings(merged_ports, cont->network_settings);
    if (ret != 0) {
        ERROR("Failed to update network portmappings");
        goto out;
    }

    cont->network_settings->activation = true;
    cont->skip_remove_network = false;
    ret = container_network_settings_to_disk(cont);
    if (ret != 0) {
        ERROR("Failed to save container '%s' network settings", cont->common_config->id);
        goto out;
    }
    to_disk = true;

    ret = update_internal_file(cont);
    if (ret != 0) {
        ERROR("Failed to update container internal network file");
        goto out;
    }

out:
    if (ret != 0) {
        free_container_network_settings(cont->network_settings);
        cont->network_settings = backup;
        backup = NULL;
        DEBUG("rollback container network settings when failed");

        if (to_disk) {
            if (container_network_settings_to_disk(cont) != 0) {
                ERROR("Failed to rollback container '%s' network settings", cont->common_config->id);
            }
            DEBUG("network settings to disk when rollback");
        }
    }
    free_container_network_settings(backup);

    return ret;
}

static int setup_network(container_t *cont)
{
    int ret = 0;
    network_api_conf *config = NULL;
    network_api_result_list *result = NULL;
    cni_anno_port_mappings_container *merged_ports = NULL;

    config = build_adaptor_native_config(cont, true);
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
        goto detach_out;
    }

    ret = update_container_network_settings(cont, merged_ports, result);
    if (ret == 0) {
        goto out;
    }
    ERROR("Failed to update container network settings");

detach_out:
    if (network_module_detach(config, NETWOKR_API_TYPE_NATIVE) != 0) {
        ERROR("Failed to detach network");
    }
    DEBUG("detach network plane when rollback");

out:
    free_cni_anno_port_mappings_container(merged_ports);
    free_network_api_conf(config);
    free_network_api_result_list(result);

    return ret;
}

int prepare_network(container_t *cont)
{
    int ret = 0;
    bool new_ns = false;
    bool post_setup_network = false;

    if (cont == NULL) {
        ERROR("Invalid cont");
        return -1;
    }

    if (!util_native_network_checker(cont->hostconfig->network_mode, cont->hostconfig->system_container)) {
        goto out;
    }

    if (cont->network_settings->activation) {
        WARN("Container %s network is active", cont->common_config->id);
        goto out;
    }

    if (!validate_network(cont->network_settings->networks)) {
        ERROR("Failed to validate network");
        ret = -1;
        goto out;
    }

    post_setup_network = util_post_setup_network(cont->hostconfig->user_remap);
    ret = prepare_network_namespace(post_setup_network, cont->state->state->pid, cont->network_settings->sandbox_key);
    if (ret != 0) {
        ERROR("Failed to new net namespace");
        goto out;
    }
    new_ns = true;

    ret = setup_network(cont);
    if (ret != 0) {
        ERROR("Failed to setup network");
        goto out;
    }

out:
    if (ret != 0 && new_ns) {
        if (remove_network_namespace(cont->network_settings->sandbox_key) != 0) {
            ERROR("Faield to remove net ns for container %s", cont->common_config->id);
        }
        DEBUG("remove net namespace when rollback");
    }

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

static int drop_container_networks_info(defs_map_string_object_networks *networks)
{
    size_t i = 0;

    for (i = 0; i < networks->len; i++) {
        defs_map_string_object_networks_element *value = networks->values[i];
        if (value == NULL) {
            ERROR("Invalid value networks map value");
            return -1;
        }

        free(value->ip_address);
        value->ip_address = NULL;
        value->ip_prefix_len = 0;

        free(value->gateway);
        value->gateway = NULL;

        free(value->global_i_pv6address);
        value->global_i_pv6address = NULL;
        value->global_i_pv6prefix_len = 0;

        free(value->i_pv6gateway);
        value->i_pv6gateway = NULL;

        free(value->mac_address);
        value->mac_address = NULL;
    }

    return 0;
}

static int drop_container_network_settings(container_t *cont)
{
    int ret = 0;
    container_network_settings *backup = NULL;

    ret = drop_internal_file(cont);
    if (ret != 0) {
        ERROR("Failed to update container internal network file");
        return -1;
    }

    backup = dup_contaner_network_settings(cont->network_settings);
    if (backup == NULL) {
        ERROR("Failed to dup container network settings");
        return -1;
    }

    ret = drop_container_networks_info(cont->network_settings->networks);
    if (ret != 0) {
        ERROR("Failed to drop container networks info");
        goto out;
    }

    // clear portmappings
    do_free_network_setting_cni_portmapping(cont->network_settings);

    cont->network_settings->activation = false;
    if (container_network_settings_to_disk(cont) != 0) {
        ERROR("Failed to save container '%s' network settings", cont->common_config->id);
        ret = -1;
    }

out:
    if (ret != 0) {
        free_container_network_settings(cont->network_settings);
        cont->network_settings = backup;
        backup = NULL;
        DEBUG("rollback container network settings when failed");
    }
    free_container_network_settings(backup);

    return ret;
}

static int teardown_network(container_t *cont)
{
    int ret = 0;
    network_api_conf *config = NULL;

    config = build_adaptor_native_config(cont, false);
    if (config == NULL) {
        ERROR("Failed to build adaptor native config");
        return -1;
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

    ret = drop_container_network_settings(cont);
    if (ret != 0) {
        ERROR("Failed to drop container network settings");
        goto out;
    }

out:
    free_network_api_conf(config);
    return ret;
}

int remove_network(container_t *cont)
{
    bool failure = false;

    if (cont == NULL) {
        ERROR("Invalid cont");
        return -1;
    }

    if (!util_native_network_checker(cont->hostconfig->network_mode, cont->hostconfig->system_container)) {
        goto out;
    }

    if (cont->skip_remove_network) {
        WARN("skip remove container %s network when restarting", cont->common_config->id);
        goto out;
    }

    if (teardown_network(cont) != 0) {
        ERROR("Failed to teardown network");
        failure = true;
    }

    if (remove_network_namespace(cont->network_settings->sandbox_key) != 0) {
        ERROR("Faield to remove net ns for container %s", cont->common_config->id);
        failure = true;
    }

out:
    return failure ? -1 : 0;
}

bool network_store_container_list_add(container_t *cont)
{
    size_t i = 0;
    bool ret = true;
    const defs_map_string_object_networks *obj = NULL;

    if (!container_is_running(cont->state)) {
        return true;
    }

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

void set_container_skip_remove_network(container_t *cont)
{
    container_lock(cont);

    cont->skip_remove_network = true;

    container_unlock(cont);
}

void reset_container_skip_remove_network(container_t *cont)
{
    container_lock(cont);

    cont->skip_remove_network = false;

    container_unlock(cont);
}
