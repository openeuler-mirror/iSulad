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
 * Create: 2020-10-31
 * Description: provide network config functions
 ********************************************************************************/

#include "network_config.h"

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "utils.h"
#include "path.h"
#include "error.h"
#include "err_msg.h"
#include "isulad_config.h"
#include "isula_libutils/log.h"
#include "libcni_api.h"
#include "libcni_conf.h"
#include "libcni_types.h"
#include "libcni_utils.h"


const char *g_network_config_exts[] = { ".conf", ".conflist", ".json" };
const char *g_bridge_name_prefix = "isula-br";
const char *g_default_driver = "bridge";
const char *g_bridge_plugins[] = { "bridge", "portmap", "firewall", NULL };

struct subnet_scope {
    char *begin;
    char *end;
};
/* Reserved IPv4 address ranges for private networks */
const struct subnet_scope g_private_networks[] = {
    /* Class C network 192.168.0.0/16 */
    {"192.168.0.0/24", "192.168.255.0/24"},
    /* Class B network 172.16.0.0/12 */
    {"172.16.0.0/24", "172.31.255.0/24"},
    /* Class A network 10.0.0.0/8 */
    {"10.0.0.0/24", "10.255.255.0/24"},
};

struct cni_conflist {
    cni_net_conf_list *conflist;
    char *path;
};

static void free_cni_conflist(struct cni_conflist *conflist)
{
    if (conflist == NULL) {
        return;
    }

    free_cni_net_conf_list(conflist->conflist);
    conflist->conflist = NULL;
    free(conflist->path);
    conflist->path = NULL;

    free(conflist);
}

static void free_cni_conflist_arr(struct cni_conflist **conflist_arr, size_t arr_len)
{
    size_t i;

    if (conflist_arr == NULL) {
        return;
    }
    for (i = 0; i < arr_len; i++) {
        free_cni_conflist(conflist_arr[i]);
        conflist_arr[i] = NULL;
    }
    free(conflist_arr);
}

static char *get_cni_conf_dir()
{
    char *dir = NULL;
    char *tmp = NULL;
    char cleaned[PATH_MAX] = { 0 };

    tmp = conf_get_cni_conf_dir();
    if (tmp == NULL) {
        return NULL;
    }

    if (util_clean_path(tmp, cleaned, sizeof(cleaned)) == NULL) {
        ERROR("Can not clean path: %s", tmp);
        goto out;
    }
    dir = util_strdup_s(cleaned);

out:
    free(tmp);
    return dir;
}

static int get_cni_bin_dir(char ***dst)
{
    int i, len;
    char **dir = NULL;
    char **tmp = NULL;
    char cleaned[PATH_MAX] = { 0 };

    len = conf_get_cni_bin_dir(&tmp);
    if (len <= 0) {
        return len;
    }

    for (i = 0; i < len; i++) {
        if (util_clean_path(tmp[i], cleaned, sizeof(cleaned)) == NULL) {
            ERROR("Can not clean path: %s", tmp[i]);
            goto free_out;
        }
        if (util_array_append(&dir, cleaned) != 0) {
            goto free_out;
        }
    }

    *dst = dir;
    util_free_array(tmp);
    return len;

free_out:
    util_free_array(dir);
    util_free_array(tmp);
    return -1;
}

static int load_cni_list_from_file(const char *file, cni_net_conf_list **list)
{
    int ret = 0;
    int nret = 0;
    struct network_config_list *li = NULL;
    struct network_config *conf = NULL;

    if (util_has_suffix(file, ".conflist")) {
        nret = conflist_from_file(file, &li);
        if (nret != 0) {
            WARN("Failed to load config list from file %s", file);
            goto out;
        }
        if (li == NULL || li->list == NULL) {
            goto out;
        }
    } else {
        nret = conf_from_file(file, &conf);
        if (nret != 0) {
            WARN("Failed to load config from file %s", file);
            goto out;
        }
        if (conf == NULL || conf->network == NULL) {
            goto out;
        }

        nret = conflist_from_conf(conf, &li);
        if (nret != 0) {
            ERROR("Failed to get conflist from conf");
            ret = -1;
            goto out;
        }
        if (li == NULL || li->list == NULL) {
            goto out;
        }
    }
    *list = li->list;
    li->list = NULL;

out:
    free_network_config_list(li);
    free_network_config(conf);
    return ret;
}

static int load_cni_conflist(const char *cni_conf_dir, struct cni_conflist ***conflist_arr, size_t *arr_len)
{
    int ret = 0;
    size_t i, old_size, new_size;
    size_t tmp_len = 0;
    size_t files_len = 0;
    char **files = NULL;
    struct cni_conflist **tmp_arr = NULL;
    cni_net_conf_list *li = NULL;

    ret = conf_files(cni_conf_dir, g_network_config_exts, sizeof(g_network_config_exts) / sizeof(char *), &files);
    if (ret != 0) {
        ERROR("Failed to get conf files");
        ret = -1;
        goto out;
    }

    files_len = util_array_len((const char **)files);
    if (files_len == 0) {
        goto out;
    }

    tmp_arr = (struct cni_conflist **)util_smart_calloc_s(sizeof(struct cni_conflist *), files_len);
    if (tmp_arr == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < files_len; i++) {
        ret = load_cni_list_from_file(files[i], &li);
        if (ret != 0) {
            ERROR("Failed to load cni list from file %s", files[i]);
            goto out;
        }
        if (li == NULL) {
            continue;
        }

        tmp_arr[tmp_len] = (struct cni_conflist *)util_common_calloc_s(sizeof(struct cni_conflist));
        if (tmp_arr[tmp_len] == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }

        tmp_arr[tmp_len]->conflist = li;
        li = NULL;
        tmp_arr[tmp_len]->path = util_strdup_s(files[i]);
        tmp_len++;
    }

    if (files_len != tmp_len) {
        if (tmp_len == 0) {
            goto out;
        }

        old_size = files_len * sizeof(struct cni_conflist *);
        new_size = tmp_len * sizeof(struct cni_conflist *);
        ret = util_mem_realloc((void **)&tmp_arr, new_size, tmp_arr, old_size);
        if (ret != 0) {
            ERROR("Out of memory");
            goto out;
        }
    }
    *conflist_arr = tmp_arr;
    tmp_arr = NULL;
    *arr_len = tmp_len;
    tmp_len = 0;

out:
    util_free_array_by_len(files, files_len);
    free_cni_conflist_arr(tmp_arr, tmp_len);
    free_cni_net_conf_list(li);

    return ret;
}

typedef int (*get_config_callback)(const cni_net_conf_list *list, char ***arr);

static int get_config_net_name(const cni_net_conf_list *list, char ***arr)
{
    if (list->name == NULL) {
        return 0;
    }

    return util_array_append(arr, list->name);
}

static int get_config_bridge_name(const cni_net_conf_list *list, char ***arr)
{
    size_t i;
    int nret = 0;
    cni_net_conf *plugin = NULL;

    if (list->plugins == NULL) {
        return 0;
    }
    for (i = 0; i < list->plugins_len; i++) {
        plugin = list->plugins[i];
        if (plugin == NULL || strcmp(plugin->type, g_default_driver) != 0 || plugin->bridge == NULL) {
            continue;
        }
        nret = util_array_append(arr, plugin->bridge);
        if (nret != 0) {
            return -1;
        }
    }

    return 0;
}

static int get_config_subnet(const cni_net_conf_list *list, char ***arr)
{
    size_t i;
    int nret = 0;
    bool condition = false;
    cni_net_conf *plugin = NULL;

    if (list->plugins == NULL) {
        return 0;
    }

    for (i = 0; i < list->plugins_len; i++) {
        plugin = list->plugins[i];
        condition = plugin == NULL || plugin->ipam == NULL || plugin->ipam->ranges == NULL || plugin->ipam->ranges_len == 0 ||
                    plugin->ipam->ranges[0] == NULL || plugin->ipam->ranges_item_lens == NULL ||
                    plugin->ipam->ranges_item_lens[0] == 0 || plugin->ipam->ranges[0][0] == NULL ||
                    plugin->ipam->ranges[0][0]->subnet == NULL;
        if (condition) {
            continue;
        }
        nret = util_array_append(arr, plugin->ipam->ranges[0][0]->subnet);
        if (nret != 0) {
            return -1;
        }
    }

    return 0;
}

static int get_cni_config(const struct cni_conflist **conflist_arr, const size_t arr_len,
                          get_config_callback cb, char ***arr)
{
    int nret = 0;
    size_t i;

    if (conflist_arr == NULL || arr_len == 0) {
        return 0;
    }

    for (i = 0; i < arr_len; i++) {
        if (conflist_arr[i] == NULL || conflist_arr[i]->conflist == NULL) {
            continue;
        }

        nret = cb(conflist_arr[i]->conflist, arr);
        if (nret != 0) {
            util_free_array(*arr);
            *arr = NULL;
            return -1;
        }
    }

    return 0;
}

static int get_interface_name(char ***interface_names)
{
    int ret = 0;
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;

    ret = getifaddrs(&ifaddr);
    if (ret != 0) {
        ERROR("Failed to get if addr");
        return ret;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        // one AF_PACKET address per interface
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_PACKET) {
            continue;
        }
        ret = util_array_append(interface_names, ifa->ifa_name);
        if (ret != 0) {
            goto out;
        }
    }

out:
    freeifaddrs(ifaddr);
    return ret;
}

static int get_host_net_ip(char ***host_net_ip)
{
    int ret = 0;
    char ipaddr[INET6_ADDRSTRLEN] = { 0 };
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;

    ret = getifaddrs(&ifaddr);
    if (ret != 0) {
        ERROR("Failed to get if addr");
        return ret;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET) {
            if (inet_ntop(AF_INET, &(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr),
                          ipaddr, INET_ADDRSTRLEN) == NULL) {
                ERROR("Failed to get ipv4 addr");
                ret = ECOMM;
                goto out;
            }
            ret = util_array_append(host_net_ip, ipaddr);
            if (ret != 0) {
                goto out;
            }
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            if (inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr),
                          ipaddr, INET6_ADDRSTRLEN) == NULL) {
                ERROR("Failed to ipv6 addr");
                ret = ECOMM;
                goto out;
            }
            ret = util_array_append(host_net_ip, ipaddr);
            if (ret != 0) {
                goto out;
            }
        }
    }

out:
    freeifaddrs(ifaddr);
    return ret;
}

/*
 * RETURN VALUE:
 * 0        : net not conflict
 * 1        : net conflict
 * others   : error
 */
static int net_conflict(const struct ipnet *net, const struct ipnet *ipnet)
{
    int ret = 0;
    size_t i = 0;
    uint8_t *first_net = NULL;
    uint8_t *first_ipnet = NULL;

    if (net == NULL || ipnet == NULL) {
        return 0;
    }

    if (net->ip_len != ipnet->ip_len || net->ip_mask_len != ipnet->ip_mask_len) {
        return 0;
    }

    first_net = util_smart_calloc_s(sizeof(uint8_t), net->ip_len);
    if (first_net == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    first_ipnet = util_smart_calloc_s(sizeof(uint8_t), ipnet->ip_len);
    if (first_ipnet == NULL) {
        free(first_net);
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < ipnet->ip_len; i++) {
        first_net[i] = net->ip[i] & net->ip_mask[i];
        first_ipnet[i] = ipnet->ip[i] & ipnet->ip_mask[i];
    }

    if (net_contain_ip(net, first_ipnet, ipnet->ip_len, true) || net_contain_ip(ipnet, first_net, net->ip_len, true)) {
        ret = 1;
    }

    free(first_net);
    free(first_ipnet);
    return ret;
}

/*
 * RETURN VALUE:
 * 0        : subnet available
 * 1        : subnet not avaliable
 * others   : error
 */
static int check_subnet_available(const char *subnet, const char **subnets, const char **hostIP)
{
    int ret = 0;
    size_t len = 0;
    size_t i = 0;
    uint8_t *ip = NULL;
    size_t ip_len = 0;
    struct ipnet *net = NULL;
    struct ipnet *tmp = NULL;

    ret = parse_cidr(subnet, &net);
    if (ret != 0 || net == NULL) {
        ERROR("Parse CIDR %s failed", subnet);
        return -1;
    }

    len = util_array_len(subnets);
    for (i = 0; i < len; i++) {
        ret = parse_cidr(subnets[i], &tmp);
        if (ret != 0 || tmp == NULL) {
            ERROR("Parse CIDR %s failed", subnets[i]);
            ret = -1;
            goto out;
        }
        ret = net_conflict(tmp, net);
        if (ret != 0) {
            goto out;
        }
        free_ipnet_type(tmp);
        tmp = NULL;
    }

    len = util_array_len(hostIP);
    for (i = 0; i < len; i++) {
        ret = parse_ip_from_str(hostIP[i], &ip, &ip_len);
        if (ret != 0 || ip == NULL || ip_len == 0) {
            ERROR("Parse IP %s failed", hostIP[i]);
            ret = -1;
            goto out;
        }
        if (net_contain_ip(net, ip, ip_len, true)) {
            ret = 1;
            goto out;
        }
        free(ip);
        ip = NULL;
        ip_len = 0;
    }

out:
    free(ip);
    free_ipnet_type(net);
    free_ipnet_type(tmp);
    return ret;
}

static int check_conflict(const network_create_request *request, const struct cni_conflist **conflist_arr,
                          const size_t arr_len)
{
    int ret = 0;
    char **net_names = NULL;
    char **subnets = NULL;
    char **hostIP = NULL;

    if (request->name != NULL) {
        ret = get_cni_config(conflist_arr, arr_len, get_config_net_name, &net_names);
        if (ret != 0) {
            goto out;
        }
        if (util_array_contain((const char **)net_names, request->name)) {
            isulad_set_error_message("Network name \"%s\" has been used", request->name);
            ret = EINVALIDARGS;
            goto out;
        }
    }

    if (request->subnet == NULL) {
        goto out;
    }

    ret = get_cni_config(conflist_arr, arr_len, get_config_subnet, &subnets);
    if (ret != 0) {
        goto out;
    }

    ret = get_host_net_ip(&hostIP);
    if (ret != 0) {
        goto out;
    }

    ret = check_subnet_available(request->subnet, (const char **)subnets, (const char **)hostIP);
    if (ret == 1) {
        isulad_set_error_message("Subnet \"%s\" conflict with CNI config or host network", request->subnet);
        ret = EINVALIDARGS;
    }

out:
    util_free_array(net_names);
    util_free_array(subnets);
    util_free_array(hostIP);
    return ret;
}

static char *find_bridge_name(const struct cni_conflist **conflist_arr, const size_t arr_len)
{
    int nret = 0;
    int i = 0;
    char *num = NULL;
    char *name = NULL;
    char **net_names = NULL;
    char **bridge_names = NULL;
    char **host_net_names = NULL;

    nret = get_cni_config(conflist_arr, arr_len, get_config_net_name, &net_names);
    if (nret != 0) {
        return NULL;
    }

    nret = get_cni_config(conflist_arr, arr_len, get_config_bridge_name, &bridge_names);
    if (nret != 0) {
        goto out;
    }

    nret = get_interface_name(&host_net_names);
    if (nret != 0) {
        goto out;
    }

    for (i = 0; i < MAX_BRIDGE_ID; i++) {
        free(name);
        name = NULL;
        free(num);
        num = NULL;

        num = util_int_to_string(i);
        if (num == NULL) {
            goto out;
        }
        name = util_string_append(num, g_bridge_name_prefix);
        if (name == NULL) {
            goto out;
        }
        if (net_names != NULL && util_array_contain((const char **)net_names, name)) {
            continue;
        }
        if (bridge_names != NULL && util_array_contain((const char **)bridge_names, name)) {
            continue;
        }
        if (host_net_names != NULL && util_array_contain((const char **)host_net_names, name)) {
            continue;
        }
        goto out;
    }
    free(name);
    name = NULL;
    isulad_set_error_message("Too many network bridges");

out:
    free(num);
    util_free_array(net_names);
    util_free_array(bridge_names);
    util_free_array(host_net_names);
    return name;
}

static char *find_private_network(char *subnet)
{
    int nret = 0;
    int i = 0;
    uint32_t ip = 0;
    uint32_t mask = 0;
    struct ipnet *ipnet = NULL;
    char *nx = NULL;
    size_t len = sizeof(g_private_networks) / sizeof(g_private_networks[0]);

    if (subnet == NULL) {
        return util_strdup_s(g_private_networks[0].begin);
    }

    for (i = 0; i < len - 1; i++) {
        if (strcmp(subnet, g_private_networks[i].end) == 0) {
            return util_strdup_s(g_private_networks[i + 1].begin);
        }
    }

    nret = parse_cidr(subnet, &ipnet);
    if (nret != 0 || ipnet == NULL) {
        ERROR("Parse IP %s failed", subnet);
        return NULL;
    }
    for (i = 0; i < ipnet->ip_len; i++) {
        ip <<= 8;
        mask <<= 8;
        ip += (uint32_t)(ipnet->ip[i]);
        mask += (uint32_t)(ipnet->ip_mask[i]);
    }
    mask = ~mask + 1;
    ip += mask;
    mask = 0xff;
    for (i = ipnet->ip_len - 1; i >= 0 ; i--) {
        ipnet->ip[i] = (uint8_t)(ip & mask);
        ip >>= 8;
    }

    nx = ipnet_to_string(ipnet);
    free_ipnet_type(ipnet);

    return nx;
}

static char *find_subnet(const struct cni_conflist **conflist_arr, const size_t arr_len)
{
    int nret = 0;
    char *subnet = NULL;
    char **config_subnet = NULL;
    char **hostIP = NULL;

    size_t len = sizeof(g_private_networks) / sizeof(g_private_networks[0]);
    const char *end = g_private_networks[len - 1].end;

    nret = get_cni_config(conflist_arr, arr_len, get_config_subnet, &config_subnet);
    if (nret != 0) {
        return NULL;
    }

    nret = get_host_net_ip(&hostIP);
    if (nret != 0) {
        goto out;
    }

    do {
        char *nx_subnet = find_private_network(subnet);
        if (nx_subnet == NULL) {
            free(subnet);
            subnet = NULL;
            goto out;
        } else {
            free(subnet);
            subnet = nx_subnet;
        }

        nret = check_subnet_available(subnet, (const char **)config_subnet, (const char **)hostIP);
        if (nret == 0) {
            goto out;
        }
        if (nret == 1) {
            continue;
        }
        // error
        free(subnet);
        subnet = NULL;
        goto out;
    } while (strcmp(subnet, end) != 0);

    free(subnet);
    subnet = NULL;
    isulad_set_error_message("Cannot find avaliable subnet by default");

out:
    util_free_array(config_subnet);
    util_free_array(hostIP);
    return subnet;
}

static char *find_gateway(const char *subnet)
{
    int nret = 0;
    size_t i;
    uint8_t *first_ip = NULL;
    char *gateway = NULL;
    struct ipnet *ipnet = NULL;

    nret = parse_cidr(subnet, &ipnet);
    if (nret != 0 || ipnet == NULL) {
        ERROR("Parse IP %s failed", subnet);
        return NULL;
    }

    first_ip = util_smart_calloc_s(sizeof(uint8_t), ipnet->ip_len);
    if (first_ip == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    if (ipnet->ip_mask[ipnet->ip_mask_len - 1] == 0xff) {
        isulad_set_error_message("No avaliable gateway in %s", subnet);
        goto out;
    }

    for (i = 0; i < ipnet->ip_len; i++) {
        first_ip[i] = ipnet->ip[i] & ipnet->ip_mask[i];
    }
    first_ip[ipnet->ip_len - 1] = first_ip[ipnet->ip_len - 1] | 0x01;
    gateway = ip_to_string(first_ip, ipnet->ip_len);

out:
    free_ipnet_type(ipnet);
    free(first_ip);
    return gateway;
}

static cni_net_conf_ipam *conf_bridge_ipam(const network_create_request *request,
                                           const struct cni_conflist **conflist_arr,
                                           const size_t arr_len)
{
    cni_net_conf_ipam *ipam = NULL;

    ipam = util_common_calloc_s(sizeof(cni_net_conf_ipam));
    if (ipam == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    ipam->type = util_strdup_s("host-local");
    ipam->routes = util_common_calloc_s(sizeof(cni_network_route *));
    if (ipam->routes == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    ipam->routes[0] = util_common_calloc_s(sizeof(cni_network_route));
    if (ipam->routes[0] == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    ipam->routes_len++;
    ipam->routes[0]->dst = util_strdup_s("0.0.0.0/0");

    ipam->ranges = (cni_net_conf_ipam_ranges_element ***)util_common_calloc_s(sizeof(cni_net_conf_ipam_ranges_element **));
    if (ipam->ranges == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    ipam->ranges_item_lens = (size_t *)util_common_calloc_s(sizeof(size_t));
    if (ipam->ranges_item_lens == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }

    ipam->ranges[0] = (cni_net_conf_ipam_ranges_element **)util_common_calloc_s(sizeof(cni_net_conf_ipam_ranges_element *));
    if (ipam->ranges[0] == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    ipam->ranges_len++;
    ipam->ranges[0][0] = (cni_net_conf_ipam_ranges_element *)util_common_calloc_s(sizeof(cni_net_conf_ipam_ranges_element));
    if (ipam->ranges[0][0] == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    (ipam->ranges_item_lens)[0]++;

    if (request->subnet != NULL) {
        ipam->ranges[0][0]->subnet = util_strdup_s(request->subnet);
    } else {
        ipam->ranges[0][0]->subnet = find_subnet(conflist_arr, arr_len);
        if (ipam->ranges[0][0]->subnet == NULL) {
            ERROR("Failed to find available subnet");
            goto err_out;
        }
    }

    if (request->gateway != NULL) {
        ipam->ranges[0][0]->gateway = util_strdup_s(request->gateway);
    } else {
        ipam->ranges[0][0]->gateway = find_gateway(ipam->ranges[0][0]->subnet);
        if (ipam->ranges[0][0]->gateway == NULL) {
            ERROR("Failed to find gateway");
            goto err_out;
        }
    }

    return ipam;

err_out:
    free_cni_net_conf_ipam(ipam);
    return NULL;
}

static cni_net_conf *conf_bridge_plugin(const network_create_request *request, const struct cni_conflist **conflist_arr,
                                        const size_t arr_len)
{
    cni_net_conf *plugin = NULL;

    plugin = util_common_calloc_s(sizeof(cni_net_conf));
    if (plugin == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (request->driver == NULL) {
        plugin->type = util_strdup_s(g_default_driver);
    } else {
        plugin->type = util_strdup_s(request->driver);
    }

    plugin->bridge = find_bridge_name(conflist_arr, arr_len);
    if (plugin->bridge == NULL) {
        ERROR("Failed to find avaliable bridge name");
        goto err_out;
    }

    if (request->internal) {
        plugin->is_gateway = false;
        plugin->ip_masq = false;
    } else {
        plugin->is_gateway = true;
        plugin->ip_masq = true;
    }
    plugin->hairpin_mode = true;

    plugin->ipam = conf_bridge_ipam(request, conflist_arr, arr_len);
    if (plugin->ipam == NULL) {
        ERROR("Failed to config bridge ipam");
        goto err_out;
    }

    return plugin;

err_out:
    free_cni_net_conf(plugin);
    return NULL;
}

static cni_net_conf *conf_portmap_plugin(const network_create_request *request)
{
    cni_net_conf *plugin = NULL;

    plugin = util_common_calloc_s(sizeof(cni_net_conf));
    if (plugin == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    plugin->type = util_strdup_s("portmap");
    plugin->capabilities = util_common_calloc_s(sizeof(json_map_string_bool));
    if (plugin->capabilities == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    plugin->capabilities->keys = util_common_calloc_s(sizeof(char *));
    if (plugin->capabilities->keys == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    plugin->capabilities->keys[0] = util_strdup_s("portMappings");
    plugin->capabilities->values = util_common_calloc_s(sizeof(bool));
    if (plugin->capabilities->values == NULL) {
        free(plugin->capabilities->keys[0]);
        ERROR("Out of memory");
        goto err_out;
    }
    plugin->capabilities->values[0] = true;
    plugin->capabilities->len++;

    return plugin;

err_out:
    free_cni_net_conf(plugin);
    return NULL;
}

static cni_net_conf *conf_firewall_plugin(const network_create_request *request)
{
    cni_net_conf *plugin = NULL;

    plugin = util_common_calloc_s(sizeof(cni_net_conf));
    if (plugin == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    plugin->type = util_strdup_s("firewall");

    return plugin;
}

static cni_net_conf_list *conf_bridge_conflist(const network_create_request *request,
                                               const struct cni_conflist **conflist_arr,
                                               const size_t arr_len)
{
    size_t len;
    cni_net_conf *plugin = NULL;
    cni_net_conf_list *list = NULL;

    list = util_common_calloc_s(sizeof(cni_net_conf_list));
    if (list == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    len = util_array_len(g_bridge_plugins);
    list->plugins = (cni_net_conf **)util_smart_calloc_s(sizeof(cni_net_conf *), len);
    if (list->plugins == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }

    list->plugins_len = 0;
    plugin = conf_bridge_plugin(request, conflist_arr, arr_len);
    if (plugin == NULL) {
        ERROR("Failed to config bridge plugin");
        goto err_out;
    }
    list->plugins[list->plugins_len] = plugin;
    list->plugins_len++;

    plugin = conf_portmap_plugin(request);
    if (plugin == NULL) {
        ERROR("Failed to config portmap plugin");
        goto err_out;
    }
    list->plugins[list->plugins_len] = plugin;
    list->plugins_len++;

    plugin = conf_firewall_plugin(request);
    if (plugin == NULL) {
        ERROR("Failed to config firewall plugin");
        goto err_out;
    }
    list->plugins[list->plugins_len] = plugin;
    list->plugins_len++;

    list->cni_version = util_strdup_s(CURRENT_VERSION);
    if (request->name != NULL) {
        list->name = util_strdup_s(request->name);
    } else {
        // config bridge as conflist name
        list->name = util_strdup_s(list->plugins[0]->bridge);
    }

    return list;

err_out:
    free_cni_net_conf_list(list);
    return NULL;
}

static int do_create_conflist_file(const char *cni_conf_dir, cni_net_conf_list *list, char **path)
{
    int ret = 0;
    int nret = 0;
    char conflist_file[PATH_MAX] = { 0x00 };
    char *conflist_json = NULL;
    parser_error err = NULL;

    EVENT("Network Event: {Object: %s, Type: Creating}", list->name);

    if (!util_dir_exists(cni_conf_dir)) {
        ret = util_mkdir_p(cni_conf_dir, CONFIG_DIRECTORY_MODE);
        if (ret != 0) {
            ERROR("Failed to create network config directory %s", cni_conf_dir);
            return -1;
        }
    }

    nret = snprintf(conflist_file, sizeof(conflist_file), "%s/%s%s.conflist", cni_conf_dir,
                    ISULAD_CNI_NETWORK_CONF_FILE_PRE, list->name);
    if ((size_t)nret >= sizeof(conflist_file) || nret < 0) {
        ERROR("Failed to snprintf conflist_file");
        return -1;
    }

    conflist_json = cni_net_conf_list_generate_json(list, NULL, &err);
    if (conflist_json == NULL) {
        ERROR("Failed to generate conf list json: %s", err);
        ret = -1;
        goto out;
    }

    if (util_file_exists(conflist_file)) {
        ERROR("File %s exist", conflist_file);
        isulad_set_error_message("File %s exist", conflist_file);
        ret = -1;
        goto out;
    }

    if (util_atomic_write_file(conflist_file, conflist_json, strlen(conflist_json), CONFIG_FILE_MODE) != 0) {
        ERROR("Failed write %s", conflist_file);
        ret = -1;
        goto out;
    }

    EVENT("Network Event: {Object: %s, Type: Created}", list->name);
    *path = util_strdup_s(conflist_file);

out:
    free(conflist_json);
    free(err);
    return ret;
}

static int do_cni_bin_detect(const char **cni_bin_dir, const int bin_dir_len, const char *file, char ***absence)
{
    size_t i;
    char *path = NULL;

    for (i = 0; i < bin_dir_len; i++) {
        path = util_path_join(cni_bin_dir[i], file);
        if (path == NULL) {
            return -1;
        }

        if (util_file_exists(path)) {
            free(path);
            return 0;
        }

        free(path);
        path = NULL;
    }

    return util_array_append(absence, file);
}

static int cni_bin_detect(const char **cni_bin_dir, int bin_dir_len)
{
    int ret = 0;
    size_t i, len;
    char **absence = NULL;
    char *file_str = NULL;
    char *dir_str = NULL;

    len = util_array_len(g_bridge_plugins);
    for (i = 0; i < len; i++) {
        ret = do_cni_bin_detect(cni_bin_dir, bin_dir_len, g_bridge_plugins[i], &absence);
        if (ret != 0) {
            ERROR("Failed to do cni bin detect for plugin %s", g_bridge_plugins[i]);
            goto out;
        }
    }

    if (absence == NULL) {
        return ret;
    }

    len = util_array_len((const char **)absence);
    file_str = util_string_join(",", (const char **)absence, len);
    if (file_str == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    dir_str = util_string_join(",", (const char **)cni_bin_dir, bin_dir_len);
    if (dir_str == NULL) {
        ERROR("Out of memory");
        free(file_str);
        ret = -1;
        goto out;
    }

    isulad_set_error_message("WARN:cannot find cni plugin \"%s\" in dir \"%s\"", file_str, dir_str);
    free(file_str);
    free(dir_str);

out:
    util_free_array(absence);
    return ret;
}

int network_config_bridge_create(const network_create_request *request, network_create_response **response)
{
    int ret = 0;
    int bin_dir_len = 0;
    size_t arr_len = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *cni_conf_dir = NULL;
    char **cni_bin_dir = NULL;
    cni_net_conf_list *bridge_list = NULL;
    struct cni_conflist **conflist_arr = NULL;

    cni_conf_dir = get_cni_conf_dir();
    if (cni_conf_dir == NULL) {
        ERROR("Failed to get cni conf dir");
        cc = ISULAD_ERR_EXEC;
        ret = -1;
        goto out;
    }

    ret = load_cni_conflist(cni_conf_dir, &conflist_arr, &arr_len);
    if (ret != 0) {
        isulad_set_error_message("Failed to load cni list, maybe the count of network config files is above 200");
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    ret = check_conflict(request, (const struct cni_conflist **)conflist_arr, arr_len);
    if (ret != 0) {
        cc = ISULAD_ERR_INPUT;
        goto out;
    }

    bridge_list = conf_bridge_conflist(request, (const struct cni_conflist **)conflist_arr, arr_len);
    if (bridge_list == NULL) {
        cc = ISULAD_ERR_EXEC;
        ret = -1;
        goto out;
    }

    ret = do_create_conflist_file(cni_conf_dir, bridge_list, &(*response)->path);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    bin_dir_len = get_cni_bin_dir(&cni_bin_dir);
    if (bin_dir_len <= 0) {
        ERROR("Failed to get cni bin dir");
        cc = ISULAD_ERR_EXEC;
        ret = -1;
        goto out;
    }

    ret = cni_bin_detect((const char **)cni_bin_dir, bin_dir_len);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
    }

out:
    free(cni_conf_dir);
    util_free_array(cni_bin_dir);
    free_cni_net_conf_list(bridge_list);
    free_cni_conflist_arr(conflist_arr, arr_len);

    (*response)->cc = cc;
    if (g_isulad_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }

    return ret;
}

static char *get_conflist_json(const cni_net_conf_list *list)
{
    char *json = NULL;
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };

    json = cni_net_conf_list_generate_json(list, &ctx, &err);
    if (json == NULL) {
        ERROR("Failed to generate conf list json: %s", err);
    }

    free(err);
    return json;
}

int network_config_inspect(const char *name, char **network_json)
{
    int ret = 0;
    size_t i;
    size_t arr_len = 0;
    char *cni_conf_dir = NULL;
    struct cni_conflist **conflist_arr = NULL;

    cni_conf_dir = get_cni_conf_dir();
    if (cni_conf_dir == NULL) {
        ERROR("Failed to get cni conf dir");
        return -1;
    }

    ret = load_cni_conflist(cni_conf_dir, &conflist_arr, &arr_len);
    if (ret != 0) {
        isulad_set_error_message("Failed to load cni list, maybe the count of network config files is above 200");
        goto out;
    }

    EVENT("Network Event: {Object: %s, Type: Inspecting}", name);

    for (i = 0; i < arr_len; i++) {
        if (conflist_arr[i]->conflist->name == NULL || strcmp(conflist_arr[i]->conflist->name, name) != 0) {
            continue;
        }
        *network_json = get_conflist_json(conflist_arr[i]->conflist);
        if (*network_json == NULL) {
            ret = -1;
            goto out;
        }
        // TODO: inspect the linked containers ip info
        goto out;
    }

    isulad_set_error_message("No such network %s", name);
    ret = -1;

out:
    free(cni_conf_dir);
    free_cni_conflist_arr(conflist_arr, arr_len);

    return ret;
}

static bool network_info_match_filter(const cni_net_conf_list *list, const struct filters_args *filters)
{
    size_t i;
    size_t len = list->plugins_len;

    if (!filters_args_match(filters, "name", list->name)) {
        return false;
    }

    for (i = 0; i < len; i++) {
        if (filters_args_match(filters, "plugin", list->plugins[i]->type)) {
            return true;
        }
    }

    return false;
}

static network_network_info *get_network_info(const cni_net_conf_list *list)
{
    size_t i;
    int nret = 0;
    network_network_info *net_info = NULL;

    net_info = (network_network_info *)util_common_calloc_s(sizeof(network_network_info));
    if (net_info == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    net_info->name = util_strdup_s(list->name);
    net_info->version = util_strdup_s(list->cni_version);
    net_info->plugins_len = 0;
    if (list->plugins_len == 0) {
        return net_info;
    }

    for (i = 0; i < list->plugins_len; i++) {
        if (list->plugins[i]->type == NULL) {
            continue;
        }
        nret = util_array_append(&net_info->plugins, list->plugins[i]->type);
        if (nret != 0) {
            ERROR("Failed to append network plugins array");
            goto err_out;
        }
        net_info->plugins_len++;
    }
    return net_info;

err_out:
    free_network_network_info(net_info);
    return NULL;
}

static void free_network_info_arr(network_network_info **networks, size_t len)
{
    size_t i;

    if (networks == NULL) {
        return;
    }
    for (i = 0; i < len; i++) {
        free_network_network_info(networks[i]);
    }
    free(networks);
}

int network_config_list(const struct filters_args *filters, network_network_info ***networks, size_t *networks_len)
{
    int ret = 0;
    size_t i, old_size, new_size;
    char *cni_conf_dir = NULL;
    struct cni_conflist **conflist_arr = NULL;
    size_t arr_len = 0;
    network_network_info **nets = NULL;
    size_t nets_len = 0;
    network_network_info *net_info = NULL;

    cni_conf_dir = get_cni_conf_dir();
    if (cni_conf_dir == NULL) {
        ERROR("Failed to get cni conf dir");
        return -1;
    }

    ret = load_cni_conflist(cni_conf_dir, &conflist_arr, &arr_len);
    if (ret != 0) {
        isulad_set_error_message("Failed to load cni list, maybe the count of network config files is above 200");
        goto out;
    }

    if (arr_len == 0) {
        goto out;
    }

    nets = (network_network_info **)util_common_calloc_s(sizeof(network_network_info *) * arr_len);
    if (nets == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    EVENT("Network Event: {Object: network, Type: List}");

    for (i = 0; i < arr_len; i++) {
        if (filters != NULL && !network_info_match_filter(conflist_arr[i]->conflist, filters)) {
            continue;
        }
        net_info = get_network_info(conflist_arr[i]->conflist);
        if (net_info == NULL) {
            ret = -1;
            goto out;
        }
        nets[nets_len] = net_info;
        net_info = NULL;
        nets_len++;
    }
    if (arr_len != nets_len) {
        if (nets_len == 0) {
            goto out;
        }

        old_size = arr_len * sizeof(network_network_info *);
        new_size = nets_len * sizeof(network_network_info *);
        ret = util_mem_realloc((void **)&nets, new_size, nets, old_size);
        if (ret != 0) {
            ERROR("Out of memory");
            goto out;
        }
    }
    *networks = nets;
    nets = NULL;
    *networks_len = nets_len;
    nets_len = 0;

out:
    free(cni_conf_dir);
    free_cni_conflist_arr(conflist_arr, arr_len);
    free_network_info_arr(nets, nets_len);
    return ret;
}

static struct cni_conflist *get_network_by_name(const char *name)
{
    int nret = 0;
    size_t i;
    char *cni_conf_dir = NULL;
    size_t arr_len = 0;
    struct cni_conflist **conflist_arr = NULL;
    struct cni_conflist *res = NULL;

    cni_conf_dir = get_cni_conf_dir();
    if (cni_conf_dir == NULL) {
        ERROR("Failed to get cni conf dir");
        return NULL;
    }

    nret = load_cni_conflist(cni_conf_dir, &conflist_arr, &arr_len);
    if (nret != 0) {
        isulad_set_error_message("Failed to load cni list, maybe the count of network config files is above 200");
        goto out;
    }

    for (i = 0; i < arr_len; i++) {
        if (conflist_arr[i]->conflist->name == NULL || strcmp(conflist_arr[i]->conflist->name, name) != 0) {
            continue;
        }

        res = (struct cni_conflist *)util_common_calloc_s(sizeof(struct cni_conflist));
        if (res == NULL) {
            ERROR("Out of memory");
            goto out;
        }

        res->conflist = conflist_arr[i]->conflist;
        conflist_arr[i]->conflist = NULL;
        res->path = util_strdup_s(conflist_arr[i]->path);

        goto out;
    }

    isulad_set_error_message("Cannot find network \"%s\" in cni conf dir \"%s\"", name, cni_conf_dir);

out:
    free(cni_conf_dir);
    free_cni_conflist_arr(conflist_arr, arr_len);
    return res;
}

static char *get_bridge_name(cni_net_conf_list *list)
{
    size_t i;
    cni_net_conf *plugin = NULL;

    if (list->plugins == NULL) {
        return NULL;
    }

    for (i = 0; i < list->plugins_len; i++) {
        plugin = list->plugins[i];
        if (plugin == NULL || strcmp(plugin->type, g_default_driver) != 0 || plugin->bridge == NULL) {
            continue;
        }
        return util_strdup_s(plugin->bridge);
    }

    return NULL;
}

static void run_delete_device(void *args)
{
    char **tmp_args = (char **)args;
    const size_t CMD_ARGS_NUM = 4;

    if (util_array_len((const char **)tmp_args) != (size_t)CMD_ARGS_NUM) {
        COMMAND_ERROR(" delete device need four args");
        exit(1);
    }

    execvp(tmp_args[0], tmp_args);
}

static int remove_interface(const char *ifa)
{
    int ret = 0;
    size_t i = 0;;
    const size_t args_len = 4;
    char **args = NULL;
    char **interfaces = NULL;
    char *stdout_msg = NULL;
    char *stderr_msg = NULL;

    ret = get_interface_name(&interfaces);
    if (ret != 0) {
        ERROR("Failed to get interface names");
        return -1;
    }

    if (util_array_len((const char **)interfaces) == 0) {
        return 0;
    }

    if (!util_array_contain((const char **)interfaces, ifa)) {
        goto out;
    }

    args = (char **)util_smart_calloc_s(sizeof(char *), args_len);
    if (args == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    args[i++] = util_strdup_s("ip");
    args[i++] = util_strdup_s("link");
    args[i++] = util_strdup_s("delete");
    args[i] = util_strdup_s(ifa);

    if (!util_exec_cmd(run_delete_device, args, NULL, &stdout_msg, &stderr_msg)) {
        ERROR("Unexpected command output %s with error: %s", stdout_msg, stderr_msg);
        ret = -1;
    }

out:
    util_free_array(interfaces);
    util_free_array(args);
    free(stdout_msg);
    free(stderr_msg);
    return ret;
}

int network_config_remove(const char *name, char **res_name)
{
    int ret = 0;
    int get_err = 0;
    char *bridge = NULL;
    struct cni_conflist *network = NULL;

    network = get_network_by_name(name);
    if (network == NULL) {
        ERROR("Failed to get network");
        return -1;
    }

    EVENT("Event: {Object: network %s, Type: remove}", name);

    // TODO: find the linked containers
    // TODO: remove containers if request->force is true,else return error

    bridge = get_bridge_name(network->conflist);
    if (bridge != NULL) {
        ret = remove_interface(bridge);
        if (ret != 0) {
            ERROR("Failed to remove bridge %s", bridge);
            goto out;
        }
    }

    if (!util_remove_file(network->path, &get_err)) {
        ERROR("Failed to delete %s, error: %s", network->path, strerror(get_err));
        ret = -1;
        goto out;
    }
    *res_name = util_strdup_s(network->conflist->name);

out:
    free_cni_conflist(network);
    free(bridge);
    return ret;
}
