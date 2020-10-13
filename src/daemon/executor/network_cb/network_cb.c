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
 * Create: 2020-09-10
 * Description: provide network callback functions
 ********************************************************************************/

#include "network_cb.h"

#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include "isula_libutils/cni_net_conf_list.h"
#include "isula_libutils/log.h"
#include "isulad_config.h"
#include "utils.h"
#include "path.h"
#include "err_msg.h"
#include "error.h"
#include "daemon_arguments.h"
#include "libcni_api.h"
#include "libcni_conf.h"
#include "libcni_types.h"
#include "libcni_utils.h"

const char *default_driver = "bridge";

pthread_rwlock_t network_rwlock;
enum lock_type { SHARED = 0, EXCLUSIVE };

static inline bool network_list_lock(enum lock_type type)
{
    int nret = 0;

    if (type == SHARED) {
        nret = pthread_rwlock_rdlock(&network_rwlock);
    } else {
        nret = pthread_rwlock_wrlock(&network_rwlock);
    }
    if (nret != 0) {
        ERROR("Lock network list failed: %s", strerror(nret));
        return false;
    }

    return true;
}

static inline void network_list_unlock()
{
    int nret = 0;

    nret = pthread_rwlock_unlock(&network_rwlock);
    if (nret != 0) {
        FATAL("Unlock network list failed: %s", strerror(nret));
    }
}

static bool network_is_valid_name(const char *name)
{
    if (strnlen(name, MAX_NETWORK_NAME_LEN + 1) > MAX_NETWORK_NAME_LEN) {
        isulad_set_error_message("Network name \"%s\" too long, max length:%d", name,
                                 MAX_NETWORK_NAME_LEN);
        return false;
    }
    if (util_reg_match(CNI_VALID_NAME_CHARS, name) != 0) {
        isulad_set_error_message("Invalid network name:%s, only %s are allowed", name, CNI_VALID_NAME_CHARS);
        return false;
    }

    return true;
}

static int check_parameter(const network_create_request *request)
{
    int ret = 0;
    uint8_t *ip = NULL;
    size_t ip_len = 0;
    struct ipnet *net = NULL;

    if (request->name != NULL && !network_is_valid_name(request->name)) {
        return EINVALIDARGS;
    }

    if (request->driver != NULL && strcmp(request->driver, default_driver) != 0) {
        isulad_set_error_message("Cannot support driver:%s", request->driver);
        return EINVALIDARGS;
    }

    if (request->subnet == NULL) {
        if (request->gateway != NULL) {
            isulad_set_error_message("Cannot specify gateway without subnet");
            ret = EINVALIDARGS;
        }
        return ret;
    }

    ret = parse_cidr(request->subnet, &net);
    if (ret != 0 || net == NULL) {
        ERROR("Parse CIDR failed");
        isulad_set_error_message("Invalid subnet %s", request->subnet);
        ret = EINVALIDARGS;
        goto out;
    }

    if (request->gateway == NULL) {
        goto out;
    }

    ret = parse_ip_from_str(request->gateway, &ip, &ip_len);
    if (ret != 0 || ip == NULL || ip_len == 0) {
        ERROR("Parse IP %s failed", request->gateway);
        isulad_set_error_message("Invalid gateway %s", request->gateway);
        ret = EINVALIDARGS;
        goto out;
    }

    if (!net_contain_ip(net, ip, ip_len, false)) {
        isulad_set_error_message("subnet \"%s\" and gateway \"%s\" not match", request->subnet, request->gateway);
        ret = EINVALIDARGS;
    }

out:
    free_ipnet_type(net);
    free(ip);
    return ret;
}

static char *get_cni_conf_dir()
{
    char *res = NULL;
    char cleaned[PATH_MAX] = { 0 };
    char *tmp_dir = NULL;
    const char *default_conf_dir = "/etc/cni/net.d";
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        ERROR("failed to lock server config");
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL) {
        ERROR("failed to get server config");
        goto out;
    }

    if (conf->json_confs->cni_conf_dir == NULL) {
        tmp_dir = util_strdup_s(default_conf_dir);
    } else {
        tmp_dir = util_strdup_s(conf->json_confs->cni_conf_dir);
    }
    if (util_clean_path(tmp_dir, cleaned, sizeof(cleaned)) == NULL) {
        ERROR("Can not clean path: %s", tmp_dir);
        goto out;
    }
    res = util_strdup_s(cleaned);

out:
    free(tmp_dir);
    if (isulad_server_conf_unlock()) {
        ERROR("failed to unlock server config");
        free(res);
        res = NULL;
    }
    return res;
}

static char *get_cni_bin_dir()
{
    char *res = NULL;
    char cleaned[PATH_MAX] = { 0 };
    char *tmp_dir = NULL;
    const char *default_bin_dir = "/opt/cni/bin";
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        ERROR("failed to lock server config");
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL) {
        ERROR("failed to get server config");
        goto out;
    }

    if (conf->json_confs->cni_bin_dir == NULL) {
        tmp_dir = util_strdup_s(default_bin_dir);
    } else {
        tmp_dir = util_strdup_s(conf->json_confs->cni_bin_dir);
    }
    if (util_clean_path(tmp_dir, cleaned, sizeof(cleaned)) == NULL) {
        ERROR("Can not clean path: %s", tmp_dir);
        goto out;
    }
    res = util_strdup_s(cleaned);

out:
    free(tmp_dir);
    if (isulad_server_conf_unlock()) {
        ERROR("failed to unlock server config");
        free(res);
        res = NULL;
    }
    return res;
}

static int load_cni_list_from_file(const char *file, cni_net_conf_list **list)
{
    int ret = 0;
    int nret = 0;
    struct network_config_list *file_list = NULL;
    struct network_config *file_conf = NULL;

    if (util_has_suffix(file, ".conflist")) {
        nret = conflist_from_file(file, &file_list);
        if (nret != 0) {
            WARN("Failed to load config list from file %s", file);
            goto out;
        }
        if (file_list == NULL || file_list->list == NULL) {
            goto out;
        }
    } else {
        nret = conf_from_file(file, &file_conf);
        if (nret != 0) {
            WARN("Failed to load config from file %s", file);
            goto out;
        }
        if (file_conf == NULL || file_conf->network == NULL) {
            goto out;
        }

        nret = conflist_from_conf(file_conf, &file_list);
        if (nret != 0) {
            ERROR("Failed to get conflist from conf");
            ret = -1;
            goto out;
        }
        if (file_list == NULL || file_list->list == NULL) {
            goto out;
        }
    }
    *list = file_list->list;
    file_list->list = NULL;

out:
    free_network_config_list(file_list);
    free_network_config(file_conf);
    return ret;
}

static int load_cni_list(const char *cni_conf_dir, cni_net_conf_list ***list, size_t *len)
{
    int ret = 0;
    size_t i = 0;
    size_t list_len = 0;
    size_t files_len = 0;
    size_t old_size, new_size;
    char **files = NULL;
    const char *exts[] = { ".conf", ".conflist", ".json" };
    cni_net_conf_list **list_arr = NULL;
    cni_net_conf_list *tmp = NULL;

    ret = conf_files(cni_conf_dir, exts, sizeof(exts) / sizeof(char *), &files);
    if (ret != 0) {
        ERROR("get conf files failed");
        return -1;
    }

    files_len = util_array_len((const char **)files);
    if (files_len == 0) {
        return 0;
    }

    list_arr = util_smart_calloc_s(sizeof(struct network_config_list *), files_len);
    if (list_arr == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < files_len; i++) {
        ret = load_cni_list_from_file(files[i], &tmp);
        if (ret != 0) {
            goto out;
        }
        if (tmp == NULL) {
            continue;
        }
        list_arr[list_len] = tmp;
        list_len++;
        tmp = NULL;
    }

    if (files_len != list_len) {
        if (list_len == 0) {
            goto out;
        }

        old_size = files_len * sizeof(cni_net_conf_list *);
        new_size = list_len * sizeof(cni_net_conf_list *);
        ret = util_mem_realloc((void **)&list_arr, new_size, list_arr, old_size);
        if (ret != 0) {
            ERROR("Out of memory");
            goto out;
        }
    }
    *list = list_arr;
    list_arr = NULL;
    *len = list_len;
    list_len = 0;

out:
    util_free_array_by_len(files, files_len);
    for (i = 0; i < list_len; i++) {
        free_cni_net_conf_list(list_arr[i]);
    }
    free(list_arr);
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
        if (plugin == NULL || strcmp(plugin->type, default_driver) != 0 || plugin->bridge == NULL) {
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
    cni_net_conf *plugin = NULL;

    if (list->plugins == NULL) {
        return 0;
    }

    for (i = 0; i < list->plugins_len; i++) {
        plugin = list->plugins[i];
        if (plugin == NULL || plugin->ipam == NULL || plugin->ipam->subnet == NULL) {
            continue;
        }
        nret = util_array_append(arr, plugin->ipam->subnet);
        if (nret != 0) {
            return -1;
        }
    }

    return 0;
}

static int get_cni_config(const cni_net_conf_list **list_arr, const size_t list_arr_len,
                          get_config_callback cb, char***arr)
{
    int nret = 0;
    size_t i;

    if (list_arr == NULL || list_arr_len == 0) {
        return 0;
    }

    for (i = 0; i < list_arr_len; i++) {
        if (list_arr[i] == NULL) {
            continue;
        }

        nret = cb(list_arr[i], arr);
        if (nret != 0) {
            util_free_array(*arr);
            *arr = NULL;
            return -1;
        }
    }

    return 0;
}

static int get_host_net_name(char ***host_net_names)
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
        ret = util_array_append(host_net_names, ifa->ifa_name);
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
        ERROR("Parse CIDR failed");
        return -1;
    }

    len = util_array_len(subnets);
    for (i = 0; i < len; i++) {
        ret = parse_cidr(subnets[i], &tmp);
        if (ret != 0 || tmp == NULL) {
            ERROR("Parse CIDR failed");
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

static int check_conflict(const network_create_request *request, const cni_net_conf_list **list_arr,
                          const size_t list_arr_len)
{
    int ret = 0;
    char **net_names = NULL;
    char **subnets = NULL;
    char **hostIP = NULL;

    if (request->name != NULL) {
        ret = get_cni_config(list_arr, list_arr_len, get_config_net_name, &net_names);
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

    ret = get_cni_config(list_arr, list_arr_len, get_config_subnet, &subnets);
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

static int find_bridge_name(const cni_net_conf_list **list_arr, const size_t list_arr_len, char **bridge)
{
    int ret = 0;
    int i = 0;
    char *num = NULL;
    char *name = NULL;
    char **net_names = NULL;
    char **bridge_names = NULL;
    char **host_net_names = NULL;
    const char *bridge_name_prefix = "isula-cni";

    ret = get_cni_config(list_arr, list_arr_len, get_config_net_name, &net_names);
    if (ret != 0) {
        return -1;
    }

    ret = get_cni_config(list_arr, list_arr_len, get_config_bridge_name, &bridge_names);
    if (ret != 0) {
        goto out;
    }

    ret = get_host_net_name(&host_net_names);
    if (ret != 0) {
        goto out;
    }

    for (i = 0; i < MAX_BRIDGE_ID; i++) {
        free(name);
        name = NULL;
        free(num);
        num = NULL;

        num = util_int_to_string(i);
        if (num == NULL) {
            ret = ECOMMON;
            goto out;
        }
        name = util_string_append(num, bridge_name_prefix);
        if (name == NULL) {
            ret = ECOMMON;
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
        *bridge = name;
        name = NULL;
        ret = 0;
        goto out;
    }
    ret = -1;
    isulad_set_error_message("Too many network bridges");

out:
    free(num);
    free(name);
    util_free_array(net_names);
    util_free_array(bridge_names);
    util_free_array(host_net_names);
    return ret;
}

static int next_net(char **net)
{
    int ret = 0;
    int i = 0;
    struct ipnet *ipnet = NULL;
    uint32_t ip = 0;
    uint32_t mask = 0;

    if (net == NULL) {
        return -1;
    }

    ret = parse_cidr(*net, &ipnet);
    if (ret != 0 || ipnet == NULL) {
        ERROR("Parse IP failed");
        return -1;
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

    free(*net);
    *net = ipnet_to_string(ipnet);
    if (*net == NULL) {
        ret = -1;
    }

    free_ipnet_type(ipnet);
    return ret;
}

static int find_subnet(const cni_net_conf_list **list_arr, const size_t list_arr_len, char **subnet)
{
    int ret = 0;
    size_t i = 0;
    char *tmp_subnet = NULL;
    char **subnets = NULL;
    char **hostIP = NULL;
    const char *default_subnet = "192.201.1.0/24";

    ret = get_cni_config(list_arr, list_arr_len, get_config_subnet, &subnets);
    if (ret != 0) {
        return -1;
    }

    ret = get_host_net_ip(&hostIP);
    if (ret != 0) {
        goto out;
    }

    tmp_subnet = util_strdup_s(default_subnet);
    for (i = 0; i < MAX_SUBNET_INCREASE; i++) {
        ret = check_subnet_available(tmp_subnet, (const char **)subnets, (const char **)hostIP);
        if (ret == 0) {
            *subnet = tmp_subnet;
            tmp_subnet = NULL;
            ret = 0;
            goto out;
        }
        if (ret != 1) {
            goto out;
        }
        ret = next_net(&tmp_subnet);
        if (ret != 0) {
            goto out;
        }
    }
    ret = -1;
    isulad_set_error_message("Cannot find avaliable subnet by default");

out:
    util_free_array(subnets);
    util_free_array(hostIP);
    free(tmp_subnet);
    return ret;
}

static int find_gateway(const char *subnet, char **gateway)
{
    int ret = 0;
    size_t i = 0;
    uint8_t *first_ip = NULL;
    struct ipnet *ipnet = NULL;

    ret = parse_cidr(subnet, &ipnet);
    if (ret != 0 || ipnet == NULL) {
        ERROR("Parse IP failed");
        return -1;
    }

    first_ip = util_smart_calloc_s(sizeof(uint8_t), ipnet->ip_len);
    if (first_ip == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (ipnet->ip_mask[ipnet->ip_mask_len - 1] == 0xff) {
        isulad_set_error_message("No avaliable gateway in %s", subnet);
        ret = -1;
        goto out;
    }

    for (i = 0; i < ipnet->ip_len; i++) {
        first_ip[i] = ipnet->ip[i] & ipnet->ip_mask[i];
    }
    first_ip[ipnet->ip_len - 1] = first_ip[ipnet->ip_len - 1] | 0x01;
    *gateway = ip_to_string(first_ip, ipnet->ip_len);

out:
    free_ipnet_type(ipnet);
    free(first_ip);
    return ret;
}

static int conf_net_ipam(const network_create_request *request, const cni_net_conf_list **list_arr,
                         const size_t list_arr_len, cni_net_conf_ipam **ipam)
{
    int ret = 0;
    cni_net_conf_ipam *tmp_ipam = NULL;

    tmp_ipam = util_common_calloc_s(sizeof(cni_net_conf_ipam));
    if (tmp_ipam == NULL) {
        ERROR("Out of memory");
        return ECOMMON;
    }

    tmp_ipam->type = util_strdup_s("host-local");
    tmp_ipam->routes = util_common_calloc_s(sizeof(cni_network_route *));
    if (tmp_ipam->routes == NULL) {
        ERROR("Out of memory");
        ret = ECOMMON;
        goto err_out;
    }
    tmp_ipam->routes[0] = util_common_calloc_s(sizeof(cni_network_route));
    if (tmp_ipam->routes[0] == NULL) {
        ERROR("Out of memory");
        ret = ECOMMON;
        goto err_out;
    }
    tmp_ipam->routes_len++;
    tmp_ipam->routes[0]->dst = util_strdup_s("0.0.0.0/0");

    if (request->subnet != NULL) {
        tmp_ipam->subnet = util_strdup_s(request->subnet);
    } else {
        ret = find_subnet(list_arr, list_arr_len, &(tmp_ipam->subnet));
        if (ret != 0) {
            ERROR("Failed to find available subnet");
            goto err_out;
        }
    }

    if (request->gateway != NULL) {
        tmp_ipam->gateway = util_strdup_s(request->gateway);
    } else {
        ret = find_gateway(tmp_ipam->subnet, &(tmp_ipam->gateway));
        if (ret != 0) {
            ERROR("Failed to find gateway");
            goto err_out;
        }
    }

    *ipam = tmp_ipam;
    return ret;

err_out:
    free_cni_net_conf_ipam(tmp_ipam);
    return ret;
}

static cni_net_conf *conf_bridge_plugin(const network_create_request *request, const cni_net_conf_list **list_arr,
                                        const size_t list_arr_len)
{
    int nret = 0;
    cni_net_conf *plugin = NULL;

    plugin = util_common_calloc_s(sizeof(cni_net_conf));
    if (plugin == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (request->driver == NULL) {
        plugin->type = util_strdup_s(default_driver);
    } else {
        plugin->type = util_strdup_s(request->driver);
    }

    nret = find_bridge_name(list_arr, list_arr_len, &(plugin->bridge));
    if (nret != 0) {
        ERROR("Failed to find bridge name");
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

    nret = conf_net_ipam(request, list_arr, list_arr_len, &(plugin->ipam));
    if (nret != 0) {
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

static int conf_network_list(const network_create_request *request, const cni_net_conf_list **list_arr,
                             const size_t list_arr_len, cni_net_conf_list **network_list)
{
#define PLUGINS_LEN 3   // plugins: driver portmap firewall
    int ret = 0;
    cni_net_conf *plugin = NULL;
    cni_net_conf_list *list = NULL;

    list = util_common_calloc_s(sizeof(cni_net_conf_list));
    if (list == NULL) {
        ERROR("Out of memory");
        return ECOMMON;
    }

    list->plugins = (cni_net_conf **)util_smart_calloc_s(sizeof(cni_net_conf *), PLUGINS_LEN);
    if (list->plugins == NULL) {
        ERROR("Out of memory");
        ret = ECOMMON;
        goto err_out;
    }

    plugin = conf_bridge_plugin(request, (const cni_net_conf_list **)list_arr, list_arr_len);
    if (plugin == NULL) {
        ERROR("Failed to config bridge plugin");
        ret = ECOMMON;
        goto err_out;
    }
    list->plugins[list->plugins_len] = plugin;
    list->plugins_len++;

    plugin = conf_portmap_plugin(request);
    if (plugin == NULL) {
        ERROR("Failed to config portmap plugin");
        ret = ECOMMON;
        goto err_out;
    }
    list->plugins[list->plugins_len] = plugin;
    list->plugins_len++;

    plugin = conf_firewall_plugin(request);
    if (plugin == NULL) {
        ERROR("Failed to config firewall plugin");
        ret = ECOMMON;
        goto err_out;
    }
    list->plugins[list->plugins_len] = plugin;
    list->plugins_len++;
    plugin = NULL;

    list->cni_version = util_strdup_s(CURRENT_VERSION);
    if (request->name != NULL) {
        list->name = util_strdup_s(request->name);
    } else {
        list->name = util_strdup_s(list->plugins[0]->bridge);
    }

    *network_list = list;
    return ret;

err_out:
    free_cni_net_conf_list(list);
    return ret;
}

static int plugin_exist(const char *cni_bin_dir)
{
    int ret = 0;
    size_t len = 0;
    size_t i = 0;
    const char *plugin[] = { "bridge", "portmap", "firewall", NULL };
    char *plugin_file = NULL;
    char *tmp = NULL;
    char **missing_file = NULL;

    if (!util_dir_exists(cni_bin_dir)) {
        isulad_set_error_message("WARN:cni plugin dir \"%s\" doesn't exist", cni_bin_dir);
        return 0;
    }

    len = util_array_len(plugin);
    for (i = 0; i < len; i++) {
        plugin_file = util_path_join(cni_bin_dir, plugin[i]);
        if (plugin_file == NULL) {
            return -1;
        }
        if (!util_file_exists(plugin_file)) {
            ret = util_array_append(&missing_file, plugin[i]);
            if (ret != 0) {
                free(plugin_file);
                ERROR("Out of memory");
                goto out;
            }
        }
        free(plugin_file);
        plugin_file = NULL;
    }

    if (missing_file == NULL) {
        return ret;
    }

    len = util_array_len((const char **)missing_file);
    tmp = util_string_join(", ", (const char **)missing_file, len);
    if (tmp == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    isulad_set_error_message("WARN:cni plugin \"%s\" doesn't exist in dir %s", tmp, cni_bin_dir);
    free(tmp);

out:
    util_free_array(missing_file);
    return ret;
}

static int do_create_network_conf(const char *cni_conf_dir, cni_net_conf_list *list, char **path)
{
    int ret = 0;
    char *conflist_json = NULL;
    char conflist_file[PATH_MAX] = { 0x00 };
    parser_error err = NULL;

    if (!util_dir_exists(cni_conf_dir)) {
        ret = util_mkdir_p(cni_conf_dir, CONFIG_DIRECTORY_MODE);
        if (ret != 0) {
            ERROR("Failed to create network config directory %s", cni_conf_dir);
            return -1;
        }
    }

    ret = snprintf(conflist_file, sizeof(conflist_file), "%s/%s.conflist", cni_conf_dir, list->name);
    if ((size_t)ret >= sizeof(conflist_file) || ret < 0) {
        return -1;
    }

    conflist_json = cni_net_conf_list_generate_json(list, NULL, &err);
    if (conflist_json == NULL) {
        ERROR("Failed to generate conf list json: %s", err);
        return -1;
    }

    if (util_atomic_write_file(conflist_file, conflist_json, strlen(conflist_json), CONFIG_FILE_MODE) != 0) {
        ERROR("Failed write %s", conflist_file);
        ret = -1;
        goto out;
    }

    EVENT("Event: {Object: network %s, Type: create}", list->name);
    *path = util_strdup_s(conflist_file);

out:
    free(conflist_json);
    free(err);
    return 0;
}

static void free_cni_list_arr(cni_net_conf_list **list_arr, size_t list_arr_len)
{
    size_t i;

    if (list_arr == NULL) {
        return;
    }
    for (i = 0; i < list_arr_len; i++) {
        free_cni_net_conf_list(list_arr[i]);
    }
    free(list_arr);
}

static int network_create_cb(const network_create_request *request, network_create_response **response)
{
    int ret = 0;
    size_t list_arr_len = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *cni_bin_dir = NULL;
    char *cni_conf_dir = NULL;
    cni_net_conf_list *list = NULL;
    cni_net_conf_list **list_arr = NULL;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    DAEMON_CLEAR_ERRMSG();
    *response = util_common_calloc_s(sizeof(network_create_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return ECOMMON;
    }

    ret = check_parameter(request);
    if (ret != 0) {
        cc = ISULAD_ERR_INPUT;
        goto out;
    }

    cni_conf_dir = get_cni_conf_dir();
    if (cni_conf_dir == NULL) {
        cc = ISULAD_ERR_EXEC;
        ret = ECOMMON;
        goto out;
    }

    network_list_lock(EXCLUSIVE);
    ret = load_cni_list(cni_conf_dir, &list_arr, &list_arr_len);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        goto unlock_out;
    }

    ret = check_conflict(request, (const cni_net_conf_list **)list_arr, list_arr_len);
    if (ret != 0) {
        cc = ISULAD_ERR_INPUT;
        goto unlock_out;
    }

    // TODO: support other drivers
    ret = conf_network_list(request, (const cni_net_conf_list **)list_arr, list_arr_len, &list);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        goto unlock_out;
    }

    ret = do_create_network_conf(cni_conf_dir, list, &(*response)->path);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        goto unlock_out;
    }
    network_list_unlock();

    cni_bin_dir = get_cni_bin_dir();
    if (cni_bin_dir == NULL) {
        cc = ISULAD_ERR_EXEC;
        ret = ECOMMON;
        goto out;
    }

    ret = plugin_exist(cni_bin_dir);
    if (ret != 0) {
        cc = ISULAD_ERR_MEMOUT;
    }
    goto out;

unlock_out:
    network_list_unlock();

out:
    free(cni_bin_dir);
    free(cni_conf_dir);
    free_cni_net_conf_list(list);
    free_cni_list_arr(list_arr, list_arr_len);

    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }
    return ret;
}

static int network_inspect_cb(const network_inspect_request *request, network_inspect_response **response)
{
    // TODO
    return 0;
}

static int network_list_cb(const network_list_request *request, network_list_response **response)
{
    // TODO
    return 0;
}

static int network_remove_cb(const network_remove_request *request, network_remove_response **response)
{
    // TODO
    return 0;
}

void network_callback_init(service_network_callback_t *cb)
{
    cb->create = network_create_cb;
    cb->inspect = network_inspect_cb;
    cb->list = network_list_cb;
    cb->remove = network_remove_cb;
}
