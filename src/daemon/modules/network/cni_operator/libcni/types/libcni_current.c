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
 * Description: provide result functions
 ********************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "libcni_current.h"
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "isula_libutils/log.h"

static cni_result_curr *new_curr_result_helper(const char *json_data)
{
    cni_result_curr *result = NULL;
    parser_error errmsg = NULL;

    if (json_data == NULL) {
        ERROR("Json data is NULL");
        return NULL;
    }
    result = cni_result_curr_parse_data(json_data, NULL, &errmsg);
    if (result == NULL) {
        ERROR("Parse failed: %s", errmsg);
        goto free_out;
    }
    return result;

free_out:
    free(errmsg);
    return NULL;
}

struct result *new_curr_result(const char *json_data)
{
    struct result *ret = NULL;
    cni_result_curr *tmp_result = NULL;

    if (json_data == NULL) {
        ERROR("empty result json");
        return NULL;
    }
    tmp_result = new_curr_result_helper(json_data);
    if (tmp_result == NULL) {
        return NULL;
    }

    ret = copy_result_from_current(tmp_result);

    free_cni_result_curr(tmp_result);
    return ret;
}

static struct interface *convert_curr_interface(const cni_network_interface *curr_interface)
{
    struct interface *result = NULL;

    if (curr_interface == NULL) {
        ERROR("Invalid argument");
        return NULL;
    }

    result = util_common_calloc_s(sizeof(struct interface));
    if (result == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    result->name = util_strdup_s(curr_interface->name);
    result->mac = util_strdup_s(curr_interface->mac);
    result->sandbox = util_strdup_s(curr_interface->sandbox);
    return result;
}

static int do_parse_ipnet(const char *cidr_str, const char *ip_str, uint8_t **ip, size_t *ip_len,
                          struct ipnet **ipnet_val)
{
    int ret = 0;

    ret = parse_cidr(cidr_str, ipnet_val);
    if (ret != 0) {
        ERROR("Parse cidr: %s failed", cidr_str);
        return -1;
    }
    if (ip_str == NULL) {
        return 0;
    }
    ret = parse_ip_from_str(ip_str, ip, ip_len);
    if (ret != 0) {
        ERROR("Parse ip: %s failed", ip_str);
        free_ipnet_type(*ipnet_val);
        *ipnet_val = NULL;
        return -1;
    }
    return 0;
}

static struct ipconfig *convert_curr_ipconfig(const cni_network_ipconfig *curr_ipconfig)
{
    struct ipconfig *result = NULL;
    struct ipnet *ipnet_val = NULL;
    int ret = 0;
    uint8_t *gateway = NULL;
    size_t gateway_len = 0;

    if (curr_ipconfig == NULL) {
        ERROR("Invalid argument");
        return NULL;
    }

    result = util_common_calloc_s(sizeof(struct ipconfig));
    if (result == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    /* parse address to ipnet */
    ret = do_parse_ipnet(curr_ipconfig->address, curr_ipconfig->gateway, &gateway, &gateway_len, &ipnet_val);
    if (ret != 0) {
        goto err_out;
    }
    result->address = ipnet_val;
    result->gateway = gateway;
    result->gateway_len = gateway_len;
    result->version = util_strdup_s(curr_ipconfig->version);

    if (curr_ipconfig->interface != NULL) {
        result->interface = util_common_calloc_s(sizeof(int32_t));
        if (result->interface == NULL) {
            ERROR("Out of memory");
            goto err_out;
        }
        *(result->interface) = *(curr_ipconfig->interface);
    }

    return result;

err_out:
    free_ipconfig_type(result);
    return NULL;
}

static struct route *convert_curr_route(const cni_network_route *curr_route)
{
    struct route *result = NULL;
    struct ipnet *dst = NULL;
    int ret = 0;
    uint8_t *gw = NULL;
    size_t gw_len = 0;

    if (curr_route == NULL) {
        ERROR("Invalid argument");
        return NULL;
    }
    ret = do_parse_ipnet(curr_route->dst, curr_route->gw, &gw, &gw_len, &dst);
    if (ret != 0) {
        return NULL;
    }

    result = util_common_calloc_s(sizeof(struct route));
    if (result == NULL) {
        ERROR("Out of memory");
        free(gw);
        free_ipnet_type(dst);
        return NULL;
    }

    result->dst = dst;
    result->gw = gw;
    result->gw_len = gw_len;

    return result;
}

static struct dns *convert_curr_dns(cni_network_dns *curr_dns)
{
    struct dns *result = NULL;

    if (curr_dns == NULL) {
        ERROR("Empty dns argument");
        return NULL;
    }

    result = util_common_calloc_s(sizeof(struct dns));
    if (result == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    result->name_servers = curr_dns->nameservers;
    result->name_servers_len = curr_dns->nameservers_len;
    result->domain = curr_dns->domain;
    result->options = curr_dns->options;
    result->options_len = curr_dns->options_len;
    result->search = curr_dns->search;
    result->search_len = curr_dns->search_len;

    (void)memset(curr_dns, 0, sizeof(cni_network_dns));

    return result;
}

static int copy_result_interface(const cni_result_curr *curr_result, struct result *value)
{
    value->interfaces_len = curr_result->interfaces_len;
    if (value->interfaces_len > 0) {
        value->interfaces = util_smart_calloc_s(value->interfaces_len, sizeof(struct interface *));
        if (value->interfaces == NULL) {
            value->interfaces_len = 0;
            ERROR("Out of memory");
            return -1;
        }
        size_t i;
        for (i = 0; i < curr_result->interfaces_len; i++) {
            value->interfaces[i] = convert_curr_interface(curr_result->interfaces[i]);
            if (value->interfaces[i] == NULL) {
                value->interfaces_len = i;
                ERROR("Convert interfaces failed");
                return -1;
            }
        }
    }
    return 0;
}

static int copy_result_ips(const cni_result_curr *curr_result, struct result *value)
{
    size_t i = 0;
    value->ips_len = curr_result->ips_len;

    if (value->ips_len == 0) {
        return 0;
    }

    value->ips = util_smart_calloc_s(value->ips_len, sizeof(struct ipconfig *));
    if (value->ips == NULL) {
        ERROR("Out of memory");
        value->ips_len = 0;
        return -1;
    }

    for (i = 0; i < value->ips_len; i++) {
        value->ips[i] = convert_curr_ipconfig(curr_result->ips[i]);
        if (value->ips[i] == NULL) {
            value->ips_len = i;
            return -1;
        }
    }
    return 0;
}

static int copy_result_routes(const cni_result_curr *curr_result, struct result *value)
{
    size_t i = 0;

    value->routes_len = curr_result->routes_len;
    if (value->routes_len == 0) {
        return 0;
    }

    value->routes = util_smart_calloc_s(value->routes_len, sizeof(struct route *));
    if (value->routes == NULL) {
        ERROR("Out of memory");
        value->routes_len = 0;
        return -1;
    }

    for (i = 0; i < value->routes_len; i++) {
        value->routes[i] = convert_curr_route(curr_result->routes[i]);
        if (value->routes[i] == NULL) {
            value->routes_len = i;
            return -1;
        }
    }
    return 0;
}

struct result *copy_result_from_current(const cni_result_curr *curr_result)
{
    struct result *value = NULL;

    if (curr_result == NULL) {
        return NULL;
    }
    value = util_common_calloc_s(sizeof(struct result));
    if (value == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    /* copy cni version */
    value->cniversion = util_strdup_s(curr_result->cni_version);

    /* copy interfaces */
    if (copy_result_interface(curr_result, value) != 0) {
        goto free_out;
    }

    /* copy ips */
    if (copy_result_ips(curr_result, value) != 0) {
        goto free_out;
    }

    /* copy routes */
    if (copy_result_routes(curr_result, value) != 0) {
        goto free_out;
    }

    /* copy dns */
    value->my_dns = convert_curr_dns(curr_result->dns);
    if (value->my_dns == NULL) {
        goto free_out;
    }

    return value;
free_out:
    free_result(value);
    return NULL;
}

static cni_network_interface *interface_to_json_interface(const struct interface *src)
{
    cni_network_interface *result = NULL;

    if (src == NULL) {
        ERROR("Invalid arguments");
        return NULL;
    }

    result = util_common_calloc_s(sizeof(cni_network_interface));
    if (result == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    result->name = util_strdup_s(src->name);
    result->mac = util_strdup_s(src->mac);
    result->sandbox = util_strdup_s(src->sandbox);

    return result;
}

static int parse_ip_and_gateway(const struct ipconfig *src, cni_network_ipconfig *result)
{
    if (src->address != NULL) {
        result->address = ipnet_to_string(src->address);
        if (result->address == NULL) {
            ERROR("Covert ipnet failed");
            return -1;
        }
    }

    if (src->gateway && src->gateway_len > 0) {
        result->gateway = ip_to_string(src->gateway, src->gateway_len);
        if (result->gateway == NULL) {
            ERROR("IP to string failed");
            return -1;
        }
    }
    return 0;
}

static cni_network_ipconfig *ipconfig_to_json_ipconfig(const struct ipconfig *src)
{
    cni_network_ipconfig *result = NULL;
    int ret = -1;

    if (src == NULL) {
        ERROR("Invalid arguments");
        return result;
    }

    result = util_common_calloc_s(sizeof(cni_network_ipconfig));
    if (result == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    /* parse address and ip */
    if (parse_ip_and_gateway(src, result) != 0) {
        goto out;
    }

    if (src->version != NULL) {
        result->version = util_strdup_s(src->version);
    }

    if (src->interface != NULL) {
        result->interface = util_common_calloc_s(sizeof(int32_t));
        if (result->interface == NULL) {
            ERROR("Out of memory");
            goto out;
        }
        *(result->interface) = *(src->interface);
    }

    ret = 0;
out:
    if (ret != 0) {
        free_cni_network_ipconfig(result);
        result = NULL;
    }
    return result;
}

static cni_network_route *route_to_json_route(const struct route *src)
{
    cni_network_route *result = NULL;
    int ret = -1;

    if (src == NULL) {
        ERROR("Invalid arguments");
        return NULL;
    }

    result = (cni_network_route *)util_common_calloc_s(sizeof(cni_network_route));
    if (result == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    if (src->dst != NULL) {
        result->dst = ipnet_to_string(src->dst);
        if (result->dst == NULL) {
            goto out;
        }
    }

    if (src->gw != NULL && src->gw_len > 0) {
        result->gw = ip_to_string(src->gw, src->gw_len);
        if (result->gw == NULL) {
            ERROR("ip to string failed");
            goto out;
        }
    }

    ret = 0;
out:
    if (ret != 0) {
        free_cni_network_route(result);
        result = NULL;
    }
    return result;
}

static int dns_to_json_copy_servers(const struct dns *src, cni_network_dns *result)
{
    size_t i;
    bool need_copy = (src->name_servers != NULL && src->name_servers_len > 0);

    if (!need_copy) {
        return 0;
    }

    result->nameservers = (char **)util_smart_calloc_s(src->name_servers_len, sizeof(char *));
    if (result->nameservers == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    result->nameservers_len = src->name_servers_len;
    for (i = 0; i < src->name_servers_len; i++) {
        result->nameservers[i] = util_strdup_s(src->name_servers[i]);
    }
    return 0;
}

static int dns_to_json_copy_options(const struct dns *src, cni_network_dns *result)
{
    size_t i;
    bool need_copy = (src->options != NULL && src->options_len > 0);

    if (!need_copy) {
        return 0;
    }

    result->options = (char **)util_smart_calloc_s(src->options_len, sizeof(char *));
    if (result->options == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    result->options_len = src->options_len;
    for (i = 0; i < src->options_len; i++) {
        result->options[i] = util_strdup_s(src->options[i]);
    }

    return 0;
}

static int dns_to_json_copy_searchs(const struct dns *src, cni_network_dns *result)
{
    size_t i;
    bool need_copy = (src->search != NULL && src->search_len > 0);

    if (!need_copy) {
        return 0;
    }

    result->search = (char **)util_smart_calloc_s(src->search_len, sizeof(char *));
    if (result->search == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    result->search_len = src->search_len;
    for (i = 0; i < src->search_len; i++) {
        result->search[i] = util_strdup_s(src->search[i]);
    }
    return 0;
}

static int do_copy_dns_configs_to_json(const struct dns *src, cni_network_dns *result)
{
    if (dns_to_json_copy_servers(src, result) != 0) {
        return -1;
    }

    if (dns_to_json_copy_options(src, result) != 0) {
        return -1;
    }

    if (dns_to_json_copy_searchs(src, result) != 0) {
        return -1;
    }
    return 0;
}

static cni_network_dns *dns_to_json_dns(const struct dns *src)
{
    cni_network_dns *result = NULL;
    int ret = -1;

    if (src == NULL) {
        return NULL;
    }

    result = (cni_network_dns *)util_common_calloc_s(sizeof(cni_network_dns));
    if (result == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    if (src->domain != NULL) {
        result->domain = util_strdup_s(src->domain);
    }

    ret = do_copy_dns_configs_to_json(src, result);
out:
    if (ret != 0) {
        free_cni_network_dns(result);
        result = NULL;
    }
    return result;
}

static bool copy_interfaces_from_result_to_json(const struct result *src, cni_result_curr *res)
{
    size_t i = 0;
    bool empty_src = (src->interfaces == NULL || src->interfaces_len == 0);

    if (empty_src) {
        return true;
    }

    res->interfaces_len = 0;

    res->interfaces = (cni_network_interface **)util_smart_calloc_s(src->interfaces_len,
                                                                    sizeof(cni_network_interface *));
    if (res->interfaces == NULL) {
        ERROR("Out of memory");
        return false;
    }
    for (i = 0; i < src->interfaces_len; i++) {
        if (src->interfaces[i] == NULL) {
            continue;
        }
        res->interfaces[i] = interface_to_json_interface(src->interfaces[i]);
        if (res->interfaces[i] == NULL) {
            ERROR("interface to json struct failed");
            return false;
        }
        res->interfaces_len++;
    }
    return true;
}

static bool copy_ips_from_result_to_json(const struct result *src, cni_result_curr *res)
{
    bool need_copy = (src->ips && src->ips_len > 0);

    res->ips_len = 0;
    if (need_copy) {
        res->ips = (cni_network_ipconfig **)util_smart_calloc_s(src->ips_len, sizeof(cni_network_ipconfig *));
        if (res->ips == NULL) {
            ERROR("Out of memory");
            return false;
        }
        size_t i = 0;
        for (i = 0; i < src->ips_len; i++) {
            res->ips[i] = ipconfig_to_json_ipconfig(src->ips[i]);
            if (res->ips[i] == NULL) {
                ERROR("parse ip failed");
                return false;
            }
            res->ips_len++;
        }
    }
    return true;
}

static bool copy_routes_from_result_to_json(const struct result *src, cni_result_curr *res)
{
    bool need_copy = (src->routes && src->routes_len > 0);

    res->routes_len = 0;
    if (need_copy) {
        res->routes = (cni_network_route **)util_smart_calloc_s(src->routes_len, sizeof(cni_network_route *));
        if (res->routes == NULL) {
            ERROR("Out of memory");
            return false;
        }
        size_t i = 0;
        for (i = 0; i < src->routes_len; i++) {
            res->routes[i] = route_to_json_route(src->routes[i]);
            if (res->routes[i] == NULL) {
                ERROR("Parse route failed");
                return false;
            }
            res->routes_len++;
        }
    }
    return true;
}

static int do_result_copy_configs_to_json(const struct result *src, cni_result_curr *res)
{
    /* copy interfaces */
    if (!copy_interfaces_from_result_to_json(src, res)) {
        return -1;
    }

    /* copy ips */
    if (!copy_ips_from_result_to_json(src, res)) {
        return -1;
    }

    /* copy routes */
    if (!copy_routes_from_result_to_json(src, res)) {
        return -1;
    }

    /* copy dns */
    if (src->my_dns != NULL) {
        res->dns = dns_to_json_dns(src->my_dns);
        if (res->dns == NULL) {
            return -1;
        }
    }

    return 0;
}

cni_result_curr *cni_result_curr_to_json_result(const struct result *src)
{
    cni_result_curr *res = NULL;
    int ret = -1;

    if (src == NULL) {
        ERROR("Invalid arguments");
        return res;
    }

    res = (cni_result_curr *)util_common_calloc_s(sizeof(cni_result_curr));
    if (res == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    /* copy cni version */
    if (src->cniversion != NULL) {
        res->cni_version = util_strdup_s(src->cniversion);
    }

    ret = do_result_copy_configs_to_json(src, res);
out:
    if (ret != 0) {
        free_cni_result_curr(res);
        res = NULL;
    }
    return res;
}

