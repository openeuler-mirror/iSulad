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
 * Description: provide types functions
 *********************************************************************************/
#define _GNU_SOURCE /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "isula_libutils/log.h"
#include "libcni_types.h"
#include "utils.h"

#define IPV4_TO_V6_EMPTY_PREFIX_BYTES 12

void free_ipnet_type(struct ipnet *val)
{
    if (val == NULL) {
        return;
    }
    free(val->ip);
    val->ip = NULL;
    free(val->ip_mask);
    val->ip_mask = NULL;
    free(val);
}

void free_ipconfig_type(struct ipconfig *ipc)
{
    if (ipc == NULL) {
        return;
    }
    free(ipc->gateway);
    ipc->gateway = NULL;
    free(ipc->version);
    ipc->version = NULL;
    free_ipnet_type(ipc->address);
    ipc->address = NULL;
    free(ipc->interface);
    ipc->interface = NULL;
    free(ipc);
}

void free_route_type(struct route *val)
{
    if (val == NULL) {
        return;
    }
    free(val->gw);
    val->gw = NULL;
    free_ipnet_type(val->dst);
    val->dst = NULL;
    free(val);
}

void free_interface_type(struct interface *val)
{
    if (val == NULL) {
        return;
    }
    free(val->mac);
    val->mac = NULL;
    free(val->name);
    val->name = NULL;
    free(val->sandbox);
    val->sandbox = NULL;
    free(val);
}

void free_dns_type(struct dns *val)
{
    size_t i = 0;
    if (val == NULL) {
        return;
    }
    free(val->domain);
    val->domain = NULL;
    for (i = 0; i < val->name_servers_len; i++) {
        free(val->name_servers[i]);
        val->name_servers[i] = NULL;
    }
    free(val->name_servers);
    val->name_servers = NULL;
    for (i = 0; i < val->options_len; i++) {
        free(val->options[i]);
        val->options[i] = NULL;
    }
    free(val->options);
    val->options = NULL;
    for (i = 0; i < (val->search_len); i++) {
        free(val->search[i]);
        val->search[i] = NULL;
    }
    free(val->search);
    val->search = NULL;
    free(val);
}

void free_result(struct result *val)
{
    size_t i = 0;

    if (val == NULL) {
        return;
    }

    free(val->cniversion);
    val->cniversion = NULL;
    for (i = 0; i < val->interfaces_len; i++) {
        free_interface_type(val->interfaces[i]);
        val->interfaces[i] = NULL;
    }
    free(val->interfaces);
    val->interfaces = NULL;
    for (i = 0; i < val->ips_len; i++) {
        free_ipconfig_type(val->ips[i]);
        val->ips[i] = NULL;
    }
    free(val->ips);
    val->ips = NULL;
    for (i = 0; i < val->routes_len; i++) {
        free_route_type(val->routes[i]);
        val->routes[i] = NULL;
    }
    free(val->routes);
    val->routes = NULL;
    free_dns_type(val->my_dns);
    val->my_dns = NULL;
    free(val);
}

static inline bool check_clibcni_util_uint8_join_args(const char *sep, const uint8_t *parts, size_t len)
{
    return (sep == NULL || strlen(sep) == 0 || len == 0 || parts == NULL);
}

static char *do_uint8_join(const char *sep, const char *type, const uint8_t *parts, size_t parts_len, size_t result_len)
{
#define MAX_UINT_LEN 3
    char *res_string = NULL;
    size_t iter = 0;
    char buffer[MAX_UINT_LEN + 1] = { 0 };
    int nret = 0;

    if (result_len > (SIZE_MAX - 1)) {
        ERROR("Large string");
        return NULL;
    }

    res_string = util_common_calloc_s(result_len + 1);
    if (res_string == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (iter = 0; iter < parts_len - 1; iter++) {
        nret = snprintf(buffer, MAX_UINT_LEN + 1, type, parts[iter]);
        if (nret < 0 || nret >= MAX_UINT_LEN + 1) {
            ERROR("Sprint failed");
            free(res_string);
            return NULL;
        }
        (void)strcat(res_string, buffer);
        (void)strcat(res_string, sep);
    }
    nret = snprintf(buffer, sizeof(buffer), type, parts[parts_len - 1]);
    if (nret < 0 || nret >= MAX_UINT_LEN + 1) {
        ERROR("Sprint failed");
        free(res_string);
        return NULL;
    }
    (void)strcat(res_string, buffer);

    return res_string;
}

static char *clibcni_util_uint8_join(const char *sep, const char *type, const uint8_t *parts, size_t len)
{
    size_t sep_len = 0;
    size_t result_len = 0;

    if (check_clibcni_util_uint8_join_args(sep, parts, len)) {
        ERROR("Invalid arguments");
        return NULL;
    }

    sep_len = strlen(sep);
    if (len > SIZE_MAX / sep_len) {
        ERROR("Large string");
        return NULL;
    }
    result_len = (len - 1) * sep_len;

    if (len > SIZE_MAX / MAX_UINT_LEN) {
        ERROR("Large string");
        return NULL;
    }
    result_len += (MAX_UINT_LEN * len);

    return do_uint8_join(sep, type, parts, len, result_len);
}

static bool is_ipv4(const uint8_t *ip, size_t len)
{
    size_t i = 0;
    bool invalid_arg = (ip == NULL || len < 10);

    if (invalid_arg) {
        return false;
    }
    for (i = 0; i < 10; i++) {
        if (ip[i] != 0) {
            return false;
        }
    }

    return true;
}

static int simple_mask_len(const uint8_t *mask, size_t len)
{
    size_t i = 0;
    int ret = 0;

    for (i = 0; i < len; i++) {
        uint8_t work = mask[i];
        if (work == 0xff) {
            ret += 8;
            continue;
        }

        while ((work & 0x80) != 0) {
            ret++;
            work <<= 1;
        }

        if (work != 0) {
            return -1;
        }

        size_t j = i;
        for (j++; j < len; j++) {
            if (mask[j] != 0) {
                return -1;
            }
        }
        break;
    }
    return ret;
}

static size_t to_ipv4(const uint8_t *src, size_t src_len, uint8_t **ipv4)
{
    uint8_t *ip = NULL;
    bool invalid_arg = (src == NULL || ipv4 == NULL);

    if (invalid_arg) {
        return 0;
    }
    if (src_len == IPV4LEN) {
        ip = util_smart_calloc_s(IPV4LEN, sizeof(uint8_t));
        if (ip == NULL) {
            return 0;
        }
        (void)memcpy(ip, src, IPV4LEN);
        *ipv4 = ip;
        return IPV4LEN;
    }

    if (src_len == IPV6LEN && is_ipv4(src, src_len) && src[10] == 0xff && src[11] == 0xff) {
        ip = util_smart_calloc_s(IPV4LEN, sizeof(uint8_t));
        if (ip == NULL) {
            return 0;
        }
        size_t i = 0;
        for (i = 0; i < IPV4LEN; i++) {
            ip[i] = src[i + 12];
        }
        *ipv4 = ip;
        return IPV4LEN;
    }
    return 0;
}

// IPV6 max address "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
#define IPV6_MAX_ADDR_LEN 40
const char g_HEX_DICT[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

/*
 * return:
 *    0 means continue to find ip
 *    1 means get right ip
 *    -1 means something wrong
 * */
static int do_parse_ip_to_string(const uint8_t *ip, size_t len, char **result)
{
    char *tmp = NULL;
    int ret = 0;
    int nret = 0;
    size_t res_len = 0;

    tmp = clibcni_util_uint8_join("", "%x", ip, len);
    if (tmp == NULL) {
        return -1;
    }

    if (strlen(tmp) > (SIZE_MAX - 2)) {
        ret = -1;
        goto free_out;
    }

    res_len = 1 + strlen(tmp) + 1;
    *result = util_common_calloc_s(res_len);
    if (*result == NULL) {
        ret = -1;
        goto free_out;
    }
    nret = snprintf(*result, res_len, "%s%s", "?", tmp);
    if (nret < 0 || (size_t)nret >= res_len) {
        free(*result);
        *result = NULL;
        ret = -1;
    } else {
        ret = 1;
    }

free_out:
    free(tmp);
    return ret;
}

static int get_ip_string(const uint8_t *ip, size_t len, char **result)
{
    size_t work_ip_len = 0;
    uint8_t *work_ip = NULL;
    int ret = 0;

    work_ip_len = to_ipv4(ip, len, &work_ip);
    if (work_ip_len == IPV4LEN) {
        *result = clibcni_util_uint8_join(".", "%u", work_ip, work_ip_len);
        ret = 1; // get right result
        goto free_out;
    }
    if (len != IPV6LEN) {
        ret = do_parse_ip_to_string(ip, len, result);
    }

free_out:
    free(work_ip);
    return ret;
}

static void generate_ip_string(const uint8_t *ip, int e0, int e1, char **result)
{
    int i = 0;
    int j = 0;

    *result = util_common_calloc_s(IPV6_MAX_ADDR_LEN);
    if (*result == NULL) {
        return;
    }
    for (i = 0, j = 0; i < IPV6LEN; i += 2) {
        if (i == e0) {
            (*result)[j++] = ':';
            (*result)[j++] = ':';
            i = e1;
            if (i >= IPV6LEN) {
                break;
            }
        } else if (i > 0) {
            (*result)[j++] = ':';
        }
        int nret = (ip[i] >> 4);
        (*result)[j++] = g_HEX_DICT[nret];
        nret = (ip[i] & 0x0f);
        (*result)[j++] = g_HEX_DICT[nret];
        nret = (ip[i + 1] >> 4);
        (*result)[j++] = g_HEX_DICT[nret];
        nret = (ip[i + 1] & 0x0f);
        (*result)[j++] = g_HEX_DICT[nret];
    }
    return;
}

char *ip_to_string(const uint8_t *ip, size_t len)
{
    char *result = NULL;
    int i = 0;
    int j = 0;
    int e0 = 0;
    int e1 = 0;

    if (len == 0) {
        return util_strdup_s("<nil>");
    }

    if (get_ip_string(ip, len, &result) != 0) {
        goto free_out;
    }

    /* find zeros */
    e0 = e1 = -1;
    for (i = 0; i < IPV6LEN; i += 2) {
        j = i;
        while (j < IPV6LEN && ip[j] == 0 && ip[j + 1] == 0) {
            j += 2;
        }
        if (j > i && (j - i) > (e1 - e0)) {
            e0 = i;
            e1 = j;
            i = j;
        }
    }

    if (e1 - e0 <= 2) {
        e1 = -1;
        e0 = -1;
    }

    generate_ip_string(ip, e0, e1, &result);

free_out:
    return result;
}

static char *mask_hex_string(const uint8_t *mask, size_t len)
{
    char *result = NULL;
    size_t res_len = 0;
    size_t i = 0;
    size_t j = 0;

    if (len == 0) {
        return util_strdup_s("<nil>");
    }

    if (len > ((SIZE_MAX - 1) / 2)) {
        return NULL;
    }
    res_len = (len * 2) + 1;

    result = util_common_calloc_s(res_len);
    if (result == NULL) {
        return NULL;
    }
    for (i = 0, j = 0; i < len; i++) {
        int tmp = (mask[i] >> 4);
        result[j++] = g_HEX_DICT[tmp];
        tmp = (mask[i] & 0x0f);
        result[j++] = g_HEX_DICT[tmp];
    }
    return result;
}

static size_t try_to_ipv4(const struct ipnet *value, uint8_t **pip, char **err)
{
    size_t iplen = 0;

    iplen = to_ipv4(value->ip, value->ip_len, pip);
    if (iplen == 0) {
        if (value->ip_len == IPV6LEN) {
            *pip = util_smart_calloc_s(IPV6LEN, sizeof(uint8_t));
            if (*pip == NULL) {
                ERROR("Out of memory");
                *err = util_strdup_s("Out of memory");
                return 0;
            }
            (void)memcpy(*pip, value->ip, IPV6LEN);
            iplen = IPV6LEN;
        } else {
            if (asprintf(err, "Invalid ip, len=%lu", iplen) < 0) {
                ERROR("Out of memory");
                *err = util_strdup_s("Out of memory");
            }
            return 0;
        }
    }
    return iplen;
}

static int get_ipv4_mask(const struct ipnet *value, size_t iplen, uint8_t **mask, char **err)
{
    if (iplen != IPV4LEN) {
        int nret = asprintf(err, "len of IP: %lu diffrent to len of mask: %lu", iplen, value->ip_mask_len);
        if (nret < 0) {
            *err = util_strdup_s("Out of memory");
            ERROR("Out of memory");
        }
        return 0;
    }
    *mask = util_smart_calloc_s(IPV4LEN, sizeof(uint8_t));
    if (*mask == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        return -1;
    }
    (void)memcpy(*mask, value->ip_mask, IPV4LEN);
    return IPV4LEN;
}

static int get_ipv6_mask(const struct ipnet *value, size_t iplen, uint8_t **mask, char **err)
{
    if (iplen == IPV4LEN) {
        *mask = util_smart_calloc_s(IPV4LEN, sizeof(uint8_t));
        if (*mask == NULL) {
            *err = util_strdup_s("Out of memory");
            ERROR("Out of memory");
            return 0;
        }
        (void)memcpy(*mask, (value->ip_mask + IPV4_TO_V6_EMPTY_PREFIX_BYTES), IPV4LEN);
        return IPV4LEN;
    } else {
        (void)memcpy(*mask, value->ip_mask, IPV6LEN);
        return IPV6LEN;
    }
}

static size_t try_get_mask(const struct ipnet *value, size_t iplen, uint8_t **mask, char **err)
{
    size_t masklen = 0;
    int nret = 0;

    switch (value->ip_mask_len) {
        case IPV4LEN:
            nret = get_ipv4_mask(value, iplen, mask, err);
            if (nret == 0) {
                return 0;
            } else if (nret < 0) {
                goto free_out;
            }
            masklen = (size_t)nret;
            break;
        case IPV6LEN:
            nret = get_ipv6_mask(value, iplen, mask, err);
            if (nret == 0) {
                return 0;
            } else if (nret < 0) {
                goto free_out;
            }
            masklen = (size_t)nret;
            break;
        default:
            nret = asprintf(err, "Invalid mask len: %lu", value->ip_mask_len);
            if (nret < 0) {
                *err = util_strdup_s("Out of memory");
                ERROR("Out of memory");
            }
            goto free_out;
    }
    return masklen;
free_out:
    free(*mask);
    *mask = NULL;
    return 0;
}

static char *do_generate_ip_with_mask(const uint8_t *mask, size_t masklen, const char *ip, char **err)
{
    char *tmp_mask = NULL;
    char *result = NULL;
    int nret = 0;
    size_t res_len = 0;

    if (ip == NULL) {
        return NULL;
    }
    tmp_mask = mask_hex_string(mask, masklen);
    if (tmp_mask == NULL) {
        *err = util_strdup_s("Mask toString failed");
        ERROR("Mask toString failed");
        goto free_out;
    }

    if (strlen(ip) > ((SIZE_MAX - 2) - strlen(tmp_mask))) {
        *err = util_strdup_s("Too long ips");
        ERROR("Too long ips");
        goto free_out;
    }

    res_len = strlen(ip) + 1 + strlen(tmp_mask) + 1;
    result = util_common_calloc_s(res_len);
    if (result == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        goto free_out;
    }
    nret = snprintf(result, res_len, "%s/%s", ip, tmp_mask);
    if (nret < 0 || (size_t)nret >= res_len) {
        *err = util_strdup_s("Sprintf first type failed");
        ERROR("Sprintf failed");
        free(result);
        result = NULL;
    }
free_out:
    free(tmp_mask);
    return result;
}

char *ipnet_to_string(const struct ipnet *value, char **err)
{
    char *result = NULL;
    char *tmp_ip = NULL;
    uint8_t *ip = NULL;
    uint8_t *mask = NULL;
    size_t iplen = 0;
    size_t masklen = 0;
    int slen = 0;
    int nret = 0;
    size_t res_len = 0;

    iplen = try_to_ipv4(value, &ip, err);
    if (iplen == 0) {
        goto free_out;
    }

    masklen = try_get_mask(value, iplen, &mask, err);
    if (masklen == 0) {
        goto free_out;
    }

    slen = simple_mask_len(mask, masklen);
    tmp_ip = ip_to_string(ip, iplen);
    if (tmp_ip == NULL) {
        *err = util_strdup_s("IP toString failed");
        ERROR("IP toString failed");
        goto free_out;
    }
    if (slen == -1) {
        result = do_generate_ip_with_mask(mask, masklen, tmp_ip, err);
        goto free_out;
    }

    if (strlen(tmp_ip) > (SIZE_MAX - 5)) {
        *err = util_strdup_s("Too long ips");
        goto free_out;
    }

    res_len = strlen(tmp_ip) + 1 + 3 + 1;
    result = util_common_calloc_s(res_len);
    if (result == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        goto free_out;
    }
    nret = snprintf(result, res_len, "%s/%d", tmp_ip, slen);
    if (nret < 0 || (size_t)nret >= res_len) {
        ERROR("Sprintf failed");
        *err = util_strdup_s("Sprintf second type failed");
        free(result);
        result = NULL;
    }

free_out:
    free(tmp_ip);
    free(mask);
    free(ip);
    return result;
}

static int get_ip_from_in6_addr(const struct in6_addr *ipv6, uint8_t **ip, size_t *len)
{
    uint8_t *result = NULL;

    if (ipv6 == NULL) {
        return 0;
    }
    result = util_smart_calloc_s(IPV6LEN, sizeof(uint8_t));
    if (result == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    (void)memcpy(result, ipv6->s6_addr, IPV6LEN * sizeof(uint8_t));

    *ip = result;
    *len = IPV6LEN;
    return 0;
}

static int get_ip_from_in_addr(const struct in_addr *ipv4, uint8_t **ip, size_t *len)
{
    uint8_t *result = NULL;
    size_t i = 0;
    uint32_t work = 0;

    if (ipv4 == NULL) {
        return 0;
    }
    result = util_smart_calloc_s(IPV4LEN, sizeof(uint8_t));
    if (result == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    work = ipv4->s_addr;
    for (i = 0; i < IPV4LEN; i++) {
        result[i] = (uint8_t)(work & 0x0ff);
        work >>= 8;
    }

    *ip = result;
    *len = IPV4LEN;
    return 0;
}

static int do_parse_ipv6_from_str(const char *addr, struct in6_addr *ipv6, uint8_t **ips, size_t *len, int *ret,
                                  char **err)
{
    int nret = 0;

    if (addr == NULL) {
        ERROR("Empty address");
        return -1;
    }
    nret = inet_pton(AF_INET6, addr, ipv6);
    if (nret < 0) {
        nret = asprintf(err, "ipv6 inet_pton %s", strerror(errno));
        if (nret < 0) {
            ERROR("Sprintf failed");
            *ret = 1;
        }
        return -1;
    } else if (nret == 0) {
        nret = asprintf(err, "Invalid ip address: %s", addr);
        if (nret < 0) {
            ERROR("Sprintf failed");
            *ret = 1;
        }
        return -1;
    }

    *ret = get_ip_from_in6_addr(ipv6, ips, len);

    return *ret;
}

int parse_ip_from_str(const char *addr, uint8_t **ips, size_t *len, char **err)
{
    int nret = 0;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    int ret = -1;

    if (addr == NULL) {
        ERROR("Empty address");
        return -1;
    }
    nret = inet_pton(AF_INET, addr, &ipv4);
    if (nret < 0) {
        nret = asprintf(err, "ipv4 inet_pton %s", strerror(errno));
        if (nret < 0) {
            ERROR("Sprintf failed");
            ret = 1;
        }
        goto free_out;
    } else if (nret == 0) {
        /* check ipv6 */
        nret = do_parse_ipv6_from_str(addr, &ipv6, ips, len, &ret, err);
        if (nret != 0) {
            goto free_out;
        }
    } else {
        nret = get_ip_from_in_addr(&ipv4, ips, len);
        if (nret != 0) {
            goto free_out;
        }
    }
    ret = 0;
free_out:
    return ret;
}

static int do_parse_mask_in_cidr(unsigned int mask_num, struct ipnet *result, char **err)
{
    uint8_t full_mask = 0xff;
    size_t j = 0;
    size_t i = 0;
    unsigned int mask_cnt = mask_num;

    j = result->ip_len;

    result->ip_mask = util_smart_calloc_s(j, sizeof(uint8_t));
    if (result->ip_mask == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        return -1;
    }
    result->ip_mask_len = j;
    for (i = 0; i < j; i++) {
        if (mask_cnt >= 8) {
            result->ip_mask[i] = full_mask;
            mask_cnt -= 8;
            continue;
        }
        result->ip_mask[i] = ~(full_mask >> mask_cnt);
        mask_cnt = 0;
    }
    return 0;
}

int parse_cidr(const char *cidr_str, struct ipnet **ipnet_val, char **err)
{
    char *pos = NULL;
    char *addr = NULL;
    char *mask = NULL;
    char *work_cidr = NULL;
    int nret = 0;
    unsigned int mask_num = 0;
    int ret = -1;
    struct ipnet *result = NULL;

    if (cidr_str == NULL) {
        return -1;
    }

    work_cidr = util_strdup_s(cidr_str);

    result = util_common_calloc_s(sizeof(struct ipnet));
    if (result == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    pos = strchr(work_cidr, '/');
    if (pos == NULL) {
        nret = asprintf(err, "CIDR address %s", work_cidr);
        if (nret < 0) {
            ERROR("Sprintf failed");
            ret = 1;
        }
        goto free_out;
    }
    *pos = '\0';
    addr = work_cidr;
    mask = pos + 1;

    nret = parse_ip_from_str(addr, &(result->ip), &(result->ip_len), err);
    if (nret != 0) {
        ret = -1;
        goto free_out;
    }

    nret = util_safe_uint(mask, &mask_num);
    if (nret != 0 || (size_t)mask_num > (result->ip_len << 3)) {
        nret = asprintf(err, "Invalid CIDR address %s", cidr_str);
        if (nret < 0) {
            ERROR("Sprintf failed");
            *err = util_strdup_s("Asprintf cidr failed");
            ret = 1;
        }
        goto free_out;
    }

    /* parse mask */
    if (do_parse_mask_in_cidr(mask_num, result, err) != 0) {
        ret = -1;
        goto free_out;
    }
    *ipnet_val = result;
    result = NULL;
    ret = 0;

free_out:
    free(work_cidr);
    if (result != NULL) {
        free(result->ip);
        free(result->ip_mask);
        free(result);
    }
    return ret;
}

