/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: chengzeruizhi
 * Create: 2021-11-17
 * Description: provide common network functions
 ********************************************************************************/

#define _GNU_SOURCE

#include "utils_network.h"

#include <stdlib.h>

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "namespace.h"

#define IPV4_TO_V6_EMPTY_PREFIX_BYTES 12
#define MAX_INTERFACE_NAME_LENGTH 15
#define MAX_UINT_LEN 3
// IPV6 max address "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
#define IPV6_MAX_ADDR_LEN 40
const char g_HEX_DICT[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

void util_free_ipnet(struct ipnet *val)
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

static int get_ip_from_in_addr(const struct in_addr *ipv4, uint8_t **ip, size_t *len)
{
    uint8_t *result = NULL;
    size_t i = 0;
    uint32_t work = 0;

    result = (uint8_t *)util_smart_calloc_s(sizeof(uint8_t), IPV4LEN);
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

static int get_ip_from_in6_addr(const struct in6_addr *ipv6, uint8_t **ip, size_t *len)
{
    *ip = (uint8_t *)util_smart_calloc_s(sizeof(uint8_t), IPV6LEN);
    if (*ip == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    (void)memcpy(*ip, ipv6->s6_addr, IPV6LEN * sizeof(uint8_t));
    *len = IPV6LEN;

    return 0;
}

int util_parse_ip_from_str(const char *addr, uint8_t **ips, size_t *len)
{
    int nret = 0;
    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (addr == NULL || ips == NULL || len == NULL) {
        ERROR("Invalid args");
        return -1;
    }

    nret = inet_pton(AF_INET, addr, &ipv4);
    if (nret < 0) {
        // error
        SYSERROR("get ipv4 info");
        return -1;
    }

    if (nret > 0) {
        // ipv4
        return get_ip_from_in_addr(&ipv4, ips, len);
    }

    // nret == 0, ipv6
    nret = inet_pton(AF_INET6, addr, &ipv6);
    if (nret < 0) {
        SYSERROR("get ipv6 info");
        return -1;
    }
    if (nret == 0) {
        ERROR("Invalid ip address: %s", addr);
        return -1;
    }

    return get_ip_from_in6_addr(&ipv6, ips, len);
}

static char *do_uint8_join(const char *sep, const char *type, const uint8_t *parts, const size_t parts_len,
                           const size_t result_len)
{
    int nret = 0;
    size_t iter;
    char *res_string = NULL;
    char buffer[MAX_UINT_LEN + 1] = { 0 };

    if (result_len > (SIZE_MAX - 1)) {
        ERROR("Large string");
        return NULL;
    }

    res_string = util_common_calloc_s(result_len + 1);
    if (res_string == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (iter = 0; iter < parts_len; iter++) {
        nret = snprintf(buffer, MAX_UINT_LEN + 1, type, parts[iter]);
        if (nret < 0 || (size_t)nret >= MAX_UINT_LEN + 1) {
            ERROR("Sprint failed");
            free(res_string);
            return NULL;
        }
        (void)strcat(res_string, buffer);
        if (iter != parts_len - 1) {
            (void)strcat(res_string, sep);
        }
    }

    return res_string;
}

static char *uint8_join(const char *sep, const char *type, const uint8_t *parts, const size_t len)
{
    size_t sep_len, result_len;

    if (sep == NULL || type == NULL || parts == NULL || len == 0) {
        ERROR("Invalid arguments");
        return NULL;
    }

    sep_len = strlen(sep);
    if (len > SIZE_MAX / (sep_len + MAX_UINT_LEN)) {
        ERROR("Large string");
        return NULL;
    }
    result_len = (len - 1) * sep_len + MAX_UINT_LEN * len;

    return do_uint8_join(sep, type, parts, len, result_len);
}

// format
// 16bits  16bits  16bits  16bits  16bits  16bits  32bits
// 0       0       0       0       0       FFFF    IPv4 Address
static bool is_ipv4_mapped_address(const uint8_t *ip, const size_t len)
{
    size_t i;

    for (i = 0; i < 10; i++) {
        if (ip[i] != 0) {
            return false;
        }
    }

    return ip[10] == 0xff && ip[11] == 0xff;
}

// return value
// -1: error
//  0: parse ipv4 success
//  1: not ipv4 address
static int parse_ipv4_to_string(const uint8_t *ip, const size_t len, char **result)
{
    int ret = 0;
    size_t i;
    uint8_t *tmp = NULL;

    if (len == IPV4LEN) {
        *result = uint8_join(".", "%u", ip, IPV4LEN);
        if (*result == NULL) {
            ERROR("ip join failed");
            return -1;
        }

        return 0;
    }

    if (!is_ipv4_mapped_address(ip, len)) {
        return 1;
    }

    tmp = (uint8_t *)util_smart_calloc_s(sizeof(uint8_t), IPV4LEN);
    if (tmp == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < IPV4LEN; i++) {
        tmp[i] = ip[i + 12];
    }

    *result = uint8_join(".", "%u", tmp, IPV4LEN);
    if (*result == NULL) {
        ERROR("ip join failed");
        ret = -1;
    }

    free(tmp);
    return ret;
}

static int generate_ipv6_string(const uint8_t *ip, int e0, int e1, char **result)
{
    int i, j;

    *result = (char *)util_common_calloc_s(IPV6_MAX_ADDR_LEN);
    if (*result == NULL) {
        ERROR("Out of memory");
        return -1;
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
        bool skip = true;
        int nret = (ip[i] >> 4);
        if (nret != 0) {
            (*result)[j++] = g_HEX_DICT[nret];
            skip = false;
        }
        nret = (ip[i] & 0x0f);
        if (nret != 0 || !skip) {
            (*result)[j++] = g_HEX_DICT[nret];
            skip = false;
        }
        nret = (ip[i + 1] >> 4);
        if (nret != 0 || !skip) {
            (*result)[j++] = g_HEX_DICT[nret];
            skip = false;
        }
        nret = (ip[i + 1] & 0x0f);
        if (nret != 0 || !skip) {
            (*result)[j++] = g_HEX_DICT[nret];
            skip = false;
        }
    }

    return 0;
}

static int parse_ipv6_to_string(const uint8_t *ip, const size_t len, char **result)
{
    int i, j, e0, e1;

    if (len != IPV6LEN) {
        ERROR("Invalid ipv6 length");
        return -1;
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

    return generate_ipv6_string(ip, e0, e1, result);
}

static int parse_standard_ip_to_string(const uint8_t *ip, const size_t len, char **result)
{
    int nret = 0;

    if (len != IPV4LEN && len != IPV6LEN) {
        ERROR("Invalid ip length: %zu", len);
        return -1;
    }

    nret = parse_ipv4_to_string(ip, len, result);
    if (nret == 0) {
        return 0;
    }
    if (nret < 0) {
        ERROR("Failed to parse ipv4");
        return -1;
    }

    if (parse_ipv6_to_string(ip, len, result) != 0) {
        ERROR("Failed to parse ipv6");
        return -1;
    }

    return 0;
}

static int parse_nonstandard_ip_to_string(const uint8_t *ip, const size_t len, char **result)
{
    int ret = 0;
    int nret = 0;
    size_t res_len = 0;
    char *tmp = NULL;

    tmp = uint8_join("", "%02x", ip, len);
    if (tmp == NULL) {
        ERROR("ip join failed");
        return -1;
    }

    if (strlen(tmp) > (SIZE_MAX - 2)) {
        ERROR("ip is too long");
        ret = -1;
        goto free_out;
    }

    res_len = 1 + strlen(tmp) + 1;
    *result = (char *)util_common_calloc_s(res_len);
    if (*result == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }

    nret = snprintf(*result, res_len, "%s%s", "?", tmp);
    if (nret < 0 || (size_t)nret >= res_len) {
        free(*result);
        *result = NULL;
        ret = -1;
    }

free_out:
    free(tmp);
    return ret;
}

char *util_ip_to_string(const uint8_t *ip, const size_t len)
{
    char *result = NULL;

    if (ip == NULL || len == 0) {
        WARN("Empty ip args");
        return util_strdup_s("<nil>");
    }

    if (len != IPV4LEN && len != IPV6LEN) {
        // ? return error
        if (parse_nonstandard_ip_to_string(ip, len, &result) != 0) {
            ERROR("Failed to parse nonstandard ip");
            return NULL;
        }
        return result;
    }

    if (parse_standard_ip_to_string(ip, len, &result) != 0) {
        return NULL;
    }

    return result;
}

static int do_parse_mask_in_cidr(const unsigned int mask_num, struct ipnet *result)
{
    uint8_t full_mask = 0xff;
    size_t i;
    size_t ip_len = result->ip_len;
    unsigned int mask_cnt = mask_num;

    result->ip_mask = (uint8_t *)util_smart_calloc_s(sizeof(uint8_t), ip_len);
    if (result->ip_mask == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    result->ip_mask_len = ip_len;
    for (i = 0; i < ip_len; i++) {
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

int util_parse_ipnet_from_str(const char *cidr_str, struct ipnet **ipnet_val)
{
    int ret = 0;
    unsigned int mask_num = 0;
    char *pos = NULL;
    char *addr = NULL;
    char *mask = NULL;
    char *work_cidr = NULL;
    struct ipnet *result = NULL;

    if (cidr_str == NULL || ipnet_val == NULL) {
        ERROR("Invalid args");
        return -1;
    }

    work_cidr = util_strdup_s(cidr_str);
    pos = strchr(work_cidr, '/');
    if (pos == NULL) {
        ERROR("invalid CIDR address %s", work_cidr);
        ret = -1;
        goto free_out;
    }
    *pos = '\0';
    addr = work_cidr;
    mask = pos + 1;

    result = (struct ipnet *)util_common_calloc_s(sizeof(struct ipnet));
    if (result == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }

    if (util_parse_ip_from_str(addr, &(result->ip), &(result->ip_len)) != 0) {
        ret = -1;
        goto free_out;
    }

    /* parse mask */
    ret = util_safe_uint(mask, &mask_num);
    if (ret != 0 || (size_t)mask_num > (result->ip_len << 3)) {
        ERROR("Invalid CIDR address %s", cidr_str);
        ret = -1;
        goto free_out;
    }
    if (do_parse_mask_in_cidr(mask_num, result) != 0) {
        ret = -1;
        goto free_out;
    }

    *ipnet_val = result;
    result = NULL;

free_out:
    free(work_cidr);
    util_free_ipnet(result);
    return ret;
}

static int get_ipv4_mask(const struct ipnet *value, uint8_t **mask, size_t *mask_len)
{
    *mask = (uint8_t *)util_smart_calloc_s(sizeof(uint8_t), IPV4LEN);
    if (*mask == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    (void)memcpy(*mask, value->ip_mask, IPV4LEN);
    *mask_len = IPV4LEN;
    return 0;
}

static int get_ipv6_mask(const struct ipnet *value, uint8_t **mask, size_t *mask_len)
{

    if (is_ipv4_mapped_address(value->ip, value->ip_len)) {
        *mask = (uint8_t *)util_smart_calloc_s(sizeof(uint8_t), IPV4LEN);
        if (*mask == NULL) {
            ERROR("Out of memory");
            return -1;
        }

        (void)memcpy(*mask, (value->ip_mask + IPV4_TO_V6_EMPTY_PREFIX_BYTES), IPV4LEN);
        *mask_len = IPV4LEN;
        return 0;
    }

    *mask = (uint8_t *)util_smart_calloc_s(sizeof(uint8_t), IPV6LEN);
    if (*mask == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    (void)memcpy(*mask, value->ip_mask, IPV6LEN);
    *mask_len = IPV6LEN;
    return 0;
}

static int get_mask(const struct ipnet *value, uint8_t **mask, size_t *mask_len)
{
    if (value->ip_mask_len != IPV4LEN && value->ip_mask_len != IPV6LEN) {
        ERROR("Invalid mask length %zu", value->ip_mask_len);
        return -1;
    }

    if (value->ip_len != value->ip_mask_len) {
        ERROR("IP length %zu is diffrent from mask length %zu", value->ip_len, value->ip_mask_len);
        return -1;
    }

    if (value->ip_mask_len == IPV4LEN) {
        if (get_ipv4_mask(value, mask, mask_len) != 0) {
            ERROR("Failed to get ipv4 mask");
            return -1;
        }

        return 0;
    }

    if (get_ipv6_mask(value, mask, mask_len) != 0) {
        ERROR("Failed to get ipv6 mask");
        return -1;
    }

    return 0;
}

static int generate_mask_string(const uint8_t *mask, const size_t len, char **result)
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
            ERROR("Invalid mask");
            return -1;
        }

        size_t j = i;
        for (j++; j < len; j++) {
            if (mask[j] != 0) {
                ERROR("Invalid mask");
                return -1;
            }
        }
        break;
    }

    *result = util_int_to_string(ret);
    if (*result == NULL) {
        ERROR("Failed to convert %d to string", ret);
        return -1;
    }

    return 0;
}

static int parse_nonstandard_mask_to_string(const uint8_t *mask, size_t masklen, char **result)
{
    size_t res_len = 0;
    size_t i, j;

    if (masklen > ((SIZE_MAX - 1) / 2)) {
        ERROR("mask is too long");
        return -1;
    }

    res_len = (masklen * 2) + 1;
    *result = (char *)util_common_calloc_s(res_len);
    if (*result == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0, j = 0; i < masklen; i++) {
        int tmp = (mask[i] >> 4);
        (*result)[j++] = g_HEX_DICT[tmp];
        tmp = (mask[i] & 0x0f);
        (*result)[j++] = g_HEX_DICT[tmp];
    }

    return 0;
}

static int parse_mask_to_string(const struct ipnet *value, char **result)
{
    int ret = 0;
    uint8_t *mask = NULL;
    size_t mask_len = 0;

    if (get_mask(value, &mask, &mask_len) != 0) {
        ERROR("Failed to get mask");
        return -1;
    }

    if (generate_mask_string(mask, mask_len, result) != 0) {
        ERROR("Failed to generate mask string");
        // ? return error
        if (parse_nonstandard_mask_to_string(mask, mask_len, result) != 0) {
            ERROR("Failed to generate nonstandard mask");
            ret = -1;
        }
    }

    free(mask);
    return ret;
}

char *util_ipnet_to_string(const struct ipnet *value)
{
    int nret = 0;
    size_t res_len = 0;
    char *result = NULL;
    char *ip_str = NULL;
    char *mask_str = NULL;

    if (value == NULL) {
        ERROR("Invalid args");
        return NULL;
    }

    if (parse_standard_ip_to_string(value->ip, value->ip_len, &ip_str) != 0) {
        ERROR("Failed to parse ip to string");
        return NULL;
    }

    if (parse_mask_to_string(value, &mask_str) != 0) {
        ERROR("Failed to parse mask to string");
        goto out;
    }

    res_len = strlen(ip_str) + 1 + sizeof(mask_str) + 1;
    result = (char *)util_common_calloc_s(res_len);
    if (result == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    nret = snprintf(result, res_len, "%s/%s", ip_str, mask_str);
    if (nret < 0 || (size_t)nret >= res_len) {
        ERROR("Sprintf failed");
        free(result);
        result = NULL;
    }

out:
    free(ip_str);
    free(mask_str);
    return result;
}

bool util_net_contain_ip(const struct ipnet *ipnet, const uint8_t *ip, const size_t ip_len, const bool closed_interval)
{
    bool ret = false;
    bool is_first = true;
    bool is_last = true;
    size_t i = 0;
    uint8_t *first_ip = NULL;
    uint8_t *last_ip = NULL;

    if (ipnet == NULL || ip == NULL || ip_len == 0) {
        return false;
    }

    if (ipnet->ip_len != ip_len || ipnet->ip_mask_len != ip_len) {
        return false;
    }

    first_ip = (uint8_t *)util_smart_calloc_s(sizeof(uint8_t), ip_len);
    if (first_ip == NULL) {
        ERROR("Out of memory");
        return false;
    }
    last_ip = (uint8_t *)util_smart_calloc_s(sizeof(uint8_t), ip_len);
    if (last_ip == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    for (i = 0; i < ip_len; i++) {
        first_ip[i] = ipnet->ip[i] & ipnet->ip_mask[i];
        last_ip[i] = ipnet->ip[i] | (~ipnet->ip_mask[i]);
    }

    for (i = 0; i < ip_len; i++) {
        if (ip[i] < first_ip[i] || ip[i] > last_ip[i]) {
            goto out;
        }

        if (ip[i] != first_ip[i]) {
            is_first = false;
        }
        if (ip[i] != last_ip[i]) {
            is_last = false;
        }
    }

    // close interval ip range [first_ip, last_ip]
    if (closed_interval) {
        ret = true;
    } else {
        ret = !is_first && !is_last;
    }

out:
    free(first_ip);
    free(last_ip);
    return ret;
}

bool util_validate_network_name(const char *name)
{
    if (name == NULL) {
        ERROR("missing network name");
        return false;
    }

    if (strnlen(name, MAX_NETWORK_NAME_LEN + 1) > MAX_NETWORK_NAME_LEN) {
        ERROR("Network name \"%s\" too long, max length:%d", name, MAX_NETWORK_NAME_LEN);
        return false;
    }

    if (util_reg_match(NETWORK_VALID_NAME_CHARS, name) != 0) {
        ERROR("invalid characters found in network name: %s", name);
        return false;
    }

    return true;
}

// ignore native network when network_mode != bridge
bool util_native_network_checker(const char *network_mode)
{
    return namespace_is_bridge(network_mode);
}

bool util_post_setup_network(const char *user_remap)
{
    return user_remap != NULL ? true : false;
}

static bool is_invalid_char(char c)
{
    switch (c) {
        case '/':
            return true;
        case ':':
            return true;
        case '\t':
            return true;
        case '\n':
            return true;
        case '\v':
            return true;
        case '\f':
            return true;
        case '\r':
            return true;
        case ' ':
            return true;
    }
    return false;
}

bool util_validate_network_interface(const char *if_name)
{
    size_t i = 0;

    // 1. interface name must not be empty
    if (if_name == NULL || strlen(if_name) == 0) {
        ERROR("interface is empty");
        return false;
    }

    // 2. interface name must be less than 16 characters
    if (strlen(if_name) > MAX_INTERFACE_NAME_LENGTH) {
        ERROR("interface name is too long");
        return false;
    }

    // 3. interface name must not be "." or ".."
    if (strcmp(if_name, ".") == 0 || strcmp(if_name, "..") == 0) {
        ERROR("interface name is . or ..");
        return false;
    }

    // 4. interface name must not contain / or : or any whitespace characters
    for (i = 0; i < strlen(if_name); i++) {
        if (is_invalid_char(if_name[i])) {
            ERROR("interface name contain / or : or whitespace characters: %s", if_name);
            return false;
        }
    }

    return true;
}

bool util_validate_ipv4_address(const char *ipv4)
{
    struct in_addr sin_addr;

    if (ipv4 == NULL) {
        ERROR("missing ipv4 address");
        return false;
    }

    if (inet_pton(AF_INET, ipv4, &sin_addr) != 1) {
        return false;
    }

    return true;
}

bool util_validate_ipv6_address(const char *ipv6)
{
    struct in6_addr sin_addr;

    if (ipv6 == NULL) {
        ERROR("missing ipv6 address");
        return false;
    }

    if (inet_pton(AF_INET6, ipv6, &sin_addr) != 1) {
        return false;
    }

    return true;
}

bool util_validate_ip_address(const char *ip)
{
    if (ip == NULL) {
        ERROR("missing ip address");
        return false;
    }

    if (!util_validate_ipv4_address(ip) && !util_validate_ipv6_address(ip)) {
        return false;
    }

    return true;
}

bool util_validate_mac_address(const char *mac)
{
    if (mac == NULL) {
        ERROR("missing mac address");
        return false;
    }

    if (util_reg_match(NETWORK_VALID_MAC_CHARS, mac) != 0) {
        return false;
    }

    return true;
}

int util_reduce_ip_by_mask(const struct ipnet *val)
{
    size_t i;

    if (val == NULL || val->ip_len != val->ip_mask_len) {
        ERROR("Invalid ipnet");
        return -1;
    }

    for (i = 0; i < val->ip_len; i++) {
        val->ip[i] = val->ip[i] & val->ip_mask[i];
    }

    return 0;
}
