/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2020-02-27
 * Description: provide network utils functions
 *******************************************************************************/

#define _GNU_SOURCE
#include "utils_network.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_string.h"

#define IPV4_TO_V6_EMPTY_PREFIX_BYTES 12
#define MAX_INTERFACE_NAME_LENGTH 15
#define MAX_UINT_LEN 3
// IPV6 max address "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
#define IPV6_MAX_ADDR_LEN 40
const char g_HEX_DICT[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
#define PROTO_NUM 3
const char *g_proto_whitelist[PROTO_NUM] = {"tcp", "udp", "sctp"};

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

static int do_parse_ipv6_from_str(const char *addr, struct in6_addr *ipv6, uint8_t **ips, size_t *len, int *ret)
{
    int nret = 0;

    if (addr == NULL) {
        ERROR("Empty address");
        return -1;
    }
    nret = inet_pton(AF_INET6, addr, ipv6);
    if (nret < 0) {
        SYSERROR("get ipv6 info");
        return -1;
    } else if (nret == 0) {
        ERROR("Invalid ip address: %s", addr);
        return -1;
    }

    *ret = get_ip_from_in6_addr(ipv6, ips, len);

    return *ret;
}

int util_parse_ip_from_str(const char *addr, uint8_t **ips, size_t *len)
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
        SYSERROR("get ipv4 info");
        goto free_out;
    } else if (nret == 0) {
        /* check ipv6 */
        nret = do_parse_ipv6_from_str(addr, &ipv6, ips, len, &ret);
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

static int do_parse_mask_in_cidr(unsigned int mask_num, struct ipnet *result)
{
    uint8_t full_mask = 0xff;
    size_t j = 0;
    size_t i = 0;
    unsigned int mask_cnt = mask_num;

    j = result->ip_len;

    result->ip_mask = util_smart_calloc_s(j, sizeof(uint8_t));
    if (result->ip_mask == NULL) {
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

int util_parse_cidr(const char *cidr_str, struct ipnet **ipnet_val)
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
        ERROR("invalid CIDR address %s", work_cidr);
        goto free_out;
    }
    *pos = '\0';
    addr = work_cidr;
    mask = pos + 1;

    nret = util_parse_ip_from_str(addr, &(result->ip), &(result->ip_len));
    if (nret != 0) {
        ret = -1;
        goto free_out;
    }

    nret = util_safe_uint(mask, &mask_num);
    if (nret != 0 || (size_t)mask_num > (result->ip_len << 3)) {
        ERROR("Invalid CIDR address %s", cidr_str);
        goto free_out;
    }

    /* parse mask */
    if (do_parse_mask_in_cidr(mask_num, result) != 0) {
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

static size_t try_to_ipv4(const struct ipnet *value, uint8_t **pip)
{
    size_t iplen = 0;

    iplen = to_ipv4(value->ip, value->ip_len, pip);
    if (iplen == 0) {
        if (value->ip_len == IPV6LEN) {
            *pip = util_smart_calloc_s(IPV6LEN, sizeof(uint8_t));
            if (*pip == NULL) {
                ERROR("Out of memory");
                return 0;
            }
            (void)memcpy(*pip, value->ip, IPV6LEN);
            iplen = IPV6LEN;
        } else {
            ERROR("Invalid ip, len=%zu", iplen);
            return 0;
        }
    }
    return iplen;
}

static int get_ipv4_mask(const struct ipnet *value, size_t iplen, uint8_t **mask)
{
    if (iplen != IPV4LEN) {
        ERROR("len of IP: %zu diffrent to len of mask: %zu", iplen, value->ip_mask_len);
        return 0;
    }
    *mask = util_smart_calloc_s(IPV4LEN, sizeof(uint8_t));
    if (*mask == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    (void)memcpy(*mask, value->ip_mask, IPV4LEN);
    return IPV4LEN;
}

static int get_ipv6_mask(const struct ipnet *value, size_t iplen, uint8_t **mask)
{
    if (iplen == IPV4LEN) {
        *mask = util_smart_calloc_s(IPV4LEN, sizeof(uint8_t));
        if (*mask == NULL) {
            ERROR("Out of memory");
            return 0;
        }
        (void)memcpy(*mask, (value->ip_mask + IPV4_TO_V6_EMPTY_PREFIX_BYTES), IPV4LEN);
        return IPV4LEN;
    } else {
        *mask = util_smart_calloc_s(IPV6LEN, sizeof(uint8_t));
        if (*mask == NULL) {
            ERROR("Out of memory");
            return 0;
        }
        (void)memcpy(*mask, value->ip_mask, IPV6LEN);
        return IPV6LEN;
    }
}

static size_t try_get_mask(const struct ipnet *value, size_t iplen, uint8_t **mask)
{
    size_t masklen = 0;
    int nret = 0;

    switch (value->ip_mask_len) {
        case IPV4LEN:
            nret = get_ipv4_mask(value, iplen, mask);
            if (nret == 0) {
                return 0;
            } else if (nret < 0) {
                goto free_out;
            }
            masklen = (size_t)nret;
            break;
        case IPV6LEN:
            nret = get_ipv6_mask(value, iplen, mask);
            if (nret == 0) {
                return 0;
            } else if (nret < 0) {
                goto free_out;
            }
            masklen = (size_t)nret;
            break;
        default:
            ERROR("Invalid mask len: %zu", value->ip_mask_len);
            goto free_out;
    }
    return masklen;
free_out:
    free(*mask);
    *mask = NULL;
    return 0;
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

static char *do_generate_ip_with_mask(const uint8_t *mask, size_t masklen, const char *ip)
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
        ERROR("Mask toString failed");
        goto free_out;
    }

    if (strlen(ip) > ((SIZE_MAX - 2) - strlen(tmp_mask))) {
        ERROR("Too long ips");
        goto free_out;
    }

    res_len = strlen(ip) + 1 + strlen(tmp_mask) + 1;
    result = util_common_calloc_s(res_len);
    if (result == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    nret = snprintf(result, res_len, "%s/%s", ip, tmp_mask);
    if (nret < 0 || (size_t)nret >= res_len) {
        ERROR("Sprintf first type failed");
        free(result);
        result = NULL;
    }
free_out:
    free(tmp_mask);
    return result;
}

char *util_ipnet_to_string(const struct ipnet *value)
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

    if (value == NULL) {
        return NULL;
    }
    iplen = try_to_ipv4(value, &ip);
    if (iplen == 0) {
        goto free_out;
    }

    masklen = try_get_mask(value, iplen, &mask);
    if (masklen == 0) {
        goto free_out;
    }

    slen = simple_mask_len(mask, masklen);
    tmp_ip = util_ip_to_string(ip, iplen);
    if (tmp_ip == NULL) {
        ERROR("IP toString failed");
        goto free_out;
    }
    if (slen == -1) {
        result = do_generate_ip_with_mask(mask, masklen, tmp_ip);
        goto free_out;
    }

    if (strlen(tmp_ip) > (SIZE_MAX - 5)) {
        ERROR("Too long ips");
        goto free_out;
    }

    res_len = strlen(tmp_ip) + 1 + 3 + 1;
    result = util_common_calloc_s(res_len);
    if (result == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    nret = snprintf(result, res_len, "%s/%d", tmp_ip, slen);
    if (nret < 0 || (size_t)nret >= res_len) {
        ERROR("Sprintf second type failed");
        free(result);
        result = NULL;
    }

free_out:
    free(tmp_ip);
    free(mask);
    free(ip);
    return result;
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

static inline bool check_clibcni_util_uint8_join_args(const char *sep, const uint8_t *parts, size_t len)
{
    return (sep == NULL || strlen(sep) == 0 || len == 0 || parts == NULL);
}

static char *do_uint8_join(const char *sep, const char *type, const uint8_t *parts, size_t parts_len, size_t result_len)
{
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

/*
 * return:
 *    0 means continue to find ip
 *    1 means get right ip
 *    -1 means something wrong
 * */
static int do_parse_util_ip_to_string(const uint8_t *ip, size_t len, char **result)
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
        ret = do_parse_util_ip_to_string(ip, len, result);
    }

free_out:
    free(work_ip);
    return ret;
}

char *util_ip_to_string(const uint8_t *ip, size_t len)
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

bool util_net_contain_ip(const struct ipnet *ipnet, const uint8_t *ip, const size_t ip_len, bool critical)
{
    bool ret = false;
    bool is_first = true;
    bool is_last = true;
    size_t i = 0;
    uint8_t *first_ip = NULL;
    uint8_t *last_ip = NULL;

    if (ipnet == NULL || ip == NULL || ip_len == 0) {
        return ret;
    }

    if (ipnet->ip_len != ip_len || ipnet->ip_mask_len != ip_len) {
        return ret;
    }

    first_ip = util_common_calloc_s(sizeof(uint8_t) * ip_len);
    if (first_ip == NULL) {
        ERROR("Out of memory");
        return ret;
    }
    last_ip = util_common_calloc_s(sizeof(uint8_t) * ip_len);
    if (last_ip == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    for (i = 0; i < ip_len; i++) {
        first_ip[i] = ipnet->ip[i] & ipnet->ip_mask[i];
        last_ip[i] = ipnet->ip[i] | (~ipnet->ip_mask[i]);
    }

    for (i = 0; i < ip_len; i++) {
        if (first_ip[i] <= ip[i] && ip[i] <= last_ip[i]) {
            if (ip[i] != first_ip[i]) {
                is_first = false;
            }
            if (ip[i] != last_ip[i]) {
                is_last = false;
            }
            continue;
        }
        goto out;
    }

    // whether or not allow ip is critical value (frist_ip and last_ip)
    if (critical) {
        ret = true;
    } else {
        ret = !(is_first || is_last);
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

    if (util_reg_match(NETWORK_VALID_NAME_CHARS, name) != 0) {
        ERROR("invalid characters found in network name: %s", name);
        return false;
    }

    return true;
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
    struct sockaddr_in sa;

    if (ipv4 == NULL) {
        ERROR("missing ipv4 address");
        return false;
    }

    if (inet_pton(AF_INET, ipv4, &sa.sin_addr) != 1) {
        return false;
    }

    return true;
}

bool util_validate_ipv6_address(const char *ipv6)
{
    struct sockaddr_in sa;

    if (ipv6 == NULL) {
        ERROR("missing ipv6 address");
        return false;
    }

    if (inet_pton(AF_INET6, ipv6, &sa.sin_addr) != 1) {
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

bool util_parse_port_range(const char *ports, struct network_port *np)
{
    char **parts = NULL;
    bool ret = true;

    if (ports == NULL || strlen(ports) == 0) {
        ERROR("Empty string specified for ports");
        return false;
    }

    if (strchr(ports, '-') == NULL) {
        if (util_safe_uint64(ports, &np->start) != 0) {
            ERROR("invalid port: %s", ports);
            return false;
        }
        np->end = np->start;
        return true;
    }

    parts = util_string_split(ports, '-');
    if (parts == NULL || util_array_len((const char **)parts) != 2) {
        ERROR("Invalid port: %s", ports);
        ret = false;
        goto out;
    }

    if (util_safe_uint64(parts[0], &np->start) != 0) {
        ERROR("Invalid port start: %s", parts[0]);
        ret = false;
        goto out;
    }

    if (util_safe_uint64(parts[1], &np->end) != 0) {
        ERROR("Invalid port end: %s", parts[1]);
        ret = false;
        goto out;
    }

    if (np->start > np->end) {
        ERROR("Invalid port : %s", ports);
        ret = false;
        goto out;
    }

out:
    if (!ret) {
        np->start = 0;
        np->end = 0;
    }
    util_free_array(parts);
    return ret;
}

bool util_new_network_port(const char *proto, const char *port, struct network_port **res)
{
#define MAX_PORT_LEN 128
    struct network_port *work = NULL;
    bool ret = true;
    char buff[MAX_PORT_LEN] = { 0 };

    if (res == NULL || port == NULL) {
        ERROR("Invalid arguments");
        return false;
    }

    work = util_common_calloc_s(sizeof(struct network_port));
    if (work == NULL) {
        ERROR("Out of memory");
        return false;
    }

    if (!util_parse_port_range(port, work)) {
        ret = false;
        goto out;
    }

    if (work->start == work->end) {
        ret = sprintf(buff, "%zu/%s", work->start, proto) > 0;
    } else {
        ret = sprintf(buff, "%zu-%zu/%s", work->start, work->end, proto) > 0;
    }
    if (!ret) {
        ERROR("format port failed");
        goto out;
    }

    work->format_str = util_strdup_s(buff);
    work->proto = util_strdup_s(proto);

    *res = work;
    work = NULL;
out:
    util_free_network_port(work);
    return ret;
}

void util_free_network_port(struct network_port *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->format_str);
    ptr->format_str = NULL;
    free(ptr->proto);
    ptr->proto = NULL;
    ptr->start = 0;
    ptr->end = 0;
    free(ptr);
}

bool util_valid_proto(const char *proto)
{
    size_t i = 0;

    if (proto == NULL) {
        return false;
    }

    for (i = 0; i < PROTO_NUM; i++) {
        if (strcmp(g_proto_whitelist[i], proto) == 0) {
            return true;
        }
    }
    return false;
}