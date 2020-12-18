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
 * Description: provide types function definition
 *******************************************************************************/
#ifndef CLIBCNI_TYPES_TYPES_H
#define CLIBCNI_TYPES_TYPES_H

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IPV4LEN 4

#define IPV6LEN 16

/* define types for version */
struct interface {
    char *name;
    char *mac;
    char *sandbox;
};

struct ipnet {
    uint8_t *ip;
    size_t ip_len;

    uint8_t *ip_mask;
    size_t ip_mask_len;
};

struct ipconfig {
    char *version;
    int32_t *interface;
    struct ipnet *address;

    uint8_t *gateway;
    size_t gateway_len;
};

struct route {
    struct ipnet *dst;

    uint8_t *gw;
    size_t gw_len;
};

struct dns {
    char **name_servers;
    size_t name_servers_len;

    char *domain;

    char **search;
    size_t search_len;

    char **options;
    size_t options_len;
};

struct result {
    char *cniversion;
    struct interface **interfaces;
    size_t interfaces_len;

    struct ipconfig **ips;
    size_t ips_len;

    struct route **routes;
    size_t routes_len;

    struct dns *my_dns;
};

void free_ipnet_type(struct ipnet *val);

void free_ipconfig_type(struct ipconfig *ipc);

void free_route_type(struct route *val);

void free_interface_type(struct interface *val);

void free_dns_type(struct dns *val);

void free_result(struct result *val);

int parse_ip_from_str(const char *addr, uint8_t **ips, size_t *len);

int parse_cidr(const char *cidr_str, struct ipnet **ipnet_val);

/* common tool functions */

char *ipnet_to_string(const struct ipnet *value);

char *ip_to_string(const uint8_t *ip, size_t len);

bool net_contain_ip(const struct ipnet *ipnet, const uint8_t *ip, const size_t ip_len, bool critical);

#ifdef __cplusplus
}
#endif
#endif
