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

#ifndef UTILS_CUTILS_UTILS_NETWORK_H
#define UTILS_CUTILS_UTILS_NETWORK_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IPV4LEN 4

#define IPV6LEN 16

#define NETWORK_VALID_NAME_CHARS "^[a-zA-Z0-9][a-zA-Z0-9_.-]*$"
#define NETWORK_VALID_MAC_CHARS "^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$"

struct ipnet {
    uint8_t *ip;
    size_t ip_len;

    uint8_t *ip_mask;
    size_t ip_mask_len;
};

struct network_port {
    char *format_str;
    char *proto;
    uint64_t start;
    uint64_t end;
};

void util_free_ipnet(struct ipnet *val);

int util_parse_ip_from_str(const char *addr, uint8_t **ips, size_t *len);

int util_parse_cidr(const char *cidr_str, struct ipnet **ipnet_val);

char *util_ipnet_to_string(const struct ipnet *value);

char *util_ip_to_string(const uint8_t *ip, size_t len);

bool util_net_contain_ip(const struct ipnet *ipnet, const uint8_t *ip, const size_t ip_len, bool critical);

bool util_validate_network_name(const char *name);

bool util_validate_network_interface(const char *if_name);

bool util_validate_ipv4_address(const char *ipv4);

bool util_validate_ipv6_address(const char *ipv6);

bool util_validate_ip_address(const char *ip);

bool util_validate_mac_address(const char *mac);

bool util_parse_port_range(const char *ports, struct network_port *np);

/*
* support format of port:
* 1. 1-10;
* 2. 8;
*/
bool util_new_network_port(const char *proto, const char *port, struct network_port **res);

void util_free_network_port(struct network_port *ptr);

bool util_valid_proto(const char *proto);


#ifdef __cplusplus
}
#endif
#endif
