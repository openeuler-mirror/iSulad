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

#ifndef UTILS_CUTILS_UTILS_NETWORK_H
#define UTILS_CUTILS_UTILS_NETWORK_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int util_create_netns_file(const char *netns_path);

int util_mount_namespace(const char *netns_path);

int util_umount_namespace(const char *netns_path);

#define IPV4LEN 4

#define IPV6LEN 16

#define NETWORK_VALID_NAME_CHARS "^[a-zA-Z0-9][a-zA-Z0-9_.-]*$"

struct ipnet {
    uint8_t *ip;
    size_t ip_len;

    uint8_t *ip_mask;
    size_t ip_mask_len;
};

void util_free_ipnet(struct ipnet *val);

int util_parse_ip_from_str(const char *addr, uint8_t **ips, size_t *len);

int util_parse_cidr(const char *cidr_str, struct ipnet **ipnet_val);

char *util_ipnet_to_string(const struct ipnet *value);

char *util_ip_to_string(const uint8_t *ip, size_t len);

bool util_net_contain_ip(const struct ipnet *ipnet, const uint8_t *ip, const size_t ip_len, bool critical);

bool util_validate_network_name(const char *name);

bool util_validate_network_interface(const char *if_name);

#ifdef __cplusplus
}
#endif

#endif // UTILS_CUTILS_UTILS_NETWORK_H
