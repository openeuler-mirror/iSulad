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
 * Author: gaohuatao
 * Create: 2020-12-29
 * Description: provide network port parse utils functions
 *******************************************************************************/
#ifndef UTILS_CUTILS_UTILS_PORT_H
#define UTILS_CUTILS_UTILS_PORT_H

#include "map.h"
#include "isula_libutils/network_port_binding.h"
#include "isula_libutils/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PORT_LEN 128

struct port_mapping {
    // with proto, such as 8080/tcp
    char *port;
    char *host_ip;
    char *host_port;
};

struct network_port {
    char *format_str;
    char *proto;
    uint64_t start;
    uint64_t end;
};

int util_split_proto_port(const char *raw_port, char **proto, char **port);

char *util_pack_port_proto(uint64_t port, const char *proto);

// Export --publish value to custom map
int util_parse_port_specs(const char **port_arr, map_t **exposed_map, map_t **port_binding_map);

// Export --expose value to custom map
int util_parse_expose_ports(const char **expose, map_t **exposed_m);

void util_free_port_mapping(struct port_mapping *data);

int util_copy_port_binding_from_custom_map(defs_map_string_object_port_bindings **data, const map_t *port_binding_m);

bool util_parse_port_range(const char *ports, struct network_port *np);

/*
* support format of port:
* 1. 1-10;
* 2. 8;
*/
bool util_new_network_port(const char *proto, const char *port, struct network_port **res);

void util_free_network_port(struct network_port *ptr);

bool util_valid_proto(const char *proto);

int util_get_random_port();

static inline bool is_valid_port(const int port)
{
    return (port > 0 && port <= 65535);
}

bool util_check_port_free(int port);

#ifdef __cplusplus
}
#endif
#endif