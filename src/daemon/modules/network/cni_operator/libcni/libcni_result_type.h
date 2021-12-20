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

/* define types for version */
struct cni_opt_result_interface {
    char *name;
    char *mac;
    char *sandbox;
};

struct cni_opt_result_ipconfig {
    char *version;
    int32_t *interface;
    struct ipnet *address;

    uint8_t *gateway;
    size_t gateway_len;
};

struct cni_opt_result_route {
    struct ipnet *dst;

    uint8_t *gw;
    size_t gw_len;
};

struct cni_opt_result_dns {
    char **name_servers;
    size_t name_servers_len;

    char *domain;

    char **search;
    size_t search_len;

    char **options;
    size_t options_len;
};

struct cni_opt_result {
    char *cniversion;
    struct cni_opt_result_interface **interfaces;
    size_t interfaces_len;

    struct cni_opt_result_ipconfig **ips;
    size_t ips_len;

    struct cni_opt_result_route **routes;
    size_t routes_len;

    struct cni_opt_result_dns *my_dns;
};

void free_cni_opt_result_ipconfig(struct cni_opt_result_ipconfig *ipc);

void free_cni_opt_result_route(struct cni_opt_result_route *val);

void free_cni_opt_result_interface(struct cni_opt_result_interface *val);

void free_cni_opt_result_dns(struct cni_opt_result_dns *val);

void free_cni_opt_result(struct cni_opt_result *val);

#ifdef __cplusplus
}
#endif
#endif
