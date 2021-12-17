/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
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
#include "libcni_result_type.h"
#include "utils.h"
#include "utils_network.h"

void free_cni_opt_result_ipconfig(struct cni_opt_result_ipconfig *ipc)
{
    if (ipc == NULL) {
        return;
    }
    free(ipc->gateway);
    ipc->gateway = NULL;
    free(ipc->version);
    ipc->version = NULL;
    util_free_ipnet(ipc->address);
    ipc->address = NULL;
    free(ipc->interface);
    ipc->interface = NULL;
    free(ipc);
}

void free_cni_opt_result_route(struct cni_opt_result_route *val)
{
    if (val == NULL) {
        return;
    }
    free(val->gw);
    val->gw = NULL;
    util_free_ipnet(val->dst);
    val->dst = NULL;
    free(val);
}

void free_cni_opt_result_interface(struct cni_opt_result_interface *val)
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

void free_cni_opt_result_dns(struct cni_opt_result_dns *val)
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

void free_cni_opt_result(struct cni_opt_result *val)
{
    size_t i = 0;

    if (val == NULL) {
        return;
    }

    free(val->cniversion);
    val->cniversion = NULL;
    for (i = 0; i < val->interfaces_len; i++) {
        free_cni_opt_result_interface(val->interfaces[i]);
        val->interfaces[i] = NULL;
    }
    free(val->interfaces);
    val->interfaces = NULL;
    for (i = 0; i < val->ips_len; i++) {
        free_cni_opt_result_ipconfig(val->ips[i]);
        val->ips[i] = NULL;
    }
    free(val->ips);
    val->ips = NULL;
    for (i = 0; i < val->routes_len; i++) {
        free_cni_opt_result_route(val->routes[i]);
        val->routes[i] = NULL;
    }
    free(val->routes);
    val->routes = NULL;
    free_cni_opt_result_dns(val->my_dns);
    val->my_dns = NULL;
    free(val);
}
