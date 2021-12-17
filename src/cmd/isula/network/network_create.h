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
 * Author: zhangxiaoyu
 * Create: 2020-09-02
 * Description: provide network create definition
 ******************************************************************************/
#ifndef CMD_ISULA_NETWORK_CREATE_H
#define CMD_ISULA_NETWORK_CREATE_H

#include "client_arguments.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NETWORK_CREATE_OPTIONS(cmdargs)                         \
    {                                                           \
        CMD_OPT_TYPE_STRING,                                    \
        false,                                                  \
        "driver",                                               \
        'd',                                                    \
        &(cmdargs).driver,                                      \
        "Driver to manager the network (default \"bridge\")",   \
        NULL                                                    \
    },                                                          \
    {                                                           \
        CMD_OPT_TYPE_STRING_DUP,                                \
        false,                                                  \
        "gateway",                                              \
        0,                                                      \
        &(cmdargs).gateway,                                     \
        "IPv4 or IPv6 gateway for the subnet",                  \
        NULL                                                    \
    },                                                          \
    {                                                           \
        CMD_OPT_TYPE_BOOL,                                      \
        false,                                                  \
        "internal",                                             \
        0,                                                      \
        &(cmdargs).internal,                                    \
        "Restrict external access from this network",           \
        NULL                                                    \
    },                                                          \
    {                                                           \
        CMD_OPT_TYPE_STRING_DUP,                                \
        false,                                                  \
        "subnet",                                               \
        0,                                                      \
        &(cmdargs).subnet,                                      \
        "Subnet in CIDR format",                                \
        NULL                                                    \
    },

extern const char g_cmd_network_create_desc[];
extern const char g_cmd_network_create_usage[];
extern struct client_arguments g_cmd_network_create_args;
int cmd_network_create_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_NETWORK_CREATE_H
