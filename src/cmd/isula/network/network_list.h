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
 * Description: provide network list definition
 ******************************************************************************/
#ifndef CMD_ISULA_NETWORK_LIST_H
#define CMD_ISULA_NETWORK_LIST_H

#include "client_arguments.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NETWORK_LIST_OPTIONS(cmdargs)                                                               \
    {                                                                                               \
        CMD_OPT_TYPE_BOOL,                                                                          \
        false,                                                                                      \
        "quiet",                                                                                    \
        'q',                                                                                        \
        &(cmdargs).dispname,                                                                        \
        "Only display network names",                                                               \
        NULL                                                                                        \
    },                                                                                              \
    {                                                                                               \
        CMD_OPT_TYPE_CALLBACK,                                                                      \
        false,                                                                                      \
        "filter",                                                                                   \
        'f',                                                                                        \
        &(cmdargs).filters,                                                                         \
        "Filter output based on conditions provided (specify string matching name or plugin)",      \
        command_append_array                                                                        \
    },

extern const char g_cmd_network_list_desc[];
extern const char g_cmd_network_list_usage[];
extern struct client_arguments g_cmd_network_list_args;
int cmd_network_list_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_NETWORK_LIST_H
