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
 * Author: zhangxiaoyu
 * Create: 2020-09-02
 * Description: provide network remove definition
 ******************************************************************************/
#ifndef CMD_ISULA_NETWORK_REMOVE_H
#define CMD_ISULA_NETWORK_REMOVE_H

#include "client_arguments.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NETWORK_REMOVE_OPTIONS(cmdargs)                         \
    {                                                           \
        CMD_OPT_TYPE_BOOL,                                      \
        false,                                                  \
        "force",                                                \
        'f',                                                    \
        &(cmdargs).force,                                       \
        "Force to remove the containers using this network",    \
        NULL                                                    \
    },

extern const char g_cmd_network_remove_desc[];
extern const char g_cmd_networ_remove_usage[];
extern struct client_arguments g_cmd_network_remove_args;
int cmd_network_remove_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_NETWORK_REMOVE_H
