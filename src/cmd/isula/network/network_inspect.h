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
 * Description: provide network inspect definition
 ******************************************************************************/
#ifndef CMD_ISULA_NETWORK_INSPECT_H
#define CMD_ISULA_NETWORK_INSPECT_H

#include "client_arguments.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NETWORK_INSPECT_OPTIONS(cmdargs)                        \
    {                                                           \
        CMD_OPT_TYPE_STRING,                                    \
        false,                                                  \
        "format",                                               \
        'f',                                                    \
        &(cmdargs).format,                                      \
        "Format the output using the given go template",        \
        NULL                                                    \
    },

extern const char g_cmd_network_inspect_desc[];
extern const char g_cmd_network_inspect_usage[];
extern struct client_arguments g_cmd_network_inspect_args;
int cmd_network_inspect_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_NETWORK_INSPECT_H
