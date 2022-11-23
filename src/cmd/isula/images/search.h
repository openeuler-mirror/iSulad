/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2022-10-17
 * Description: provide search image
 ********************************************************************************/

#ifndef CMD_ISULA_IMAGES_SEARCH_H
#define CMD_ISULA_IMAGES_SEARCH_H

#include "client_arguments.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SEARCH_OPTIONS(cmdargs)                                                                                        \
    {                                                                                                                  \
        CMD_OPT_TYPE_CALLBACK,                                                                                         \
        false,                                                                                                         \
        "limit",                                                                                                       \
        0,                                                                                                             \
        &((cmdargs).limit),                                                                                            \
        "Max number of search results(default 25)",                                                                    \
        command_convert_uint                                                                                           \
    },                                                                                                                 \
    {                                                                                                                  \
        CMD_OPT_TYPE_CALLBACK,                                                                                         \
        false,                                                                                                         \
        "filter",                                                                                                      \
        'f',                                                                                                           \
        &((cmdargs).filters),                                                                                          \
        "Filter output based on conditions provided",                                                                  \
        command_append_array                                                                                           \
    },                                                                                                                 \
    {                                                                                                                  \
        CMD_OPT_TYPE_BOOL,                                                                                             \
        false,                                                                                                         \
        "no-trunc",                                                                                                    \
        0,                                                                                                             \
        &((cmdargs).no_trunc),                                                                                         \
        "Dont't truncate output",                                                                                      \
        NULL                                                                                                           \
    },                                                                                                                 \
    {                                                                                                                  \
        CMD_OPT_TYPE_STRING,                                                                                           \
        false,                                                                                                         \
        "format",                                                                                                      \
        0,                                                                                                             \
        &((cmdargs).format),                                                                                           \
        "Format the output using the given go template",                                                               \
        NULL                                                                                                           \
    },

extern const char g_cmd_search_desc[];
extern const char g_cmd_search_usage[];
extern struct client_arguments g_cmd_search_args;

int cmd_search_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_IMAGES_SEARCH_H
