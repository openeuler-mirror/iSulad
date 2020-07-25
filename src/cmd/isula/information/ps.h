/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide container ps definition
 ******************************************************************************/
#ifndef CMD_ISULA_INFORMATION_PS_H
#define CMD_ISULA_INFORMATION_PS_H

#include <stdbool.h>
#include <stddef.h>

#include "client_arguments.h"
#include "command_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LIST_OPTIONS(cmdargs)                                                                                        \
    { CMD_OPT_TYPE_BOOL,                                                                                             \
        false,                                                                                                         \
        "all",                                                                                                         \
        'a',                                                                                                           \
        &(cmdargs).list_all,                                                                                           \
        "Display all containers (default shows just running)",                                                         \
        NULL },                                                                                                        \
    { CMD_OPT_TYPE_BOOL, false, "quiet", 'q', &(cmdargs).dispname, "Only display numeric IDs", NULL },       \
    { CMD_OPT_TYPE_CALLBACK,                                                                                 \
      false,                                                                                                 \
      "filter",                                                                                              \
      'f',                                                                                                   \
      &(cmdargs).filters,                                                                                    \
      "Filter output based on conditions provided",                                                          \
      command_append_array },                                                                                \
    { CMD_OPT_TYPE_BOOL, false, "no-trunc", 0, &(cmdargs).no_trunc, "Don't truncate output", NULL },         \
    {                                                                                                                \
                                                                                                                     CMD_OPT_TYPE_STRING, false, "format", 0, &(cmdargs).format, "Format the output using the given go template", \
                                                                                                                     NULL                                                                                                 \
    }

extern const char g_cmd_list_desc[];
extern const char g_cmd_list_usage[];
extern struct client_arguments g_cmd_list_args;
int cmd_list_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_INFORMATION_PS_H
