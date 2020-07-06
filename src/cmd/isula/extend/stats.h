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
 * Description: provide container stats definition
 ******************************************************************************/
#ifndef __CMD_STATS_H
#define __CMD_STATS_H

#include <stdbool.h>
#include <stddef.h>

#include "client_arguments.h"
#include "command_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STATUS_OPTIONS(cmdargs)                                         \
    {                                                                   \
        CMD_OPT_TYPE_BOOL,                                              \
        false,                                                          \
        "all",                                                          \
        'a',                                                            \
        &(cmdargs).showall,                                             \
        "Show all containers (default shows just running)",             \
        NULL                                                            \
    },                                                                  \
    { CMD_OPT_TYPE_BOOL,                                        \
      false,                                                    \
      "no-stream",                                              \
      0,                                                        \
      &(cmdargs).nostream,                                      \
      "Disable streaming stats and only pull the first result", \
      NULL },

extern const char g_cmd_stats_desc[];
extern const char g_cmd_stats_usage[];
extern struct client_arguments g_cmd_stats_args;
int cmd_stats_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif /* __CMD_STATS_H */
