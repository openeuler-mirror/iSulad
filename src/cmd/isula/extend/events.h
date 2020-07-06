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
 * Description: provide container events definition
 ******************************************************************************/
#ifndef __CMD_EVENT_H
#define __CMD_EVENT_H

#include <stdbool.h>
#include <stddef.h>

#include "client_arguments.h"
#include "command_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EVENTS_OPTIONS(cmdargs)                                                                  \
    { CMD_OPT_TYPE_STRING, false, "name", 'n', &(cmdargs).name, "Name of the container", NULL }, \
    { CMD_OPT_TYPE_STRING,                                                               \
      false,                                                                             \
      "since",                                                                           \
      'S',                                                                               \
      &(cmdargs).since,                                                                  \
      "Show all events created since this timestamp",                                    \
      NULL },                                                                            \
    { CMD_OPT_TYPE_STRING,                                                               \
      false,                                                                             \
      "until",                                                                           \
      'U',                                                                               \
      &(cmdargs).until,                                                                  \
      "Show all events created until this timestamp",                                    \
      NULL },

extern const char g_cmd_events_desc[];
extern const char g_cmd_events_usage[];
extern struct client_arguments g_cmd_events_args;
int cmd_events_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif /* __CMD_EVENT_H */
