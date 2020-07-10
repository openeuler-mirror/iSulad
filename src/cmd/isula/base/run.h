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
 * Description: provide container run definition
 ******************************************************************************/
#ifndef CMD_ISULA_BASE_RUN_H
#define CMD_ISULA_BASE_RUN_H

#include <stdbool.h>
#include <stddef.h>

#include "create.h"
#include "start.h"
#include "client_arguments.h"
#include "command_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RUN_OPTIONS(cmdargs)                                      \
    { CMD_OPT_TYPE_BOOL,                                          \
        false,                                                      \
        "detach",                                                   \
        'd',                                                        \
        &(cmdargs).detach,                                          \
        "Run container in background and print container ID",       \
        NULL },                                                     \
    { CMD_OPT_TYPE_BOOL,                                  \
      false,                                              \
      "rm",                                               \
      0,                                                  \
      &(cmdargs).custom_conf.auto_remove,                 \
      "Automatically remove the container when it exits", \
      NULL },

extern const char g_cmd_run_desc[];
extern const char g_cmd_run_usage[];
extern struct client_arguments g_cmd_run_args;
int cmd_run_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_BASE_RUN_H
