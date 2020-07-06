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
 * Description: provide container exec definition
 ******************************************************************************/
#ifndef __CMD_EXEC_H
#define __CMD_EXEC_H

#include <stdbool.h>
#include <stddef.h>

#include "client_arguments.h"
#include "attach.h"
#include "command_parser.h"

#define EXEC_OPTIONS(cmdargs)                                                                                    \
    {                                                                                                            \
        CMD_OPT_TYPE_CALLBACK, false, "env", 'e', &(cmdargs).extra_env, "Set environment variables",             \
        command_append_array                                                                                     \
    },                                                                                                           \
    { CMD_OPT_TYPE_BOOL, false, "detach", 'd', &(cmdargs).detach, "Run container in background", NULL }, \
    { CMD_OPT_TYPE_BOOL, false, "tty", 't', &(cmdargs).custom_conf.tty, "Allocate a pseudo-TTY", NULL }, \
    { CMD_OPT_TYPE_BOOL,                                                                                 \
        false,                                                                                             \
        "interactive",                                                                                     \
        'i',                                                                                               \
        &(cmdargs).custom_conf.open_stdin,                                                                 \
        "Keep STDIN open even if not attached",                                                            \
        NULL },                                                                                            \
    {                                                                                                            \
        CMD_OPT_TYPE_STRING_DUP, false, "user", 'u', &(cmdargs).custom_conf.user,                                \
        "Username or UID (format: <name|uid>[:<group|gid>])", NULL                                       \
    }

extern const char g_cmd_exec_desc[];
extern const char g_cmd_exec_usage[];
extern struct client_arguments g_cmd_exec_args;
int cmd_exec_main(int argc, const char **argv);

#endif /* __CMD_EXEC_H */
