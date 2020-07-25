/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangfengtu
 * Description: provide login definition
 ******************************************************************************/
#ifndef CMD_ISULA_IMAGES_LOGIN_H
#define CMD_ISULA_IMAGES_LOGIN_H

#include <stdbool.h>
#include <stddef.h>

#include "client_arguments.h"
#include "command_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LOGIN_OPTIONS(cmdargs)                                                                      \
    { CMD_OPT_TYPE_STRING, false, "username", 'u', &(cmdargs).username, "Username", NULL },         \
    { CMD_OPT_TYPE_STRING, false, "password", 'p', &(cmdargs).password, "Password", NULL }, \
    { CMD_OPT_TYPE_BOOL,                                                                    \
      false,                                                                                \
      "password-stdin",                                                                     \
      0,                                                                                    \
      &(cmdargs).password_stdin,                                                            \
      "Take the password from stdin",                                                       \
      NULL },

extern const char g_cmd_login_desc[];
extern const char g_cmd_login_usage[];
extern struct client_arguments g_cmd_login_args;
int cmd_login_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_IMAGES_LOGIN_H
