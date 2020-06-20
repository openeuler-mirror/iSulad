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
 * Description: provide container logs definition
 ******************************************************************************/
#ifndef __CMD_LOGS_H
#define __CMD_LOGS_H

#include "client_arguments.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LOGS_OPTIONS(cmdargs)                                                                                         \
    { CMD_OPT_TYPE_BOOL, false, "follow", 'f', &(cmdargs).follow, "Follow log output", NULL },                        \
    {                                                                                                                 \
                                                                                                                      CMD_OPT_TYPE_CALLBACK, false, "tail", 0, &(cmdargs).tail, "Number of lines to show from the end of the logs", \
                                                                                                                      callback_tail                                                                                         \
    }

extern const char g_cmd_logs_desc[];
extern const char g_cmd_logs_usage[];
extern struct client_arguments g_cmd_logs_args;

int callback_tail(command_option_t *option, const char *arg);
int cmd_logs_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif /* __CMD_LOGS_H */
