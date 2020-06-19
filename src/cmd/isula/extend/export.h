/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangfengtu
 * Create: 2019-04-04
 * Description: provide container resume definition
 ******************************************************************************/
#ifndef __CMD_EXPORT_H
#define __CMD_EXPORT_H

#include "client_arguments.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EXPORT_OPTIONS(cmdargs)                                                             \
    {                                                                                       \
        CMD_OPT_TYPE_STRING, false, "output", 'o', &(cmdargs).file, "Write to a file", NULL \
    }

extern const char g_cmd_export_desc[];
extern const char g_cmd_export_usage[];
extern struct client_arguments g_cmd_export_args;
int cmd_export_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif
