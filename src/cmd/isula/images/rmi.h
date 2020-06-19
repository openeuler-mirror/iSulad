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
 * Description: provide container remove definition
 ******************************************************************************/
#ifndef __CMD_REMOVE_IMAGE_H
#define __CMD_REMOVE_IMAGE_H

#include "client_arguments.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RMI_OPTIONS(cmdargs)                                                                         \
    {                                                                                                \
        CMD_OPT_TYPE_BOOL, false, "force", 'f', &(cmdargs).force, "Force removal of the image", NULL \
    }

extern const char g_cmd_rmi_desc[];
extern const char g_cmd_rmi_usage[];
extern struct client_arguments g_cmd_rmi_args;
int cmd_rmi_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif /* __CMD_REMOVE_IMAGE_H */
