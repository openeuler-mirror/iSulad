/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2017-11-22
 * Description: provide container attach definition
 ******************************************************************************/
#ifndef __CMD_ATTACH_H
#define __CMD_ATTACH_H

#include "arguments.h"
#include "container_inspect.h"
#include "wait.h"

extern const char g_cmd_attach_desc[];
extern const char g_cmd_attach_usage[];
extern struct client_arguments g_cmd_attach_args;
int inspect_container(const struct client_arguments *args, container_inspect **inspect_data);
int cmd_attach_main(int argc, const char **argv);
#endif /* __CMD_ATTACH_H */

