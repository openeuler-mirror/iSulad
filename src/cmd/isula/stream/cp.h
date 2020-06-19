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
 * Author: tanyifeng
 * Create: 2019-04-17
 * Description: provide container cp definition
 ******************************************************************************/
#ifndef __CMD_COPY_H
#define __CMD_COPY_H

#include "client_arguments.h"

extern const char g_cmd_cp_desc[];
extern const char g_cmd_cp_usage[];
extern struct client_arguments g_cmd_cp_args;
int cmd_cp_main(int argc, const char **argv);

#endif /* __CMD_COPY_H */
