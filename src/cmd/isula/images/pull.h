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
 * Author: lifeng
 * Create: 2019-3-29
 * Description: provide pull image
 ********************************************************************************/

#ifndef __CMD_PULL_IMAGE_H
#define __CMD_PULL_IMAGE_H

#include "client_arguments.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const char g_cmd_pull_desc[];
extern const char g_cmd_pull_usage[];
extern struct client_arguments g_cmd_pull_args;
int client_pull(const struct client_arguments *args);

int cmd_pull_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif /* __CMD_PULL_IMAGE_H */
