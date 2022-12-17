/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2022-12-17
 * Description: provide client helpers function definition
 ******************************************************************************/
#ifndef CMD_ISULA_CLIENT_HELPERS_H
#define CMD_ISULA_CLIENT_HELPERS_H

#include "isula_libutils/container_inspect.h"
#include "client_arguments.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

int inspect_container(const struct client_arguments *args, container_inspect **inspect_data);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif // CMD_ISULA_CLIENT_HELPERS_H

