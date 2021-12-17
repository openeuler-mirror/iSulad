/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhangxiaoyu
 * Create: 2020-09-02
 * Description: provide network definition
 ******************************************************************************/
#ifndef CMD_ISULA_NETWORK_H
#define CMD_ISULA_NETWORK_H

#include "network_create.h"
#include "network_inspect.h"
#include "network_list.h"
#include "network_remove.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const char g_cmd_network_desc[];
extern const char g_cmd_network_usage[];
int cmd_network_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_NETWORK_H
