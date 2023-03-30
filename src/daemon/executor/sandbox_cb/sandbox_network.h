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
 * Author: xuxuepeng
 * Create: 2023-02-21
 * Description: sandbox network related operations
 * TODO: Merge this with execution_network
 *******************************************************************************/

#ifndef DAEMON_EXECUTOR_SANDBOX_CB_SANDBOX_NETWORK_H
#define DAEMON_EXECUTOR_SANDBOX_CB_SANDBOX_NETWORK_H

#include <isula_libutils/sandbox_config.h>
#include <isula_libutils/host_config.h>

#include "callback.h"
#include "sandbox_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int init_sandbox_network_confs(const char *sandbox_id, const char *rootpath,
                               host_config *hostconfig, sandbox_config *sandboxconfig);

#ifdef __cplusplus
}
#endif

#endif

