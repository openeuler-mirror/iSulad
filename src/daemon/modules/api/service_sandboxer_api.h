/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-01-18
 * Description: provide sandbox supervisor definition
 ******************************************************************************/

#ifndef DAEMON_MODULES_API_SERVICE_SANDBOXER_API_H
#define DAEMON_MODULES_API_SERVICE_SANDBOXER_API_H
#include "controller_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int create_sandbox(sandbox_t *sandbox);

int start_sandbox(sandbox_t *sandbox);

int stop_sandbox(sandbox_t *sandbox);

int delete_sandbox(sandbox_t *sandbox, bool force);

int update_sandbox_status(sandbox_t *sandbox);

#ifdef __cplusplus
}
#endif

#endif /* DAEMON_MODULES_API_SERVICE_SANDBOXER_API_H */
