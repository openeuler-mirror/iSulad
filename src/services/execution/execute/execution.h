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
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container list callback function definition
 *******************************************************************************/

#ifndef __EXECUTION_H_
#define __EXECUTION_H_

#include "callback.h"
#include "container_unix.h"

#ifdef __cplusplus
extern "C" {
#endif

void container_callback_init(service_container_callback_t *cb);

int start_container(container_t *cont, const char *console_fifos[], bool reset_rm);

int clean_container_resource(const char *id, const char *runtime, pid_t pid);

int cleanup_container(container_t *cont, bool force);

int stop_container(container_t *cont, int timeout, bool force, bool restart);

int set_container_to_removal(const container_t *cont);

int cleanup_mounts_by_id(const char *id, const char *engine_root_path);

#ifdef __cplusplus
}
#endif

#endif

