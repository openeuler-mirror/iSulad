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
 * Description: provide container supervisor definition
 ******************************************************************************/
#ifndef __ISULAD_CONTAINER_OPERATOR_H
#define __ISULAD_CONTAINER_OPERATOR_H
#include <pthread.h>
#include <semaphore.h>
#include "container_unix.h"

#ifdef __cplusplus
extern "C" {
#endif

int start_container(container_t *cont, const char *console_fifos[], bool reset_rm);

int clean_container_resource(const char *id, const char *runtime, pid_t pid);

int cleanup_container(container_t *cont, bool force);

int stop_container(container_t *cont, int timeout, bool force, bool restart);

int set_container_to_removal(const container_t *cont);

int cleanup_mounts_by_id(const char *id, const char *engine_root_path);

void umount_host_channel(const host_config_host_channel *host_channel);

void umount_share_shm(container_t *cont);

int kill_with_signal(container_t *cont, uint32_t signal);

int force_kill(container_t *cont);

bool container_in_gc_progress(const char *id);

#ifdef __cplusplus
}
#endif

#endif
