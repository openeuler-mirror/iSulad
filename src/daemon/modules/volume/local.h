/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
* Author: wangfengtu
* Create: 2020-09-07
* Description: provide isula local volume definition
*******************************************************************************/
#ifndef DAEMON_MODULES_VOLUME_LOCAL_H
#define DAEMON_MODULES_VOLUME_LOCAL_H

#include "volume_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int register_local_volume(char *root_dir);

struct volume * local_volume_create(char *name);

struct volume * local_volume_get(char *name);

int local_volume_mount(char *name);

int local_volume_umount(char *name);

struct volumes * local_volume_list(void);

int local_volume_remove(char *name);

char *local_volume_driver_name();

#ifdef __cplusplus
}
#endif

#endif // DAEMON_MODULES_VOLUME_LOCAL_H
