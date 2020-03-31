/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
* iSulad licensed under the Mulan PSL v1.
* You can use this software according to the terms and conditions of the Mulan PSL v1.
* You may obtain a copy of Mulan PSL v1 at:
*     http://license.coscl.org.cn/MulanPSL
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
* PURPOSE.
* See the Mulan PSL v1 for more details.
* Author: gaohuatao
* Create: 2020-01-19
* Description: wrap libdevmapper function to manuplite devicemapper
******************************************************************************/
#ifndef __WRAPPER_DEVMAPPER_H
#define __WRAPPER_DEVMAPPER_H

#include <libdevmapper.h>
#include <stdbool.h>

#include "driver.h"

#ifdef __cplusplus
extern "C" {
#endif

// typedef enum {
//     DM_DEVICE_CREATE,
//     DM_DEVICE_RELOAD,
//     DM_DEVICE_REMOVE,
//     DM_DEVICE_REMOVE_ALL,
//     DM_DEVICE_SUSPEND,
//     DM_DEVICE_RESUME,
//     DM_DEVICE_INFO,
//     DM_DEVICE_DEPS,
//     DM_DEVICE_RENAME,
//     DM_DEVICE_VERSION,
//     DM_DEVICE_STATUS,
//     DM_DEVICE_TABLE,
//     DM_DEVICE_WAITEVENT,
//     DM_DEVICE_LIST,
//     DM_DEVICE_CLEAR,
//     DM_DEVICE_MKNODES,
//     DM_DEVICE_LIST_VERSIONS,
//     DM_DEVICE_TARGET_MSG,
//     DM_DEVICE_SET_GEOMETRY
// } task_type_t;



struct dm_task* task_create(int type);

int set_name(struct dm_task *dmt, const char *name);

int set_message(struct dm_task *dmt, const char *message);

int set_sector(struct dm_task *dmt, uint64_t sector);

int set_cookie(struct dm_task *dmt, uint32_t *cookie, uint16_t flags);

int set_add_node(struct dm_task *dmt, dm_add_node_t add_node);

int set_ro(struct dm_task *dmt);

int set_dev_dir(const char *dir);

struct dm_task* task_create_named(int type, const char *name);


int get_table(uint64_t *start, uint64_t *length, char **target_type, char **params, const char *name);

int get_status(uint64_t *start, uint64_t *length, char **target_type, char **params, const char *name);

int get_info(struct dm_info *info, const char *name);

int remove_device(const char *name);

int get_device_list(char ***list, size_t *length);

bool udev_set_sync_support(bool enable);

int dev_create_device(const char *pool_dev_name, int device_id);

int dev_delete_device(const char *pool_fname, int device_id);

#ifdef __cplusplus
}
#endif

#endif

