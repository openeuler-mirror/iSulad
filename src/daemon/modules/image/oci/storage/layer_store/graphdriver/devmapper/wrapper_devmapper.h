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
* Author: gaohuatao
* Create: 2020-01-19
* Description: wrap libdevmapper function to manuplite devicemapper
******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_OCI_STORAGE_LAYER_STORE_GRAPHDRIVER_DEVMAPPER_WRAPPER_DEVMAPPER_H
#define DAEMON_MODULES_IMAGE_OCI_STORAGE_LAYER_STORE_GRAPHDRIVER_DEVMAPPER_WRAPPER_DEVMAPPER_H

#include <libdevmapper.h>
#include <stdbool.h>
#include <semaphore.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "driver.h"

struct dm_task;

#ifdef __cplusplus
extern "C" {
#endif

#define DEV_ERR -1
#define DEV_OK 0
#define DEV_INIT 1

typedef enum {
    ERR_TASK_RUN = 2,
    ERR_TASK_SET_NAME,
    ERR_TASK_SET_MESSAGE,
    ERR_TASK_SET_ADD_NODE, // dm_task_set_add_node failed
    ERR_TASK_SET_RO, // dm_task_set_ro failed
    ERR_TASK_ADD_TARGET, //dm_task_add_target failed
    ERR_TASK_SET_SECTOR,
    ERR_TASK_GET_DEPS,
    ERR_TASK_GET_INFO,
    ERR_TASK_GET_DRIVER_VERSION,
    ERR_TASK_GET_NAMES,
    ERR_TASK_DEFERRED_REMOVE,
    ERR_TASK_SET_COOKIE, //dm_task_set_cookie failed
    ERR_NIL_COOKIE, //cookie ptr can't be nil
    ERR_GET_BLOCK_SIZE,
    ERR_UDEV_WAIT,
    ERR_UDEV_WAIT_TIMEOUT,
    ERR_SET_DEV_DIR,
    ERR_GET_LIBRARY_VERSION,
    ERR_CREATE_REMOVE_TASK,
    ERR_RUN_REMOVE_DEVICE,
    ERR_INVALID_ADD_NODE, // Invalid AddNode type
    ERR_BUSY, // Device is Busy
    ERR_DEVICE_ID_EXISTS,
    ERR_ENXIO // No such device or address
} dm_err_t;

typedef enum {
    LOG_LEVEL_FATAL = 2,
    LOG_LEVEL_ERR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_NOTICE,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
} dm_log_level_t;

typedef struct {
    uint32_t cookie;
    pthread_mutex_t udev_mutex;
    int state; // 0: ok 1:err_udev_wait  2: err_udev_wait_timeout
} udev_wait_pth_t;

char *dev_strerror(int errnum);

struct dm_task* task_create(int type);

int set_message(struct dm_task *dmt, const char *message);

int set_sector(struct dm_task *dmt, uint64_t sector);

int set_add_node(struct dm_task *dmt, dm_add_node_t add_node);

void set_udev_wait_timeout(int64_t t);

int set_dev_dir(const char *dir);

struct dm_task* task_create_named(int type, const char *name);

void log_with_errno_init();

char *dev_get_driver_version();

int dev_get_status(uint64_t *start, uint64_t *length, char **target_type, char **params, const char *name);

int dev_get_info(struct dm_info *info, const char *name);

int dev_delete_device_force(const char *name);

int dev_remove_device_deferred(const char *name);

int dev_get_device_list(char ***list, size_t *length);

bool udev_sync_supported();

bool udev_set_sync_support(bool enable);

int dev_create_device(const char *pool_dev_name, int device_id);

int dev_delete_device(const char *pool_fname, int device_id);

int dev_get_info_with_deferred(const char *dm_name, struct dm_info *dmi);

int dev_suspend_device(const char *dm_name);

int dev_resume_device(const char *dm_name);

int dev_active_device(const char *pool_name, const char *name, int device_id, uint64_t size);

void dev_udev_wait(uint32_t cookie);

int dev_cancel_deferred_remove(const char *dm_name);

int dev_create_snap_device_raw(const char *pool_name, int device_id, int base_device_id);

int dev_set_transaction_id(const char *pool_name, uint64_t old_id, uint64_t new_id);

#ifdef __cplusplus
}
#endif

#endif

