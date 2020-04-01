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

#include "wrapper_devmapper.h"
#include "log.h"


struct dm_task* task_create(int type)
{
    struct dm_task *dmt = NULL;

    dmt = dm_task_create(type);
    return dmt;
}

int set_name(struct dm_task *dmt, const char *name)
{
    int ret;

    ret = dm_task_set_name(dmt, name);
    if (ret != 1) {
        return -1;
    }

    return 0;
}

int set_message(struct dm_task *dmt, const char *message)
{
    int ret;

    ret = dm_task_set_message(dmt, message);
    if (ret != 1) {
        return -1;
    }

    return 0;
}

int set_sector(struct dm_task *dmt, uint64_t sector)
{
    int ret;

    ret = dm_task_set_sector(dmt, sector);
    if (ret != 1) {
        return -1;
    }

    return 0;
}

int set_add_node(struct dm_task *dmt, dm_add_node_t add_node)
{
    int ret;

    ret = dm_task_set_add_node(dmt, add_node);
    if (ret != 1) {
        return -1;
    }

    return 0;
}

int set_ro(struct dm_task *dmt)
{
    int ret;

    ret = dm_task_set_ro(dmt);
    if (ret != 1) {
        return -1;
    }

    return 0;
}


int set_dev_dir(const char *dir)
{
    int ret;

    ret = dm_set_dev_dir(dir);
    if (ret != 1) {
        return -1;
    }

    return 0;
}

struct dm_task* task_create_named(int type, const char *pool_dev_name)
{
    int ret;
    struct dm_task *dmt = NULL;

    // struct dm_task *dm_task_create(int type);
    dmt = dm_task_create(type);
    if (dmt == NULL) {
        ERROR("devicemapper: Can't create task of type %d", type);
        return dmt;
    }

    ret = dm_task_set_name(dmt, pool_dev_name);
    if (ret != 1) {
        ERROR("devicemapper: Can't set task pool name %s", pool_dev_name);
        goto cleanup;
    }

    return dmt;

cleanup:
    free(dmt);
    dmt = NULL;
    return NULL;
}

// GetTable is the programmatic example for "dmsetup table".
// It outputs the current table for the specified device name.
int get_table(uint64_t *start, uint64_t *length, char **target_type, char **params, const char *name)
{
    int ret = 0;
    struct dm_task *dmt = NULL;
    struct dm_info info;

    dmt = task_create_named(DM_DEVICE_TABLE, name);
    if (dmt == NULL) {
        ERROR("devicemapper:create named task failed");
        return -1;
    }

    ret = dm_task_run(dmt);
    if (ret != 1) {
        ERROR("devicemapper: task run failed");
        goto cleanup;
    }
    // int dm_task_get_info(struct dm_task *dmt, struct dm_info *dmi);
    ret = dm_task_get_info(dmt, &info);
    if (ret != 1) {
        ERROR("devicemapper: get info err");
        goto cleanup;
    }

    if (info.exists == 0) {
        ERROR("devicemapper: GetTable() Non existing device %s", name);
        ret = -1;
        goto cleanup;
    }
    // void *dm_get_next_target(struct dm_task *dmt,
    //                      void *next, uint64_t *start, uint64_t *length,
    //                      char **target_type, char **params);
    (void)dm_get_next_target(dmt, NULL, start, length, target_type, params);

cleanup:
    free(dmt);
    return ret;
}

// GetStatus is the programmatic example of "dmsetup status".
// It outputs status information for the specified device name.
int get_status(uint64_t *start, uint64_t *length, char **target_type, char **params, const char *name)
{
    int ret = 0;
    struct dm_task *dmt = NULL;
    struct dm_info info;

    dmt = task_create_named(DM_DEVICE_STATUS, name);
    if (dmt == NULL) {
        return -1;
    }

    ret = dm_task_run(dmt);
    if (ret != 1) {
        ret = -1;
        ERROR("devicemapper: task run failed");
        goto cleanup;
    }

    ret = dm_task_get_info(dmt, &info);
    if (ret != 1) {
        ret = -1;
        ERROR("devicemapper: get info err");
        goto cleanup;
    }

    if (info.exists == 0) {
        ERROR("devicemapper: GetTable() Non existing device %s", name);
        ret = -1;
        goto cleanup;
    }

    (void)dm_get_next_target(dmt, NULL, start, length, target_type, params);
    ret = 0;

cleanup:
    free(dmt);
    return ret;
}

int get_info(struct dm_info *info, const char *name)
{
    int ret = 0;
    struct dm_task *dmt = NULL;

    dmt = task_create_named(DM_DEVICE_INFO, name);
    if (dmt == NULL) {
        return -1;
    }

    ret = dm_task_run(dmt);
    if (ret != 1) {
        ret = -1;
        ERROR("devicemapper: task run failed");
        goto cleanup;
    }

    ret = dm_task_get_info(dmt, info);
    if (ret != 1) {
        ret = -1;
        ERROR("devicemapper: get info err");
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(dmt);
    return ret;
}

// cookie值为获取到的
int set_cookie(struct dm_task *dmt, uint32_t *cookie, uint16_t flags)
{
    // int dm_task_set_cookie(struct dm_task *dmt, uint32_t *cookie, uint16_t flags);
    int ret;

    if (cookie == NULL) {
        ERROR("cookie ptr can't be nil");
        return -1;
    }

    ret = dm_task_set_cookie(dmt, cookie, flags);
    if (ret != 1) {
        ERROR("dm_task_set_cookie failed");
        return -1;
    }

    return 0;
}

int remove_device(const char *name)
{
    int ret = 0;
    struct dm_task *dmt = NULL;
    uint32_t cookie;

    dmt = task_create_named(DM_DEVICE_REMOVE, name);
    if (dmt == NULL) {
        return -1;
    }

    ret = set_cookie(dmt, &cookie, 0);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    ret = dm_task_run(dmt);
    if (ret != 1) {
        ret = -1;
        goto out;
    }

    // TODO: udev_wait(cookie)
    // 单开一个线程wait device删除成功

    ret = 0;
out:
    free(dmt);
    return ret;
}

// from devmapper_wrapper.go
// FIXME: how to use dm_task_get_names directly
static char **local_dm_task_get_names(struct dm_task *dmt, size_t *size)
{
    struct dm_names *ns, *ns1;
    unsigned next = 0;
    char **result;
    int i = 0;

    if (!(ns = dm_task_get_names(dmt))) {
        return NULL;
    }

    // No devices found
    if (!ns->dev) {
        return NULL;
    }

    // calucate the total devices
    ns1 = ns;
    *size = 0;
    do {
        ns1 = (struct dm_names *)((char *) ns1 + next);
        (*size)++;
        next = ns1->next;
    } while (next);

    result = malloc(sizeof(char *) * (*size));
    if (!result) {
        return NULL;
    }

    next = 0;
    do {
        ns = (struct dm_names *)((char *) ns + next);
        result[i++] = strdup(ns->name);
        next = ns->next;
    } while (next);

    return result;
}

int get_device_list(char ***list, size_t *length)
{
    int ret = 0;
    struct dm_task *dmt = NULL;

    if (list == NULL || length == NULL) {
        return -1;
    }

    dmt = task_create(DM_DEVICE_LIST);
    if (dmt == NULL) {
        ERROR("devicemapper:create named task status failed");
        return -1;
    }

    ret = dm_task_run(dmt);
    if (ret != 1) {
        ret = -1;
        ERROR("devicemapper: task run failed");
        goto cleanup;
    }


    *list = local_dm_task_get_names(dmt, length);
    if (*list == NULL) {
        *length = 0;
        ret = -1;
        ERROR("devicemapper: get device list failed");
        goto cleanup;
    }

    free(dmt);
    return 0;

cleanup:
    free(dmt);
    return ret;
}

bool udev_set_sync_support(bool enable)
{
    int enable_sync = 1;
    int unenable_sync = 0;
    int ret;

    if (enable) {
        dm_udev_set_sync_support(enable_sync);
    } else {
        dm_udev_set_sync_support(unenable_sync);
    }

    ret = dm_udev_get_sync_support();
    if (ret != 0) {
        return true;
    }

    return false;
}

// poolName : /dev/mapper/thin-pool
// CreateDevice creates a device with the specified poolName with the specified device id.
int dev_create_device(const char *pool_fname, int device_id)
{
    int ret = 0;
    uint64_t sector = 0;
    char message[PATH_MAX] = { 0 }; // 临时字符缓冲区上限
    struct dm_task *dmt = NULL;

    dmt = task_create_named(DM_DEVICE_TARGET_MSG, pool_fname);
    if (dmt == NULL) {
        ERROR("devicemapper:create named task failed");
        return -1;
    }

    ret = set_sector(dmt, sector);
    if (ret != 0) {
        ret = -1;
        ERROR("devicemapper: Can't set sector");
        goto cleanup;
    }

    if (snprintf(message, sizeof(message), "create_thin %d", device_id) < 0) {
        ret = -1;
        // ERROR()
        goto cleanup;
    }

    ret = set_message(dmt, message);
    if (ret != 0) {
        ret = -1;
        goto cleanup;
    }


    ret = dm_task_run(dmt);
    if (ret != 1) {
        ret = -1;
        ERROR("devicemapper: task run failed");
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(dmt);
    return ret;
}

int dev_delete_device(const char *pool_fname, int device_id)
{
    int ret = 0;
    uint64_t sector = 0;
    char message[PATH_MAX] = { 0 }; // 临时字符缓冲区上限
    struct dm_task *dmt = NULL;

    if (pool_fname == NULL) {
        ERROR("devicemapper: pool full name is NULL");
        return -1;
    }

    dmt = task_create_named(DM_DEVICE_TARGET_MSG, pool_fname);
    if (dmt == NULL) {
        ERROR("devicemapper:create named task %s failed", pool_fname);
        return -1;
    }

    ret = set_sector(dmt, sector);
    if (ret != 0) {
        ret = -1;
        ERROR("devicemapper: Can't set sector");
        goto cleanup;
    }

    if (snprintf(message, sizeof(message), "delete %d", device_id) < 0) {
        ret = -1;
        // ERROR()
        goto cleanup;
    }

    ret = set_message(dmt, message);
    if (ret != 0) {
        ret = -1;
        goto cleanup;
    }

    ret = dm_task_run(dmt);
    if (ret != 1) {
        ret = -1;
        ERROR("devicemapper: task run failed");
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(dmt);
    return ret;
}