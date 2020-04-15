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
#define _GNU_SOURCE
#include <sys/time.h>
#include <stdio.h>

#include "wrapper_devmapper.h"
#include "log.h"
#include "utils_verify.h"
#include "utils.h"

static bool dm_saw_busy = false;
static bool dm_saw_exist = false;
static bool dm_saw_enxio = false; // no such device or address
// static bool dm_saw_eno_data = false; // no data available
static int64_t dm_udev_wait_timeout = 0;


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

    if (add_node != DM_ADD_NODE_ON_RESUME && add_node != DM_ADD_NODE_ON_CREATE) {
        return ERR_INVALID_ADD_NODE;
    }

    ret = dm_task_set_add_node(dmt, add_node);
    if (ret != 1) {
        return ERR_TASK_SET_ADD_NODE;
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
static int add_target(struct dm_task *dmt, uint64_t start, uint64_t size, const char *ttype, const char *params)
{
    int ret = 0;

    ret = dm_task_add_target(dmt, start, size, ttype, params);
    if (ret != 1) {
        ret = ERR_TASK_ADD_TARGET;
    }

    return ret;
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

struct dm_task* task_create_named(int type, const char *dm_name)
{
    int ret;
    struct dm_task *dmt = NULL;

    // struct dm_task *dm_task_create(int type);
    dmt = dm_task_create(type);
    if (dmt == NULL) {
        ERROR("devicemapper: Can't create task of type %d", type);
        return dmt;
    }

    ret = dm_task_set_name(dmt, dm_name);
    if (ret != 1) {
        ERROR("devicemapper: Can't set task name %s", dm_name);
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
int dev_get_table(uint64_t *start, uint64_t *length, char **target_type, char **params, const char *name)
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
int dev_get_status(uint64_t *start, uint64_t *length, char **target_type, char **params, const char *name)
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

int dev_get_info(struct dm_info *info, const char *name)
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
        return ERR_NIL_COOKIE;
    }

    ret = dm_task_set_cookie(dmt, cookie, flags);
    if (ret != 1) {
        ERROR("dm_task_set_cookie failed");
        return ERR_TASK_SET_COOKIE;
    }

    return 0;
}

static void *udev_wait_process(void *data)
{
    udev_wait_pth_t *uwait = (udev_wait_pth_t *)data;
    int ret;

    ret = dm_udev_wait(uwait->cookie);
    if (ret != 1) {
        pthread_mutex_lock(&uwait->udev_mutex);
        uwait->state = ERR_UDEV_WAIT;
        pthread_mutex_unlock(&uwait->udev_mutex);
        pthread_exit((void *)ERR_UDEV_WAIT);
    }

    pthread_mutex_lock(&uwait->udev_mutex);
    uwait->state = DEV_OK;
    pthread_mutex_unlock(&uwait->udev_mutex);
    pthread_exit((void *)0);
}

// UdevWait waits for any processes that are waiting for udev to complete the specified cookie.
void dev_udev_wait(uint32_t cookie)
{
    pthread_t tid;
    int thread_result;
    udev_wait_pth_t *uwait = NULL;
    int ret = 0;
    float timeout = 0;
    struct timeval start, end;

    ret = gettimeofday(&start, NULL);
    if (ret != 0) {
        ERROR("devmapper: get time failed");
        goto free_out;
    }

    uwait = util_common_calloc_s(sizeof(udev_wait_pth_t));
    if (uwait == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    uwait->cookie = cookie;
    uwait->state = DEV_INIT;

    ret = pthread_mutex_init(&uwait->udev_mutex, NULL);
    if (ret != 0) {
        ERROR("Udev mutex initialized failed");
        goto free_out;
    }

    ret = pthread_create(&tid, NULL, udev_wait_process, uwait);
    if (ret != 0) {
        ERROR("devmapper: create udev wait process thread failed");
        goto free_out;
    }

    while (true) {
        pthread_mutex_lock(&uwait->udev_mutex);
        if (uwait->state != DEV_INIT) {
            goto free_out;
        }
        pthread_mutex_unlock(&uwait->udev_mutex);

        ret = gettimeofday(&end, NULL);
        if (ret != 0) {
            ERROR("devmapper: get time failed");
            goto free_out;
        }
        timeout = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000; // seconds
        if (timeout >= (float)dm_udev_wait_timeout) {
            ret = dm_udev_complete(cookie);
            if (ret != 1) {
                goto free_out;
            }
            INFO("devmapper: udev wait join thread start...");
            pthread_join(tid, (void *)&thread_result);
            INFO("devmapper: udev wait join thread end exit %d", thread_result);
            break;
        }
    }

free_out:
    pthread_mutex_destroy(&uwait->udev_mutex);
    UTIL_FREE_AND_SET_NULL(uwait);
}

int dev_remove_device(const char *pool_fname)
{
    int ret = 0;
    struct dm_task *dmt = NULL;
    uint32_t cookie;

    dmt = task_create_named(DM_DEVICE_REMOVE, pool_fname);
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

int dev_remove_device_deferred(const char *pool_fname)
{
    int ret = 0;
    struct dm_task *dmt = NULL;
    uint32_t cookie;
    uint16_t flags = DM_UDEV_DISABLE_LIBRARY_FALLBACK;

    dmt = task_create_named(DM_DEVICE_REMOVE, pool_fname);
    if (dmt == NULL) {
        return -1;
    }

    ret = dm_task_deferred_remove(dmt);
    if (ret != 1) {
        // ERROR();
        return ERR_TASK_DEFERRED_REMOVE;
    }

    ret = set_cookie(dmt, &cookie, flags);
    if (ret != 0) {
        ret = -1;
        goto out;
    }


    // TODO: udev_wait(cookie)
    // 单开一个线程wait device删除成功

    dm_saw_enxio = false;
    ret = dm_task_run(dmt);
    if (ret != 1) {
        ret = ERR_TASK_RUN;
        if (dm_saw_enxio) {
            ret = ERR_ENXIO;
        }
        ERROR("devicemapper: Error running RemoveDeviceDeferred %d", ret);
    }

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

int dev_get_device_list(char ***list, size_t *length)
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

int dev_get_info_with_deferred(const char *dm_name, struct dm_info *dmi)
{
    int ret = 0;
    struct dm_task *dmt = NULL;

    dmt = task_create_named(DM_DEVICE_INFO, dm_name);
    if (dmt == NULL) {
        return -1;
    }

    ret = dm_task_run(dmt);
    if (ret != 1) {
        ret = -1;
        ERROR("devicemapper: task run failed");
        goto cleanup;
    }

    ret = dm_task_get_info(dmt, dmi);
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

// SuspendDevice is the programmatic example of "dmsetup suspend".
// It suspends the specified device.
int dev_suspend_device(const char *dm_name)
{
    int ret = 0;
    struct dm_task *dmt = NULL;

    dmt = task_create_named(DM_DEVICE_SUSPEND, dm_name);
    if (dmt == NULL) {
        ret = -1;
        ERROR("devicemapper:create named task failed");
        goto out;
    }

    ret = dm_task_run(dmt);
    if (ret != 1) {
        ret = -1;
        ERROR("devicemapper: Error running deviceCreate (ActivateDevice) %d", ret);
    }

out:
    free(dmt);
    return ret;
}

// ResumeDevice is the programmatic example of "dmsetup resume".
// It un-suspends the specified device.
int dev_resume_device(const char *dm_name)
{
    int ret = 0;
    uint32_t cookie;
    uint16_t flags = 0;
    struct dm_task *dmt = NULL;

    dmt = task_create_named(DM_DEVICE_SUSPEND, dm_name);
    if (dmt == NULL) {
        ret = -1;
        ERROR("devicemapper:create named task failed");
        goto out;
    }

    ret = set_cookie(dmt, &cookie, flags);
    if (ret != 0) {
        ERROR("devicemapper: Can't set cookie %d", ret);
        goto out;
    }

    ret = dm_task_run(dmt);
    if (ret != 1) {
        ret = -1;
        ERROR("devicemapper: Error running deviceResume %d", ret);
    }

    dev_udev_wait(cookie);

out:
    free(dmt);
    return ret;
}

int dev_active_device(const char *pool_name, const char *name, int device_id, uint64_t size)
{
    int ret = 0;
    uint64_t start = 0;
    uint32_t cookie;
    uint16_t flags = 0;
    char params[PATH_MAX] = { 0 };
    struct dm_task *dmt = NULL;
    dm_add_node_t add_node_type = DM_ADD_NODE_ON_CREATE;

    dmt = task_create_named(DM_DEVICE_CREATE, name);
    if (dmt == NULL) {
        ERROR("devicemapper:create named task failed");
        goto out;
    }

    ret = snprintf(params, sizeof(params), "%s %d", pool_name, device_id);
    if (ret < 0) {
        // ERROR();
        goto out;
    }

    ret = add_target(dmt, start, size / 512, "thin", params);
    if (ret != 0) {
        ERROR("devicemapper: Can't add target");
        goto out;
    }

    ret = set_add_node(dmt, add_node_type);
    if (ret != 0) {
        ERROR("devicemapper: Can't add node");
        goto out;
    }

    ret = set_cookie(dmt, &cookie, flags);
    if (ret != 0) {
        ERROR("devicemapper: Can't set cookie %d", ret);
        goto out;
    }

    ret = dm_task_run(dmt);
    if (ret != 1) {
        ERROR("devicemapper: Error running deviceCreate (ActivateDevice) %d", ret);
    }

    dev_udev_wait(cookie);

out:
    free(dmt);
    return ret;
}

int dev_cancel_deferred_remove(const char *dm_name)
{
    int ret = 0;
    uint64_t sector = 0;
    struct dm_task *dmt = NULL;

    dmt = task_create_named(DM_DEVICE_TARGET_MSG, dm_name);
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

    ret = set_message(dmt, "@cancel_deferred_remove");
    if (ret != 0) {
        ret = -1;
        goto cleanup;
    }

    dm_saw_busy = false;
    dm_saw_enxio = false;
    ret = dm_task_run(dmt);
    if (ret != 1) {
        if (dm_saw_busy) {
            return ERR_BUSY;
        } else if (dm_saw_enxio) {
            return ERR_ENXIO;
        }
        ret = -1;
        ERROR("devicemapper: Error running CancelDeferredRemove");
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(dmt);
    return ret;
}

// DMLog is the logging callback containing all of the information from devicemapper.
static void dm_log(int level, char *file, int line, int dm_errno_or_class, char *message)
{
    switch (level) {
        case LOG_LEVEL_FATAL:
        case LOG_LEVEL_ERR:
            ERROR("libdevmapper(%d): %s:%d (%d) %s", level, file, line, dm_errno_or_class, message);
            break;
        case LOG_LEVEL_WARN:
            WARN("libdevmapper(%d): %s:%d (%d) %s", level, file, line, dm_errno_or_class, message);
            break;
        case LOG_LEVEL_NOTICE:
        case LOG_LEVEL_INFO:
            INFO("libdevmapper(%d): %s:%d (%d) %s", level, file, line, dm_errno_or_class, message);
            break;
        case LOG_LEVEL_DEBUG:
            DEBUG("libdevmapper(%d): %s:%d (%d) %s", level, file, line, dm_errno_or_class, message);
            break;
        default:
            INFO("libdevmapper(%d): %s:%d (%d) %s", level, file, line, dm_errno_or_class, message);
    }

}

void storage_devmapper_log_callback(int level, char *file, int line, int dm_errno_or_class, char *message)
{
    if (level < LOG_LEVEL_DEBUG) {
        if (strstr(message, "busy") != NULL) {
            dm_saw_busy = true;
        }
        if (strstr(message, "File exist") != NULL) {
            dm_saw_exist = true;
        }

        if (strstr(message, "No such device or address") != NULL) {
            dm_saw_enxio = true;
        }
    }
    dm_log(level, file, line, dm_errno_or_class, message);
}

static void	log_cb(int level, const char *file, int line, int dm_errno_or_class, const char *f, ...)
{
    char *buffer = NULL;
    va_list ap;
    int ret;

    va_start(ap, f);
    ret = vasprintf(&buffer, f, ap);
    va_end(ap);
    if (ret < 0) {
        // memory allocation failed -- should never happen?
        return;
    }

    storage_devmapper_log_callback(level, (char *)file, line, dm_errno_or_class, buffer);
    free(buffer);
}

void log_with_errno_init()
{
    dm_log_with_errno_init(log_cb);
}

// BlockDeviceDiscard runs discard for the given path.
// This is used as a workaround for the kernel not discarding block so
// on the thin pool when we remove a thinp device, so we do it
// manually
int dev_block_device_discard(const char *path)
{
    return 0;
}

// CreateSnapDeviceRaw creates a snapshot device. Caller needs to suspend and resume the origin device if it is active.
int dev_create_snap_device_raw(const char *pool_name, int device_id, int base_device_id)
{
    int ret = 0;
    uint64_t sector = 0;
    char message[PATH_MAX] = { 0 }; // 临时字符缓冲区上限
    struct dm_task *dmt = NULL;

    dmt = task_create_named(DM_DEVICE_TARGET_MSG, pool_name);
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

    if (snprintf(message, sizeof(message), "create_snap %d %d", device_id, base_device_id) < 0) {
        ret = -1;
        // ERROR()
        goto cleanup;
    }

    ret = set_message(dmt, message);
    if (ret != 0) {
        ret = -1;
        ERROR("devicemapper: Can't set message %s", message);
        goto cleanup;
    }

    dm_saw_exist = false;
    ret = dm_task_run(dmt);
    if (ret != 1) {
        if (dm_saw_exist) {
            ret = ERR_DEVICE_ID_EXISTS;
        } else {
            ret = -1;
        }
        ERROR("devicemapper: Error running deviceCreate (CreateSnapDeviceRaw)");
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(dmt);
    return ret;
}

// SetTransactionID sets a transaction id for the specified device name.
int dev_set_transaction_id(const char *pool_name, uint64_t old_id, uint64_t new_id)
{
    int ret = 0;
    uint64_t sector = 0;
    char message[PATH_MAX] = { 0 }; // 临时字符缓冲区上限
    struct dm_task *dmt = NULL;

    if (pool_name == NULL) {
        ERROR("devicemapper: pool full name is NULL");
        return -1;
    }

    dmt = task_create_named(DM_DEVICE_TARGET_MSG, pool_name);
    if (dmt == NULL) {
        ERROR("devicemapper:create named task %s failed", pool_name);
        return -1;
    }

    ret = set_sector(dmt, sector);
    if (ret != 0) {
        ret = -1;
        ERROR("devicemapper: Can't set sector");
        goto cleanup;
    }

    if (snprintf(message, sizeof(message), "set_transaction_id %lu %lu", old_id, new_id) < 0) {
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