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
 * Author: jikai
 * Create: 2023-11-22
 * Description: provide lib device mapper mock
 ******************************************************************************/

#include "libdevmapper_mock.h"

namespace {
MockLibdevmapper *g_libdevmapper_mock = nullptr;
}

void MockLibdevmapper_SetMock(MockLibdevmapper* mock)
{
    g_libdevmapper_mock = mock;
}

struct dm_task *dm_task_create(int type)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMTaskCreate(type);
    }
    return nullptr;
}

int dm_task_set_message(struct dm_task *dmt, const char *msg)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMTaskSetMessage(dmt, msg);
    }
    return 0;
}

int dm_task_set_sector(struct dm_task *dmt, uint64_t sector)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMTaskSetSector(dmt, sector);
    }
    return 0;
}

int dm_task_set_add_node(struct dm_task *dmt, dm_add_node_t add_node)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMTaskSetAddNode(dmt, add_node);
    }
    return 0;
}

int dm_task_add_target(struct dm_task *dmt, uint64_t start, uint64_t size, const char *ttype, const char *params)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMTaskAddTarget(dmt, start, size, ttype, params);
    }
    return 0;
}

int dm_set_dev_dir(const char *dir)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMSetDevDir(dir);
    }
    return 0;
}

int dm_task_set_name(struct dm_task *dmt, const char *name)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMTaskSetName(dmt, name);
    }
    return 0;
}

int dm_task_run(struct dm_task *dmt)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMTaskRun(dmt);
    }
    return 0;
}

int dm_task_get_driver_version(struct dm_task *dmt, char *version, size_t size)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMTaskGetDriverVersion(dmt, version, size);
    }
    return 0;
}

void dm_task_destroy(struct dm_task *dmt)
{
    if (g_libdevmapper_mock != nullptr) {
        g_libdevmapper_mock->DMTaskDestroy(dmt);
    }
}

int dm_get_library_version(char *version, size_t size)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMGetLibraryVersion(version, size);
    }
    return 0;
}

int dm_task_get_info(struct dm_task *dmt, struct dm_info *info)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMTaskGetInfo(dmt, info);
    }
    return 0;
}

void *dm_get_next_target(struct dm_task *dmt, void *next, uint64_t *start, uint64_t *length,
                         char **target_type, char **params)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMGetNextTarget(dmt, next, start, length, target_type, params);
    }
    return nullptr;
}

int dm_task_set_cookie(struct dm_task *dmt, uint32_t *cookie, uint16_t flags)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMTaskSetCookie(dmt, cookie, flags);
    }
    return 0;
}

int dm_udev_wait(uint32_t cookie)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMUdevWait(cookie);
    }
    return 0;
}

int dm_udev_complete(uint32_t cookie)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMUdevComplete(cookie);
    }
    return 0;
}

int dm_task_deferred_remove(struct dm_task *dmt)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMTaskDeferredRemove(dmt);
    }
    return 0;
}

struct dm_names *dm_task_get_names(struct dm_task *dmt)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMTaskGetNames(dmt);
    }
    return nullptr;
}

int dm_udev_get_sync_support(void)
{
    if (g_libdevmapper_mock != nullptr) {
        return g_libdevmapper_mock->DMUdevGetSyncSupport();
    }
    return 0;
}

void dm_udev_set_sync_support(int sync_with_udev)
{
    if (g_libdevmapper_mock != nullptr) {
        g_libdevmapper_mock->DMUdevSetSyncSupport(sync_with_udev);
    }
}

void dm_log_with_errno_init(void log_cb(int level, const char *file, int line, int dm_errno_or_class, const char *f, ...))
{
    if (g_libdevmapper_mock != nullptr) {
        g_libdevmapper_mock->DMLogWithErrnoInit(log_cb);
    }
}
