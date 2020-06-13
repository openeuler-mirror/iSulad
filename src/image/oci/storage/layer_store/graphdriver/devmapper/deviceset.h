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
* Description: provide devicemapper graphdriver function definition
******************************************************************************/
#ifndef __GRAPHDRIVER_DEVICESET_H
#define __GRAPHDRIVER_DEVICESET_H

#include <pthread.h>
#include "driver.h"
#include "metadata_store.h"
#include "device_setup.h"

#ifdef __cplusplus
extern "C" {
#endif

struct device_metadata {
    int device_id;
    uint64_t device_size;
    char *device_name;
};

struct disk_usage {
    // Used bytes on the disk.
    uint64_t used;
    // Total bytes on the disk.
    uint64_t total;
    // Available bytes on the disk.
    uint64_t available;
};

struct status {
    char *pool_name;
    char *data_file;
    char *data_loopback;
    char *metadata_file;
    char *metadata_loopback;
    struct disk_usage metadata;
    struct disk_usage data;
    uint64_t base_device_size;
    char *base_device_fs;
    uint64_t sector_size;
    bool udev_sync_supported;
    bool deferred_remove_enabled;
    bool deferred_delete_enabled;
    unsigned int deferred_deleted_device_count;
    uint64_t min_free_space;
};

int device_set_init(struct graphdriver *driver, const char *drvier_home, const char **options, size_t len);

struct device_set *devmapper_driver_devices_get();

int add_device(const char *hash, const char *base_hash, struct device_set *devset,
               const json_map_string_string *storage_opts);
int mount_device(const char *hash, const char *path, const struct driver_mount_opts *mount_opts,
                 struct device_set *devset);
int unmount_device(const char *hash, const char *mount_path, struct device_set *devset);
bool has_device(const char *hash, struct device_set *devset);

int delete_device(const char *hash, bool sync_delete, struct device_set *devset);

int export_device_metadata(struct device_metadata *dev_metadata, const char *hash, struct device_set *devset);
struct status *device_set_status();
void free_devmapper_status(struct status *st);

#ifdef __cplusplus
}
#endif

#endif
