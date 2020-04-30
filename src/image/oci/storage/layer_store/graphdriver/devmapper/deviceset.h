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
* Description: provide devicemapper graphdriver function definition
******************************************************************************/
#ifndef __GRAPHDRIVER_DEVICESET_H
#define __GRAPHDRIVER_DEVICESET_H

#include <pthread.h>
#include "driver.h"
#include "metadata_store.h"
#include "device_setup.h"
#include "map.h"
#include "image_devmapper_transaction.h"
#include "image_devmapper_deviceset_metadata.h"

#ifdef __cplusplus
extern "C" {
#endif


struct device_set {
    char *root;
    char *device_prefix;
    uint64_t transaction_id;
    int next_device_id; // deviceset-metadata
    map_t *device_id_map;

    // options
    int64_t data_loop_back_size;
    int64_t meta_data_loop_back_size;
    uint64_t base_fs_size;
    char *filesystem;
    char *mount_options;
    char **mkfs_args; // []string类型数组切片
    size_t mkfs_args_len;
    char *data_device;
    char *data_loop_file;
    char *metadata_device;
    char *metadata_loop_file;
    uint64_t thinp_block_size;
    bool do_blk_discard;
    char *thin_pool_device;

    image_devmapper_transaction *metadata_trans;

    bool override_udev_sync_check;
    bool deferred_remove;
    bool deferred_delete;
    char *base_device_uuid;
    char *base_device_filesystem;
    uint nr_deleted_devices; // number of deleted devices
    uint32_t min_free_space_percent;
    char *xfs_nospace_retries; // max retries when xfs receives ENOSPC
    int64_t udev_wait_timeout;

    image_devmapper_direct_lvm_config *lvm_setup_config;
};

struct device_metadata {
    int device_id;
    uint64_t device_size;
    char *device_name;
};

struct devmapper_conf {
    pthread_rwlock_t devmapper_driver_rwlock;
    struct device_set *devset;
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

int device_init(struct graphdriver *driver, const char *drvier_home, const char **options, size_t len);

int devmapper_conf_rdlock();
int devmapper_conf_wrlock();
int devmapper_conf_unlock();
struct device_set *devmapper_driver_devices_get();

int add_device(const char *hash, const char *base_hash, const json_map_string_string *storage_opts);
int mount_device(const char *hash, const char *path, const struct driver_mount_opts *mount_opts);
int unmount_device(const char *hash, const char *mount_path);
bool has_device(const char *hash);

int delete_device(const char *hash, bool sync_delete);

int export_device_metadata(struct device_metadata *dev_metadata, const char *hash);
struct status *device_set_status();
void free_devmapper_status(struct status *st);


#ifdef __cplusplus
}
#endif

#endif
