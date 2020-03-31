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
* Create: 2020-01-19
* Description: provide devicemapper graphdriver function definition
******************************************************************************/
#ifndef __GRAPHDRIVER_DEVMAPPER_H
#define __GRAPHDRIVER_DEVMAPPER_H

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
    bool do_blk_discard;
    uint32_t thin_block_size;
    char *thin_pool_device;

    image_devmapper_transaction *metadata_trans;
    
    bool overrid_udev_sync_check;
    bool deferred_remove;
    bool deferred_delete;
    char *base_device_uuid;
    char *base_device_filesystem;
    uint nr_deleted_devices; // number of deleted devices
    uint32_t min_free_space_percent;
    char *xfs_nospace_retries; // max retries when xfs receives ENOSPC

    image_devmapper_direct_lvm_config *lvm_setup_config;
};

struct devmapper_conf {
    pthread_rwlock_t devmapper_driver_rwlock;
    struct device_set *devset;
};

int devmapper_init(struct graphdriver *driver, const char *drvier_home, const char **options, size_t len);

bool devmapper_is_quota_options(struct graphdriver *driver, const char *option);

int devmapper_create_rw(const char *id, const char *parent, const struct graphdriver *driver,
                       const struct driver_create_opts *create_opts);

int devmapper_rm_layer(const char *id, const struct graphdriver *driver);

char *devmapper_mount_layer(const char *id, const struct graphdriver *driver,
                           const struct driver_mount_opts *mount_opts);

int devmapper_umount_layer(const char *id, const struct graphdriver *driver);

bool devmapper_layer_exists(const char *id, const struct graphdriver *driver);

int devmapper_apply_diff(const char *id, const struct graphdriver *driver, const struct io_read_wrapper *content,
                        int64_t *layer_size);

int devmapper_get_layer_metadata(const char *id, const struct graphdriver *driver, json_map_string_string *map_info);

int devmapper_get_driver_status(const struct graphdriver *driver, struct graphdriver_status *status);

int devmapper_driver_wrlock();

int devmapper_driver_rdlock();

int devmapper_driver_unlock();

#ifdef __cplusplus
}
#endif

#endif
