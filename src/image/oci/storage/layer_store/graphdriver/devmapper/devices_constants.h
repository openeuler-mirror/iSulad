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

#ifndef __DEVICES_CONSTANTS_
#define __DEVICES_CONSTANTS_

#include "map.h"
#include "isula_libutils/image_devmapper_transaction.h"
#include "isula_libutils/image_devmapper_deviceset_metadata.h"
#include "isula_libutils/image_devmapper_direct_lvm_config.h"

#define DEVICE_SET_METAFILE "deviceset-metadata"
#define TRANSACTION_METADATA "transaction-metadata"
#define DEVICE_DIRECTORY "/dev"
#define DEVMAPPER_DECICE_DIRECTORY "/dev/mapper/"
#define DEFAULT_THIN_BLOCK_SIZE 128
#define DEFAULT_METADATA_LOOPBACK_SIZE (2 * 1024 * 1024 * 1024)
// #define DEFAULT_BASE_FS_SIZE (10 * 1024 * 1024 * 1024)
#define DEFAULT_UDEV_SYNC_OVERRIDE false
#define MAX_DEVICE_ID (0xffffff) // 24 bit, pool limit

#define DEFAULT_UDEV_WAITTIMEOUT 185
#define DEFAULT_MIN_FREE_SPACE_PERCENT 10

#define DEFAULT_DEVICE_SET_MODE 0700

typedef struct {
    map_t *map; // map string image_devmapper_device_info*   key string will be strdup  value ptr will not
} metadata_store_t;

struct device_set {
    char *root;
    char *device_prefix;
    uint64_t transaction_id;
    int next_device_id; // deviceset-metadata
    map_t *device_id_map;

    metadata_store_t *meta_store; // store all devices infos
    pthread_rwlock_t devmapper_driver_rwlock; //protect all fields of DeviceSet

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

    bool driver_deferred_removal_support;
    bool enable_deferred_removal;
    bool enable_deferred_deletion;
    bool user_base_size;
};

#endif