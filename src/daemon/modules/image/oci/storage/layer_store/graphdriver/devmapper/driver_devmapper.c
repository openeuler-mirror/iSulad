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
#include "driver_devmapper.h"

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/mount.h>
#include <stdio.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "devices_constants.h"
#include "deviceset.h"
#include "isula_libutils/json_common.h"
#include "util_archive.h"
#include "constants.h"
#include "driver.h"
#include "image_api.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_fs.h"
#include "utils_string.h"

struct io_read_wrapper;

int devmapper_init(struct graphdriver *driver, const char *driver_home, const char **options, size_t len)
{
    int ret = 0;
    char *root_dir = NULL;

    if (driver == NULL || driver_home == NULL) {
        ERROR("Invalid input params");
        return -1;
    }

    driver->home = util_strdup_s(driver_home);

    root_dir = util_path_dir(driver_home);
    if (root_dir == NULL) {
        ERROR("Unable to get driver root home directory %s.", driver_home);
        ret = -1;
        goto out;
    }

    driver->backing_fs = util_get_fs_name(root_dir);
    if (driver->backing_fs == NULL) {
        ERROR("Failed to get backing fs");
        ret = -1;
        goto out;
    }

    if (util_mkdir_p(driver_home, DEFAULT_DEVICE_SET_MODE) != 0) {
        ERROR("Unable to create driver home directory %s.", driver_home);
        ret = -1;
        goto out;
    }

    if (device_set_init(driver, driver_home, options, len) != 0) {
        ERROR("Unable to init device mapper.");
        ret = -1;
        goto out;
    }

out:
    free(root_dir);
    return ret;
}

static int do_create(const char *id, const char *parent, const struct graphdriver *driver,
                     const struct driver_create_opts *create_opts)
{
    int ret = 0;
    char *mnt_parent_dir = NULL;
    char *mnt_point_dir = NULL;

    mnt_parent_dir = util_path_join(driver->home, "mnt");
    if (mnt_parent_dir == NULL) {
        ERROR("Failed to join devmapper mnt dir %s", id);
        ret = -1;
        goto out;
    }

    mnt_point_dir = util_path_join(mnt_parent_dir, id);
    if (mnt_point_dir == NULL) {
        ERROR("Failed to join devampper mount point dir %s", id);
        ret = -1;
        goto out;
    }

    if (util_mkdir_p(mnt_point_dir, DEFAULT_SECURE_DIRECTORY_MODE) != 0) {
        ERROR("Failed to mkdir path:%s", mnt_point_dir);
        ret = -1;
        goto out;
    }

    ret = add_device(id, parent, driver->devset, create_opts->storage_opt);

out:
    free(mnt_parent_dir);
    free(mnt_point_dir);
    return ret;
}

// devmapper_create_rw creates a layer that is writable for use as a container file system
int devmapper_create_rw(const char *id, const char *parent, const struct graphdriver *driver,
                        struct driver_create_opts *create_opts)
{
    if (id == NULL || driver == NULL || create_opts == NULL) {
        ERROR("invalid argument");
        return -1;
    }

    return do_create(id, parent, driver, create_opts);
}

// Create adds a device with a given id and the parent.
int devmapper_create_ro(const char *id, const char *parent, const struct graphdriver *driver,
                        const struct driver_create_opts *create_opts)
{
    if (id == NULL || driver == NULL || create_opts == NULL) {
        ERROR("invalid argument");
        return -1;
    }

    return do_create(id, parent, driver, create_opts);
}

// Remove removes a device with a given id, unmounts the filesystem.
int devmapper_rm_layer(const char *id, const struct graphdriver *driver)
{
    char *mnt_parent_dir = NULL;
    char *mnt_point_dir = NULL;
    int ret = 0;

    if (!util_valid_str(id) || driver == NULL) {
        ERROR("invalid argument");
        return -1;
    }

    if (!has_device(id, driver->devset)) {
        DEBUG("Device with id:%s is not exist", id);
        goto out;
    }

    if (delete_device(id, false, driver->devset) != 0) {
        ERROR("failed to remove device %s", id);
        ret = -1;
        goto out;
    }

    mnt_parent_dir = util_path_join(driver->home, "mnt");
    if (mnt_parent_dir == NULL) {
        ERROR("Failed to join devmapper mnt dir %s", id);
        ret = -1;
        goto out;
    }

    mnt_point_dir = util_path_join(mnt_parent_dir, id);
    if (mnt_point_dir == NULL) {
        ERROR("Failed to join devampper mount point dir %s", id);
        ret = -1;
        goto out;
    }

    if (util_path_remove(mnt_point_dir) != 0) {
        ERROR("Remove path:%s failed", mnt_point_dir);
        ret = -1;
        goto out;
    }

out:
    free(mnt_parent_dir);
    free(mnt_point_dir);
    return ret;
}

// devmapper_mount_layer mounts a device with given id into the root filesystem
char *devmapper_mount_layer(const char *id, const struct graphdriver *driver,
                            const struct driver_mount_opts *mount_opts)
{
    char *mnt_point_dir = NULL;
    char *mnt_parent_dir = NULL;
    char *rootfs = NULL;
    char *id_file = NULL;
    int ret = 0;

    if (!util_valid_str(id) || driver == NULL) {
        return NULL;
    }

    mnt_parent_dir = util_path_join(driver->home, "mnt");
    if (mnt_parent_dir == NULL) {
        ERROR("Failed to join devmapper mnt dir%s", id);
        ret = -1;
        goto out;
    }

    mnt_point_dir = util_path_join(mnt_parent_dir, id);
    if (mnt_point_dir == NULL) {
        ERROR("Failed to join devampper mount point dir:%s", id);
        ret = -1;
        goto out;
    }

    if (mount_device(id, mnt_point_dir, mount_opts, driver->devset) != 0) {
        ERROR("Mount device:%s to path:%s failed", id, mnt_point_dir);
        ret = -1;
        goto out;
    }

    rootfs = util_path_join(mnt_point_dir, "rootfs");
    if (rootfs == NULL) {
        ERROR("Failed to join devmapper rootfs %s", mnt_point_dir);
        ret = -1;
        goto out;
    }

    if (util_mkdir_p(rootfs, DEFAULT_HIGHEST_DIRECTORY_MODE) != 0 || !util_dir_exists(rootfs)) {
        ERROR("Unable to create devmapper rootfs directory %s.", rootfs);
        ret = -1;
        if (unmount_device(id, mnt_point_dir, driver->devset) != 0) {
            DEBUG("devmapper: unmount %s failed", mnt_point_dir);
        }
        goto out;
    }

    id_file = util_path_join(mnt_point_dir, "id");
    if (!util_file_exists(id_file)) {
        if (util_atomic_write_file(id_file, id, strlen(id), SECURE_CONFIG_FILE_MODE, true) != 0) {
            if (unmount_device(id, mnt_point_dir, driver->devset) != 0) {
                DEBUG("devmapper: unmount %s failed", mnt_point_dir);
            }
        }
    }

out:
    free(mnt_parent_dir);
    free(mnt_point_dir);
    free(id_file);
    if (ret != 0) {
        free(rootfs);
        rootfs = NULL;
    }
    return rootfs;
}

int devmapper_umount_layer(const char *id, const struct graphdriver *driver)
{
    int ret = 0;
    char *mp = NULL;
    char *mnt_dir = NULL;

    if (!util_valid_str(id) || driver == NULL) {
        ERROR("Invalid input params to umount layer with id(%s)", id);
        return -1;
    }

    mnt_dir = util_path_join(driver->home, "mnt");
    if (mnt_dir == NULL) {
        ERROR("Failed to join layer dir mnt");
        ret = -1;
        goto out;
    }

    mp = util_path_join(mnt_dir, id);
    if (mp == NULL) {
        ERROR("Failed to join layer dir:%s", id);
        ret = -1;
        goto out;
    }

    if (unmount_device(id, mp, driver->devset) != 0) {
        ERROR("devmapper: unmount %s failed", mp);
        ret = -1;
        goto out;
    }

out:
    free(mnt_dir);
    free(mp);
    return ret;
}

static void free_driver_mount_opts(struct driver_mount_opts *opts)
{
    if (opts == NULL) {
        return;
    }
    free(opts->mount_label);
    opts->mount_label = NULL;

    util_free_array_by_len(opts->options, opts->options_len);
    opts->options = NULL;

    free(opts);
}

bool devmapper_layer_exist(const char *id, const struct graphdriver *driver)
{
    return has_device(id, driver->devset);
}

int devmapper_apply_diff(const char *id, const struct graphdriver *driver, const struct io_read_wrapper *content)
{
    struct driver_mount_opts *mount_opts = NULL;
    char *layer_fs = NULL;
    int ret = 0;
    struct archive_options options = { 0 };
    char *err = NULL;

    if (!util_valid_str(id) || driver == NULL || content == NULL) {
        ERROR("invalid argument to apply diff with id(%s)", id);
        return -1;
    }

    mount_opts = util_common_calloc_s(sizeof(struct driver_mount_opts));
    if (mount_opts == NULL) {
        ERROR("devmapper: out of memory");
        ret = -1;
        goto out;
    }

    layer_fs = devmapper_mount_layer(id, driver, mount_opts);
    if (layer_fs == NULL) {
        ERROR("devmapper: failed to mount layer %s", id);
        ret = -1;
        goto out;
    }

    options.whiteout_format = REMOVE_WHITEOUT_FORMATE;
    if (archive_unpack(content, layer_fs, &options, &err) != 0) {
        ERROR("devmapper: failed to unpack to %s: %s", layer_fs, err);
        ret = -1;
        goto out;
    }

    if (devmapper_umount_layer(id, driver) != 0) {
        ERROR("devmapper: failed to umount layer %s", id);
        ret = -1;
        goto out;
    }

out:
    free_driver_mount_opts(mount_opts);
    free(layer_fs);
    free(err);
    return ret;
}

int devmapper_get_layer_metadata(const char *id, const struct graphdriver *driver, json_map_string_string *map_info)
{
    int ret = 0;
    char *mnt_dir = NULL;
    char *id_dir = NULL;
    char *rootfs_dir = NULL;
    struct device_metadata dev_metadata = { 0 };
    char *device_id_str = NULL;
    char *device_size_str = NULL;

    if (!util_valid_str(id) || driver == NULL || map_info == NULL) {
        ERROR("invalid argument");
        ret = -1;
        goto out;
    }

    if (export_device_metadata(&dev_metadata, id, driver->devset) != 0) {
        ERROR("Failed to export device metadata of device %s", id);
        ret = -1;
        goto out;
    }

    device_id_str = util_int_to_string(dev_metadata.device_id);
    if (device_id_str == NULL) {
        ERROR("Failed to map long long int to string");
        ret = -1;
        goto out;
    }

    device_size_str = util_uint_to_string(dev_metadata.device_size);
    if (device_size_str == NULL) {
        ERROR("Failed to map long long unsigned int to string");
        ret = -1;
        goto out;
    }

    mnt_dir = util_path_join(driver->home, "mnt");
    if (mnt_dir == NULL) {
        ERROR("Failed to join mnt dir");
        ret = -1;
        goto out;
    }

    id_dir = util_path_join(mnt_dir, id);
    if (id_dir == NULL) {
        ERROR("Failed to join devmapper id dir:%s", id);
        ret = -1;
        goto out;
    }
    rootfs_dir = util_path_join(id_dir, "rootfs");
    if (rootfs_dir == NULL) {
        ERROR("Failed to join devmapper rootfs dir");
        ret = -1;
        goto out;
    }

    if (append_json_map_string_string(map_info, "DeviceId", device_id_str) != 0) {
        ERROR("Failed to append device id:%s", device_id_str);
        ret = -1;
        goto out;
    }

    if (append_json_map_string_string(map_info, "DeviceSize", device_size_str) != 0) {
        ERROR("Failed to append device size:%s", device_size_str);
        ret = -1;
        goto out;
    }

    if (append_json_map_string_string(map_info, "DeviceName", dev_metadata.device_name) != 0) {
        ERROR("Failed to append device name:%s", dev_metadata.device_name);
        ret = -1;
        goto out;
    }

    if (append_json_map_string_string(map_info, "MergedDir", rootfs_dir) != 0) {
        ERROR("Failed to append device merge dir:%s", rootfs_dir);
        ret = -1;
        goto out;
    }

out:
    free(dev_metadata.device_name);
    free(mnt_dir);
    free(id_dir);
    free(rootfs_dir);
    free(device_id_str);
    free(device_size_str);
    return ret;
}

static void status_append(const char *name, const char *value, uint64_t u_data, int integer_data, char **status,
                          data_type type)
{
#define MAX_INFO_LENGTH 100
    char tmp[PATH_MAX] = { 0 };
    char *str = NULL;
    int nret = 0;

    if (name == NULL) {
        ERROR("invalid argument");
        return;
    }

    switch (type) {
        case STRING:
            nret = snprintf(tmp, MAX_INFO_LENGTH, "%s: %s\n", name, value);
            break;
        case UINT64_T:
            // If u_data does not reach int64_t limit, executing of type conversion is safe
            if (u_data < LONG_MAX) {
                char *human_size = NULL;
                human_size = util_human_size_decimal((int64_t)u_data);
                if (human_size == NULL) {
                    WARN("devmapper: convert human size failed");
                }
                nret = snprintf(tmp, MAX_INFO_LENGTH, "%s: %s\n", name, human_size);
                free(human_size);
            } else {
                // If unsigned long int is bigger than LONG_MAX, just print directly with Byte unit
                nret = snprintf(tmp, MAX_INFO_LENGTH, "%s: %luB\n", name, u_data);
            }
            break;
        case INT:
            nret = snprintf(tmp, MAX_INFO_LENGTH, "%s: %d\n", name, integer_data);
            break;
        case UINT64_NONE:
            // Print without unit
            nret = snprintf(tmp, MAX_INFO_LENGTH, "%s: %lu\n", name, u_data);
        default:
            break;
    }

    if (nret < 0 || nret >= MAX_INFO_LENGTH) {
        ERROR("Failed to print status");
        return;
    }

    str = *status;
    *status = NULL;
    *status = util_string_append(tmp, str);
    free(str);
}

char *status_to_str(const struct status *st)
{
    char *str = NULL;

    status_append("Pool Name", st->pool_name, 0, 0, &str, STRING);
    status_append("Pool Blocksize", NULL, st->sector_size, 0, &str, UINT64_T);
    status_append("Base Device Size", NULL, st->base_device_size, 0, &str, UINT64_T);
    status_append("Backing Filesystem", st->base_device_fs, 0, 0, &str, STRING);
    status_append("Data file", st->data_file, 0, 0, &str, STRING);
    status_append("Metadata file", st->metadata_file, 0, 0, &str, STRING);
    status_append("Data Space Used", NULL, st->data.used, 0, &str, UINT64_T);
    status_append("Data Space Total", NULL, st->data.total, 0, &str, UINT64_T);
    status_append("Data Space Available", NULL, st->data.available, 0, &str, UINT64_T);
    status_append("Metadata Space Used", NULL, st->metadata.used, 0, &str, UINT64_T);
    status_append("Metadata Space Total", NULL, st->metadata.total, 0, &str, UINT64_T);
    status_append("Metadata Space Available", NULL, st->metadata.available, 0, &str, UINT64_T);
    status_append("Thin Pool Minimum Free Space", NULL, st->min_free_space, 0, &str, UINT64_T);

    if (st->udev_sync_supported) {
        status_append("Udev Sync Supported", "true", 0, 0, &str, STRING);
    } else {
        status_append("Udev Sync Supported", "false", 0, 0, &str, STRING);
    }

    if (st->deferred_remove_enabled) {
        status_append("Deferred Removal Enabled", "true", 0, 0, &str, STRING);
    } else {
        status_append("Deferred Removal Enabled", "false", 0, 0, &str, STRING);
    }

    if (st->deferred_delete_enabled) {
        status_append("Deferred Deletion Enabled", "true", 0, 0, &str, STRING);
    } else {
        status_append("Deferred Deletion Enabled", "false", 0, 0, &str, STRING);
    }

    status_append("Deferred Deleted Device Count", NULL, st->deferred_deleted_device_count, 0, &str, UINT64_NONE);
    status_append("Library Version", st->library_version, 0, 0, &str, STRING);
    status_append("Semaphore Set Used", NULL, 0, st->semusz, &str, INT);
    status_append("Semaphore Set Total", NULL, 0, st->semmni, &str, INT);
    if (st->sem_msg != NULL) {
        status_append("WARNING", st->sem_msg, 0, 0, &str, STRING);
    }

    return str;
}

int devmapper_get_driver_status(const struct graphdriver *driver, struct graphdriver_status *status)
{
    int ret = 0;
    struct status *st = NULL;
    char *status_str = NULL;

    if (driver == NULL || status == NULL) {
        return -1;
    }

    st = device_set_status(driver->devset);
    if (st == NULL) {
        ERROR("Failed to get device set status");
        ret = -1;
        goto out;
    }

    status->driver_name = util_strdup_s(driver->name);
    status->backing_fs = util_strdup_s(driver->backing_fs);
    status_str = status_to_str(st);
    status->status = util_strdup_s(status_str);
    if (status->status == NULL) {
        ERROR("Get devicemapper driver status string failed");
        ret = -1;
        goto out;
    }

out:
    free_devmapper_status(st);
    free(status_str);
    return ret;
}

int devmapper_clean_up(struct graphdriver *driver)
{
    int ret = 0;

    if (driver == NULL) {
        ERROR("Invalid input param to cleanup devicemapper");
        return -1;
    }

    if (device_set_shutdown(driver->devset, driver->home) != 0) {
        ERROR("devmapper: shutdown device set failed root is %s", driver->home);
        ret = -1;
        goto out;
    }

    if (free_deviceset_with_lock(driver->devset) != 0) {
        ERROR("Free device set data failed");
        ret = -1;
        goto out;
    }
    driver->devset = NULL;

out:
    return ret;
}

int devmapper_repair_lowers(const char *id, const char *parent, const struct graphdriver *driver)
{
    return 0;
}

int devmapper_get_layer_fs_info(const char *id, const struct graphdriver *driver, imagetool_fs_info *fs_info)
{
    return 0;
}
