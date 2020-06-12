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
#include <libdevmapper.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/sysmacros.h>
#include <sys/mount.h>

#include "isula_libutils/log.h"
#include "libisulad.h"
#include "utils.h"
#include "wrapper_devmapper.h"
#include "devices_constants.h"
#include "device_setup.h"
#include "deviceset.h"
#include "isula_libutils/json_common.h"
#include "util_archive.h"

int devmapper_init(struct graphdriver *driver, const char *drvier_home, const char **options, size_t len)
{
    return device_init(driver, drvier_home, options, len);
}

static int do_create(const char *id, const char *parent, const struct graphdriver *driver,
                     const struct driver_create_opts *create_opts)
{
    return add_device(id, parent, driver, create_opts->storage_opt);
}

// devmapper_create_rw creates a layer that is writable for use as a container file system
int devmapper_create_rw(const char *id, const char *parent, const struct graphdriver *driver,
                        struct driver_create_opts *create_opts)
{
    if (id == NULL || driver == NULL || create_opts == NULL) {
        return -1;
    }

    return do_create(id, parent, driver, create_opts);
}

// Create adds a device with a given id and the parent.
int devmapper_create_ro(const char *id, const char *parent, const struct graphdriver *driver,
                        const struct driver_create_opts *create_opts)
{
    if (id == NULL || driver == NULL || create_opts == NULL) {
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

    if (id == NULL || driver == NULL) {
        return -1;
    }

    if (!has_device(id, driver)) {
        return 0;
    }

    ret = delete_device(id, false, driver);
    if (ret != 0) {
        ERROR("failed to remove device %s", id);
        return ret;
    }

    mnt_parent_dir = util_path_join(driver->home, "mnt");
    if (mnt_parent_dir == NULL) {
        ret = -1;
        ERROR("Failed to join devmapper mnt dir %s", id);
        goto out;
    }

    mnt_point_dir = util_path_join(mnt_parent_dir, id);
    if (mnt_point_dir == NULL) {
        ret = -1;
        ERROR("Failed to join devampper mount point dir %s", id);
        goto out;
    }

    ret = util_path_remove(mnt_point_dir);

out:
    free(mnt_parent_dir);
    free(mnt_point_dir);
    return ret;
}

static int write_file(const char *fpath, const char *buf)
{
    int fd = 0;
    ssize_t nwrite;

    if (fpath == NULL || buf == NULL) {
        return 0;
    }

    fd = util_open(fpath, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        ERROR("Failed to open file: %s: %s", fpath, strerror(errno));
        return -1;
    }
    nwrite = util_write_nointr(fd, buf, strlen(buf));
    if (nwrite < 0) {
        ERROR("Failed to write %s to %s: %s", buf, fpath, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);

    return 0;
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

    if (id == NULL || driver == NULL || mount_opts == NULL) {
        return NULL;
    }

    mnt_parent_dir = util_path_join(driver->home, "mnt");
    if (mnt_parent_dir == NULL) {
        ERROR("Failed to join devmapper mnt dir%s", id);
        goto out;
    }

    mnt_point_dir = util_path_join(mnt_parent_dir, id);
    if (mnt_point_dir == NULL) {
        ERROR("Failed to join devampper mount point dir:%s", id);
        goto out;
    }

    DEBUG("devmapper: start to mount container device");
    ret = mount_device(id, mnt_point_dir, mount_opts, driver);
    if (ret != 0) {
        goto out;
    }

    rootfs = util_path_join(mnt_point_dir, "rootfs");
    if (rootfs == NULL) {
        ERROR("Failed to join devmapper rootfs %s", mnt_point_dir);
        goto out;
    }

    if (util_mkdir_p(rootfs, 0755) != 0 || !util_dir_exists(rootfs)) {
        ERROR("Unable to create devmapper rootfs directory %s.", rootfs);
        ret = -1;
        if (unmount_device(id, mnt_point_dir, driver) != 0) {
            DEBUG("devmapper: unmount %s failed", mnt_point_dir);
        }
        goto out;
    }

    id_file = util_path_join(mnt_point_dir, "id");
    if (!util_file_exists(id_file)) {
        // Create an "id" file with the container/image id in it to help reconstruct this in case
        // of later problems
        ret = write_file(id_file, id);
        if (ret != 0) {
            if (unmount_device(id, mnt_point_dir, driver) != 0) {
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

    if (id == NULL || driver == NULL) {
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

    ret = unmount_device(id, mp, driver);
    if (ret != 0) {
        DEBUG("devmapper: unmount %s failed", mp);
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

bool devmapper_layer_exists(const char *id, const struct graphdriver *driver)
{
    return has_device(id, driver);
}

int devmapper_apply_diff(const char *id, const struct graphdriver *driver, const struct io_read_wrapper *content,
                         int64_t *layer_size)
{
    struct driver_mount_opts *mount_opts = NULL;
    char *layer_fs = NULL;
    int ret = 0;
    struct archive_options options = { 0 };

    if (id == NULL || driver == NULL || content == NULL) {
        ERROR("invalid argument");
        return -1;
    }

    mount_opts = util_common_calloc_s(sizeof(struct driver_mount_opts));
    if (mount_opts == NULL) {
        ERROR("devmapper: out of memory");
        return -1;
    }

    layer_fs = devmapper_mount_layer(id, driver, mount_opts);
    if (layer_fs == NULL) {
        ERROR("devmapper: failed to mount layer %s", id);
        ret = -1;
        goto out;
    }

    options.whiteout_format = OVERLAY_WHITEOUT_FORMATE;

    ret = archive_unpack(content, layer_fs, &options);
    if (ret != 0) {
        ERROR("devmapper: failed to unpack to :%s", layer_fs);
    }

    if (devmapper_umount_layer(id, driver)) {
        ERROR("devmapper: failed to umount layer %s", id);
        ret = -1;
    }

out:
    free_driver_mount_opts(mount_opts);
    free(layer_fs);
    return ret;
}

int devmapper_get_layer_metadata(const char *id, const struct graphdriver *driver, json_map_string_string *map_info)
{
    int ret = 0;
    char *mnt_dir = NULL;
    char *id_dir = NULL;
    char *rootfs_dir = NULL;
    struct device_metadata dev_metadata;
    char *device_id_str = NULL;
    char *device_size_str = NULL;

    if (id == NULL || driver == NULL || map_info == NULL) {
        ERROR("invalid argument");
        ret = -1;
        goto out;
    }

    ret = export_device_metadata(&dev_metadata, id, driver);
    if (ret != 0) {
        ERROR("Failed to export device metadata of device %s", id);
        goto out;
    }

    device_id_str = util_int_to_string(dev_metadata.device_id);
    if (device_id_str == NULL) {
        ret = -1;
        ERROR("Failed to map long long int to string");
        goto out;
    }

    device_size_str = util_uint_to_string(dev_metadata.device_size);
    if (device_size_str == NULL) {
        ret = -1;
        ERROR("Failed to map long long unsigned int to string");
        goto out;
    }

    mnt_dir = util_path_join(driver->home, "mnt");
    if (mnt_dir == NULL) {
        ret = -1;
        ERROR("Failed to join mnt dir");
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
        ret = -1;
        ERROR("Failed to join devmapper rootfs dir");
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
    free(mnt_dir);
    free(id_dir);
    free(rootfs_dir);
    free(device_id_str);
    free(device_size_str);
    return ret;
}

static void status_append(const char *name, const char *value, uint64_t data, char **status, data_type type)
{
#define MAX_INFO_LENGTH 100
    char tmp[PATH_MAX] = { 0 };
    char *str = NULL;
    size_t nret = 0;

    if (name == NULL) {
        return;
    }

    switch (type) {
        case STRING:
            nret = snprintf(tmp, MAX_INFO_LENGTH, "%s: %s\n", name, value);
            break;
        case UINT64_T:
            nret = snprintf(tmp, MAX_INFO_LENGTH, "%s: %lu\n", name, data);
            break;
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

    status_append("Pool Name", st->pool_name, 0, &str, STRING);
    status_append("Pool Blocksize", NULL, st->sector_size, &str, UINT64_T);
    status_append("Base Device Size", NULL, st->base_device_size, &str, UINT64_T);
    status_append("Backing Filesystem", st->base_device_fs, 0, &str, STRING);
    status_append("Data file", st->data_file, 0, &str, STRING);
    status_append("Metadata file", st->metadata_file, 0, &str, STRING);
    status_append("Data Space Used", NULL, st->data.used, &str, UINT64_T);
    status_append("Data Space Total", NULL, st->data.total, &str, UINT64_T);
    status_append("Data Space Available", NULL, st->data.available, &str, UINT64_T);
    status_append("Metadata Space Used", NULL, st->metadata.used, &str, UINT64_T);
    status_append("Metadata Space Total", NULL, st->metadata.total, &str, UINT64_T);
    status_append("Metadata Space Available", NULL, st->metadata.available, &str, UINT64_T);
    status_append("Thin Pool Minimum Free Space", NULL, st->min_free_space, &str, UINT64_T);

    if (st->udev_sync_supported) {
        status_append("Udev Sync Supported", "true", 0, &str, STRING);
    } else {
        status_append("Udev Sync Supported", "false", 0, &str, STRING);
    }

    if (st->deferred_remove_enabled) {
        status_append("Deferred Removal Enabled", "true", 0, &str, STRING);
    } else {
        status_append("Deferred Removal Enabled", "false", 0, &str, STRING);
    }

    if (st->deferred_delete_enabled) {
        status_append("Deferred Deletion Enabled", "true", 0, &str, STRING);
    } else {
        status_append("Deferred Deletion Enabled", "false", 0, &str, STRING);
    }

    status_append("Deferred Deleted Device Count", NULL, st->deferred_deleted_device_count, &str, UINT64_T);

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

    st = device_set_status(driver);
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
        ret = -1;
        goto out;
    }

out:
    free_devmapper_status(st);
    free(status_str);
    return ret;
}

int devmapper_clean_up(const struct graphdriver *driver)
{
    if (driver == NULL) {
        return -1;
    }
    return umount(driver->home);
}
