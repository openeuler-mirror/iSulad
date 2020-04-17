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

#include "log.h"
#include "libisulad.h"
#include "utils.h"
#include "wrapper_devmapper.h"
#include "devices_constants.h"
#include "device_setup.h"
#include "deviceset.h"
#include "json_common.h"

int devmapper_init(struct graphdriver *driver, const char *drvier_home, const char **options, size_t len)
{
    return device_init(driver, drvier_home, options, len);
}

static int do_create(const char *id, const char *parent, const struct driver_create_opts *create_opts)
{
    return add_device(id, parent, create_opts->storage_opt);
}

// devmapper_create_rw creates a layer that is writable for use as a container file system
int devmapper_create_rw(const char *id, const char *parent, const struct graphdriver *driver,
                        const struct driver_create_opts *create_opts)
{
    if (id == NULL || parent == NULL || driver == NULL || create_opts == NULL) {
        return -1;
    }

    return do_create(id, parent, create_opts);
}

// Create adds a device with a given id and the parent.
int devmapper_create_ro(const char *id, const char *parent, const struct graphdriver *driver,
                        const struct driver_create_opts *create_opts)
{
    if (id == NULL || parent == NULL || driver == NULL || create_opts == NULL) {
        return -1;
    }

    return do_create(id, parent, create_opts);
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

    if (!has_device(id)) {
        return 0;
    }

    ret = delete_device(id, false);
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
    ret = mount_device(id, mnt_point_dir, mount_opts);
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
        if (unmount_device(id, mnt_point_dir) != 0) {
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
            if (unmount_device(id, mnt_point_dir) != 0) {
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

    ret = unmount_device(id, mp);
    if (ret != 0) {
        DEBUG("devmapper: unmount %s failed", mp);
    }

out:
    free(mnt_dir);
    free(mp);
    return ret;
}

bool devmapper_layer_exists(const char *id, const struct graphdriver *driver)
{
    return has_device(id);
}

int devmapper_apply_diff(const char *id, const struct graphdriver *driver, const struct io_read_wrapper *content,
                         int64_t *layer_size)
{
    return 0;
}

int devmapper_get_layer_metadata(const char *id, const struct graphdriver *driver, json_map_string_string *map_info)
{
    return 0;
}

int devmapper_get_driver_status(const struct graphdriver *driver, struct graphdriver_status *status)
{
    return 0;
}
