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
* Create: 2020-06-01
* Description: isula image export operator implement
*******************************************************************************/
#include "oci_export.h"
#include <stdbool.h>
#include <stdlib.h>
#include <linux/limits.h>

#include "storage.h"
#include "isula_libutils/log.h"
#include "err_msg.h"
#include "util_archive.h"
#include "path.h"
#include "utils_file.h"

int oci_do_export(char *id, char *file)
{
    int ret = 0;
    int ret2 = 0;
    char *mount_point = NULL;
    char *errmsg = NULL;
    char cleanpath[PATH_MAX] = { 0 };

    if (id == NULL || file == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    if (util_clean_path(file, cleanpath, sizeof(cleanpath)) == NULL) {
        ERROR("clean path for %s failed", file);
        ret = -1;
        goto out;
    }

    if (util_fileself_exists(cleanpath)) {
        ERROR("dst file %s exist", cleanpath);
        ret = -1;
        goto out;
    }

    mount_point = storage_rootfs_mount(id);
    if (mount_point == NULL) {
        ERROR("mount container %s failed", id);
        isulad_set_error_message("Failed to export rootfs with error: failed to mount rootfs");
        return -1;
    }

    ret = archive_chroot_tar(mount_point, cleanpath, &errmsg);
    if (ret != 0) {
        ERROR("failed to export container %s to file %s: %s", id, cleanpath, errmsg);
        isulad_set_error_message("Failed to export rootfs with error: %s", errmsg);
        goto out;
    }

out:
    free(mount_point);
    mount_point = NULL;
    free(errmsg);
    errmsg = NULL;

    ret2 = storage_rootfs_umount(id, false);
    if (ret2 != 0) {
        ret = ret2;
        ERROR("umount container %s failed", id);
        isulad_try_set_error_message("Failed to export rootfs with error: failed to umount rootfs");
    }

    return ret;
}
