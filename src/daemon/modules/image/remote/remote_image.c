/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: liuxu
 * Create: 2025-02-11
 * Explanation: provide remote image function
 ******************************************************************************/
#include "remote_image.h"

#include <isula_libutils/log.h>

#include "utils.h"


char *remote_resolve_image_name(const char *name)
{
    return util_strdup_s(IMAGE_NAME_COCO);
}

int remote_prepare_rf(const im_prepare_request *request, char **real_rootfs)
{
    if (real_rootfs == NULL) {
        ERROR("Failed to prepare remote rootfs, rootfs is NULL.");
        return -1;
    }
    // real_rootfs will be changed by runtime when sandbox image type is "remote"
    *real_rootfs = util_strdup_s("rootfs");
    return 0;
}

int remote_rmi(const im_rmi_request *request)
{
    return 0;
}

int remote_get_filesystem_info(im_fs_info_response **response)
{
    return 0;
}

int remote_container_filesystem_usage(const im_container_fs_usage_request *request, imagetool_fs_info **fs_usage)
{
    return 0;
}

int remote_delete_broken_rf(const im_delete_rootfs_request *request)
{
    return 0;
}

int remote_delete_rf(const im_delete_rootfs_request *request)
{
    return 0;
}

int remote_umount_rf(const im_umount_request *request)
{
    return 0;
}

int remote_mount_rf(const im_mount_request *request)
{
    return 0;
}

int remote_merge_conf_rf(const char *img_name, container_config *container_spec)
{
    return 0;
}

int remote_get_user_conf(const char *basefs, host_config *hc, const char *userstr, defs_process_user *puser)
{
    return 0;
}
