/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide image functions
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <sys/utsname.h>
#include <ctype.h>

#include "log.h"
#include "utils.h"
#include "specs_extend.h"
#include "securec.h"
#include "ext_image.h"

#ifdef ENABLE_OCI_IMAGE
#include "oci_image.h"
#include "oci_images_store.h"
#include "oci_config_merge.h"
#endif

bool ext_detect(const char *image_name)
{
    if (image_name == NULL) {
        return false;
    }

    if (image_name[0] != '/') {
        INFO("Rootfs should be absolutely path");
        return false;
    }

    return util_file_exists(image_name);
}
int ext_filesystem_usage(struct bim *bim, imagetool_fs_info **fs_usage)
{
    return 0;
}

int ext_prepare_rf(struct bim *bim, const json_map_string_string *storage_opt, char **real_rootfs)
{
    int ret = 0;

    if (real_rootfs != NULL) {
        if (bim->image_name != NULL) {
            char real_path[PATH_MAX] = { 0 };
            if (bim->image_name[0] != '/') {
                ERROR("Rootfs should be absolutely path");
                lcrd_set_error_message("Rootfs should be absolutely path");
                return -1;
            }
            if (realpath(bim->image_name, real_path) == NULL) {
                ERROR("Failed to clean rootfs path '%s': %s", bim->image_name, strerror(errno));
                lcrd_set_error_message("Failed to clean rootfs path '%s': %s", bim->image_name, strerror(errno));
                return -1;
            }
            *real_rootfs = util_strdup_s(real_path);
        } else {
            ERROR("Failed to get external rootfs");
            ret = -1;
        }
    }
    return ret;
}

int ext_mount_rf(struct bim *bim)
{
    return 0;
}

int ext_umount_rf(struct bim *bim)
{
    return 0;
}

int ext_delete_rf(struct bim *bim)
{
    return 0;
}

char *ext_resolve_image_name(const char *image_name)
{
    return util_strdup_s(image_name);
}

#ifdef ENABLE_OCI_IMAGE
int ext_merge_conf(oci_runtime_spec *oci_spec, const host_config *host_spec, container_custom_config *custom_spec,
                   struct bim *bim, char **real_rootfs)
{
    int ret = 0;
    char *resolved_name = NULL;
    oci_image_t *image_info = NULL;

    // Ensure rootfs is valid.
    ret = ext_prepare_rf(bim, host_spec->storage_opt, real_rootfs);
    if (ret != 0) {
        return ret;
    }

    ret = ext_umount_rf(bim);
    if (ret != 0) {
        return ret;
    }

    // No config neeed merge if NULL.
    if (bim->ext_config_image == NULL) {
        ret = 0;
        goto out;
    }

    // Get image's config and merge configs.
    resolved_name = oci_resolve_image_name(bim->ext_config_image);
    if (resolved_name == NULL) {
        ERROR("Resolve external config image name failed, image name is %s", bim->ext_config_image);
        ret = -1;
        goto out;
    }

    image_info = oci_images_store_get(resolved_name);
    if (image_info == NULL) {
        ERROR("Get image from image store failed, image name is %s", resolved_name);
        ret = -1;
        goto out;
    }

    ret = oci_image_merge_config(image_info->info, oci_spec, custom_spec);

out:
    free(resolved_name);
    resolved_name = NULL;

    oci_image_unref(image_info);
    image_info = NULL;

    return ret;
}
#else
int ext_merge_conf(oci_runtime_spec *oci_spec, const host_config *host_spec, container_custom_config *custom_spec,
                   struct bim *bim, char **real_rootfs)
{
    int ret = 0;

    // Ensure rootfs is valid.
    ret = ext_prepare_rf(bim, host_spec->storage_opt, real_rootfs);
    if (ret != 0) {
        return ret;
    }

    ret = ext_umount_rf(bim);
    if (ret != 0) {
        return ret;
    }

    return ret;
}
#endif

int ext_get_user_conf(const char *basefs, host_config *hc, const char *userstr, oci_runtime_spec_process_user *puser)
{
    if (basefs == NULL || puser == NULL) {
        ERROR("Empty basefs or puser");
        return -1;
    }
    return get_user(basefs, hc, userstr, puser);
}

int ext_list_images(im_list_request *request, imagetool_images_list **list)
{
    int ret = 0;

    *list = util_common_calloc_s(sizeof(imagetool_images_list));
    if (*list == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

int ext_remove_image(im_remove_request *request)
{
    return 0;
}

int ext_inspect_image(struct bim *bim, char **inspected_json)
{
    return 0;
}

int ext_load_image(im_load_request *request)
{
    return 0;
}

int ext_login(im_login_request *request)
{
    return 0;
}

int ext_logout(im_logout_request *request)
{
    return 0;
}

int ext_init(const char *rootpath)
{
    return 0;
}
