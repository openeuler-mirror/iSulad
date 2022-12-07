/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangrunze
 * Create: 2022-10-31
 * Description: provide rootfs cleaner functions
 *********************************************************************************/
#include <sys/stat.h>
#include <string.h>
#include "oci_rootfs_clean.h"
#include "container_api.h"
#include "image_api.h"
#include "utils_file.h"
#include "utils.h"
#include "linked_list.h"

struct cb_result {
    int clean_err_cnt;
};

static bool walk_dir_cb(const char *path_name, const struct dirent *sub_dir, void *context)
{
    struct cb_result *result = (struct cb_result *)context;
    container_t *cont = containers_store_get(sub_dir->d_name);
    int rm_rootfs_ret = 0;

    if (cont != NULL) {
        container_unref(cont);
        return true;
    }

    INFO("cleaning leftover dir: %s", sub_dir->d_name);
    rm_rootfs_ret = im_remove_container_rootfs(IMAGE_TYPE_OCI, sub_dir->d_name);
    if (rm_rootfs_ret != 0) {
        result->clean_err_cnt++;
    }

    return true;
}


int oci_rootfs_cleaner(struct clean_ctx *ctx)
{
    struct cb_result res = { 0 };
    im_get_rf_dir_request request = { 0 };
    char *rf_dir = NULL;
    int ret = 0;

    request.type = IMAGE_TYPE_OCI;
    rf_dir = im_get_rootfs_dir(&request);
    if (rf_dir == NULL) {
        return 0;
    }

    ret = util_scan_subdirs(rf_dir, walk_dir_cb, &res);
    free(rf_dir);
    if (ret != 0) {
        ERROR("failed to scan subdirs");
        return -1;
    }

    if (res.clean_err_cnt == 0) {
        return 0;
    }

    return -1;
}

int oci_broken_rootfs_cleaner(struct clean_ctx *ctx)
{
    int rm_fail_cnt = 0;
    struct linked_list *it = NULL;
    struct linked_list *next = NULL;
    char *id = NULL;

    if (ctx == NULL) {
        return -1;
    }

    linked_list_for_each_safe(it, &(ctx->broken_rootfs_list), next) {
        id = (char *)it->elem;
        if (im_remove_broken_rootfs(IMAGE_TYPE_OCI, id) != 0) {
            ERROR("Failed to clean broken rootfs %s", id);
            rm_fail_cnt++;
        } else {
            EVENT("clean broken rootfs succeed %s", id);
        }
    }

    if (rm_fail_cnt != 0) {
        DEBUG("can't clean some broken rootfs, %d left", rm_fail_cnt);
        return -1;
    }

    return 0;
}