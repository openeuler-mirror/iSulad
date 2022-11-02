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


int oci_rootfs_cleaner(void)
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
