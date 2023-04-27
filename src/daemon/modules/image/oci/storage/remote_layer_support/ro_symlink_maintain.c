/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangrunze
 * Create: 2023-01-12
 * Description: provide remote symlink maintain functions
 ******************************************************************************/
#define _GNU_SOURCE
#include "ro_symlink_maintain.h"

#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include "path.h"
#include "linked_list.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_file.h"

#define REMOTE_RO_LAYER_DIR "RO"

// overlay-layers and overlay-layers/RO
static char *image_home;

static char *layer_ro_dir;
static char *layer_home;

// overlay and overlay/RO
static char *overlay_ro_dir;
static char *overlay_home;

int remote_image_init(const char *root_dir)
{
    if (root_dir == NULL) {
        goto out;
    }

    image_home = util_strdup_s(root_dir);
    if (image_home == NULL) {
        ERROR("Failed create path for remote image home");
        goto out;
    }
    return 0;

out:
    remote_maintain_cleanup();
    return -1;
}

int remote_layer_init(const char *root_dir)
{
    if (root_dir == NULL) {
        goto out;
    }

    layer_home = util_strdup_s(root_dir);
    layer_ro_dir = util_path_join(root_dir, REMOTE_RO_LAYER_DIR);
    if (layer_ro_dir == NULL) {
        ERROR("Failed join path when init remote layer maintainer");
        goto out;
    }
    if (!util_file_exists(layer_ro_dir) && util_mkdir_p(layer_ro_dir, 0700) != 0) {
        ERROR("Failed to create RO dir under overlay");
        goto out;
    }

    return 0;

out:
    remote_maintain_cleanup();
    return -1;
}

int remote_overlay_init(const char *driver_home)
{
    if (driver_home == NULL) {
        goto out;
    }

    overlay_home = util_strdup_s(driver_home);
    overlay_ro_dir = util_path_join(driver_home, REMOTE_RO_LAYER_DIR);
    if (overlay_ro_dir == NULL) {
        ERROR("Failed to join path when init remote maintainer");
        goto out;
    }
    // build RO dir if not exist
    if (!util_file_exists(overlay_ro_dir) && util_mkdir_p(overlay_ro_dir, 0700) != 0) {
        ERROR("Failed to create RO dir under overlay");
        goto out;
    }

    return 0;

out:
    remote_maintain_cleanup();
    return -1;
}

void remote_maintain_cleanup(void)
{
    free(image_home);
    image_home = NULL;

    free(layer_home);
    layer_home = NULL;
    free(layer_ro_dir);
    layer_ro_dir = NULL;
    free(overlay_home);

    overlay_home = NULL;
    free(overlay_ro_dir);
    overlay_ro_dir = NULL;
}

static int do_build_ro_dir(const char *home, const char *id)
{
    char *ro_symlink = NULL;
    char *ro_layer_dir = NULL;
    int nret = 0;
    int ret = 0;

    nret = asprintf(&ro_symlink, "%s/%s", home, id);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Failed create ro layer dir sym link path");
        return -1;
    }

    nret = asprintf(&ro_layer_dir, "%s/%s/%s", home, REMOTE_RO_LAYER_DIR, id);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Failed to create ro layer dir path");
        return -1;
    }

    if (util_mkdir_p(ro_layer_dir, IMAGE_STORE_PATH_MODE) != 0) {
        ret = -1;
        ERROR("Failed to create layer direcotry %s", ro_layer_dir);
        goto out;
    }

    if (symlink(ro_layer_dir, ro_symlink) != 0) {
        ret = -1;
        SYSERROR("Failed to create symlink to layer dir %s", ro_layer_dir);
        goto err_out;
    }

    goto out;

err_out:
    if (util_recursive_rmdir(ro_layer_dir, 0)) {
        ERROR("Failed to delete layer path: %s", ro_layer_dir);
    }

out:
    free(ro_layer_dir);
    free(ro_symlink);
    return ret;
}

int remote_overlay_build_ro_dir(const char *id)
{
    return do_build_ro_dir(overlay_home, id);
}

int remote_layer_build_ro_dir(const char *id)
{
    return do_build_ro_dir(layer_home, id);
}

int do_remove_ro_dir(const char *home, const char *id)
{
    char *ro_layer_dir = NULL;
    char *ro_symlink = NULL;
    char clean_path[PATH_MAX] = { 0 };
    int ret = 0;
    int nret = 0;

    if (id == NULL) {
        return 0;
    }

    nret = asprintf(&ro_symlink, "%s/%s", home, id);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create layer sym link path failed");
        return -1;
    }

    if (util_clean_path(ro_symlink, clean_path, sizeof(clean_path)) == NULL) {
        ERROR("Failed to clean path: %s", ro_symlink);
        ret = -1;
        goto out;
    }

    if (util_path_remove(clean_path) != 0) {
        SYSERROR("Failed to remove link path %s", clean_path);
    }

    nret = asprintf(&ro_layer_dir, "%s/%s/%s", home, REMOTE_RO_LAYER_DIR, id);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create layer json path failed");
        ret = -1;
        goto out;
    }

    ret = util_recursive_rmdir(ro_layer_dir, 0);

out:
    free(ro_layer_dir);
    free(ro_symlink);
    return ret;
}

int remote_layer_remove_ro_dir(const char *id)
{
    return do_remove_ro_dir(layer_home, id);
}

int remote_overlay_remove_ro_dir(const char *id)
{
    return do_remove_ro_dir(overlay_home, id);
}

maintain_context get_maintain_context(void)
{
    maintain_context ctx = {0x0};

    ctx.image_home = image_home;
    ctx.layer_ro_dir = layer_ro_dir;
    ctx.layer_home = layer_home;
    ctx.overlay_ro_dir = overlay_ro_dir;
    ctx.overlay_home = overlay_home;

    return ctx;
}
