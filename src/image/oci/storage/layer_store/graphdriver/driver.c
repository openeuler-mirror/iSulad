/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide image functions
 ******************************************************************************/

#include "driver.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <linux/limits.h>

#include "driver_overlay2.h"
#include "driver_devmapper.h"
#include "utils_array.h"
#include "utils.h"
#include "libisulad.h"
#include "isula_libutils/log.h"
#include "util_archive.h"

static struct graphdriver *g_graphdriver = NULL;

/* overlay2 */
#define DRIVER_OVERLAY2_NAME "overlay2"
#define DRIVER_OVERLAY_NAME "overlay"

static const struct graphdriver_ops g_overlay2_ops = {
    .init = overlay2_init,
    .create_rw = overlay2_create_rw,
    .create_ro = overlay2_create_ro,
    .rm_layer = overlay2_rm_layer,
    .mount_layer = overlay2_mount_layer,
    .umount_layer = overlay2_umount_layer,
    .exists = overlay2_layer_exists,
    .apply_diff = overlay2_apply_diff,
    .get_layer_metadata = overlay2_get_layer_metadata,
    .get_driver_status = overlay2_get_driver_status,
    .clean_up = overlay2_clean_up,
    .try_repair_lowers = overlay2_repair_lowers,
};

/* devicemapper */
#define DRIVER_DEVMAPPER_NAME "devicemapper"

static const struct graphdriver_ops g_devmapper_ops = {
    .init = devmapper_init,
};

static struct graphdriver g_drivers[] = {
    {.name = DRIVER_OVERLAY2_NAME,  .ops = &g_overlay2_ops},
    {.name = DRIVER_OVERLAY_NAME,   .ops = &g_overlay2_ops},
    {.name = DRIVER_DEVMAPPER_NAME, .ops = &g_devmapper_ops}
};

static const size_t g_numdrivers = sizeof(g_drivers) / sizeof(struct graphdriver);

int graphdriver_init(const struct storage_module_init_options *opts)
{
    int ret = 0;
    size_t i = 0;
    char driver_home[PATH_MAX] = { 0 };

    if (opts == NULL || opts->storage_root == NULL || opts->driver_name == NULL) {
        ret = -1;
        goto out;
    }

    int nret = snprintf(driver_home, PATH_MAX, "%s/%s", opts->storage_root, opts->driver_name);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        ERROR("Sprintf graph driver path failed");
        ret = -1;
        goto out;
    }

    for (i = 0; i < g_numdrivers; i++) {
        if (strcmp(opts->driver_name, g_drivers[i].name) == 0) {
            if (g_drivers[i].ops->init(&g_drivers[i], driver_home, (const char **)opts->driver_opts, opts->driver_opts_len) != 0) {
                ret = -1;
                goto out;
            }
            g_graphdriver = &g_drivers[i];
            break;
        }
    }

    if (i == g_numdrivers) {
        ERROR("unsupported driver %s", opts->driver_name);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

int graphdriver_create_rw(const char *id, const char *parent, struct driver_create_opts *create_opts)
{
    if (g_graphdriver == NULL) {
        ERROR("Driver not inited yet");
        return -1;
    }

    if (id == NULL || parent == NULL || create_opts == NULL) {
        ERROR("Invalid input arguments for driver create");
        return -1;
    }

    return g_graphdriver->ops->create_rw(id, parent, g_graphdriver, create_opts);;
}

int graphdriver_create_ro(const char *id, const char *parent, const struct driver_create_opts *create_opts)
{
    if (g_graphdriver == NULL) {
        ERROR("Driver not inited yet");
        return -1;
    }

    if (id == NULL || parent == NULL || create_opts == NULL) {
        ERROR("Invalid input arguments for driver create");
        return -1;
    }

    return g_graphdriver->ops->create_ro(id, parent, g_graphdriver, create_opts);;
}

int graphdriver_rm_layer(const char *id)
{
    if (g_graphdriver == NULL) {
        ERROR("Driver not inited yet");
        return -1;
    }

    if (id == NULL) {
        ERROR("Invalid input arguments for driver remove layer");
        return -1;
    }

    return g_graphdriver->ops->rm_layer(id, g_graphdriver);
}

char *graphdriver_mount_layer(const char *id, const struct driver_mount_opts *mount_opts)
{
    if (g_graphdriver == NULL) {
        ERROR("Driver not inited yet");
        return NULL;
    }

    if (id == NULL || mount_opts == NULL) {
        ERROR("Invalid input arguments for driver mount layer");
        return NULL;
    }

    return g_graphdriver->ops->mount_layer(id, g_graphdriver, mount_opts);
}

int graphdriver_umount_layer(const char *id)
{
    if (g_graphdriver == NULL) {
        ERROR("Driver not inited yet");
        return -1;
    }

    if (id == NULL) {
        ERROR("Invalid input arguments for driver umount layer");
        return -1;
    }

    return g_graphdriver->ops->umount_layer(id, g_graphdriver);
}

bool graphdriver_layer_exists(const char *id)
{
    if (g_graphdriver == NULL) {
        ERROR("Driver not inited yet");
        return -1;
    }

    if (id == NULL) {
        ERROR("Invalid input arguments for driver exists layer");
        return -1;
    }

    return g_graphdriver->ops->exists(id, g_graphdriver);
}

int graphdriver_apply_diff(const char *id, const struct io_read_wrapper *content, int64_t *layer_size)
{
    if (g_graphdriver == NULL) {
        ERROR("Driver not inited yet");
        return -1;
    }

    if (id == NULL || content == NULL || layer_size == NULL) {
        ERROR("Invalid input arguments for driver umount layer");
        return -1;
    }

    return g_graphdriver->ops->apply_diff(id, g_graphdriver, content, layer_size);
}

int graphdriver_get_layer_metadata(const char *id, json_map_string_string *map_info)
{
    if (g_graphdriver == NULL) {
        ERROR("Driver not inited yet");
        return -1;
    }

    if (id == NULL || map_info == NULL) {
        ERROR("Invalid input arguments for driver umount layer");
        return -1;
    }

    return g_graphdriver->ops->get_layer_metadata(id, g_graphdriver, map_info);
}

struct graphdriver_status *graphdriver_get_status(void)
{
    int ret = -1;
    struct graphdriver_status *status = NULL;

    if (g_graphdriver == NULL) {
        ERROR("Driver not inited yet");
        return NULL;
    }

    status = util_common_calloc_s(sizeof(struct graphdriver_status));
    if (status == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }

    ret = g_graphdriver->ops->get_driver_status(g_graphdriver, status);
    if (ret != 0) {
        ERROR("Failed to get driver status");
        goto free_out;
    }

free_out:
    if (ret != 0) {
        free_graphdriver_status(status);
        return NULL;
    }
    return status;
}

void free_graphdriver_status(struct graphdriver_status *status)
{
    if (status == NULL) {
        return;
    }
    free(status->driver_name);
    status->driver_name = NULL;
    free(status->backing_fs);
    status->backing_fs = NULL;
    free(status->status);
    status->status = NULL;
    free(status);
}

void free_graphdriver_mount_opts(struct driver_mount_opts *opts)
{
    if (opts == NULL) {
        return;
    }
    free(opts->mount_label);
    opts->mount_label = NULL;
    util_free_array_by_len(opts->options, opts->options_len);

    free(opts);
}

int graphdriver_cleanup(void)
{
    if (g_graphdriver == NULL) {
        ERROR("Driver not inited yet");
        return -1;
    }

    return g_graphdriver->ops->clean_up(g_graphdriver);
}

int graphdriver_try_repair_lowers(const char *id, const char *parent)
{
    if (g_graphdriver == NULL) {
        ERROR("Driver not inited yet");
        return -1;
    }

    if (id == NULL || parent == NULL) {
        ERROR("Invalid input arguments for driver repair lower");
        return -1;
    }

    return g_graphdriver->ops->try_repair_lowers(id, parent, g_graphdriver);
}
