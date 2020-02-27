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
#include "utils.h"
#include "libisulad.h"
#include "isula_libutils/log.h"
#include "isulad_config.h"
#include "image.h"
#include "util_archive.h"

/* overlay/overlay2 */
#define DRIVER_OVERLAY_NAME "overlay"
#define DRIVER_OVERLAY2_NAME "overlay2"
static const struct graphdriver_ops g_overlay2_ops = {
    .init = overlay2_init,
    .is_quota_options = overlay2_is_quota_options,
    .create_rw = overlay2_create_rw,
    .rm_layer = overlay2_rm_layer,
    .mount_layer = overlay2_mount_layer,
    .umount_layer = overlay2_umount_layer,
    .exists = overlay2_layer_exists,
    .apply_diff = overlay2_apply_diff,
};

/* devicemapper */
#define DRIVER_DEVMAPPER_NAME "devicemapper"

static const struct graphdriver_ops g_devmapper_ops = {
    .init = devmapper_init,
    .is_quota_options = devmapper_is_quota_options,
};

static struct graphdriver g_drivers[] = {
    {.name = DRIVER_OVERLAY2_NAME, .ops = &g_overlay2_ops},
    {.name = DRIVER_DEVMAPPER_NAME, .ops = &g_devmapper_ops}
};

static const size_t g_numdrivers = sizeof(g_drivers) / sizeof(struct graphdriver);

struct graphdriver *graphdriver_init(const char *name, const char *isulad_root, char **storage_opts,
                                     size_t storage_opts_len)
{
    size_t i = 0;
    char driver_home[PATH_MAX] = { 0 };
    //test
    struct driver_create_opts test_create_opts = { 0 };
    struct driver_mount_opts test_mount_opts = { 0 };

    if (name == NULL || storage_opts == NULL || isulad_root == NULL) {
        return NULL;
    }

    int nret = snprintf(driver_home, PATH_MAX, "%s/%s/%s", isulad_root, "storage", name);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        ERROR("Sprintf graph driver path failed");
        return NULL;
    }

    for (i = 0; i < g_numdrivers; i++) {
        if (strcmp(name, g_drivers[i].name) == 0) {
            if (g_drivers[i].ops->init(&g_drivers[i], driver_home, (const char **)storage_opts, storage_opts_len)) {
                return NULL;
            }
            //just for test
            if (g_drivers[i].ops->create_rw("1", "", &g_drivers[i], &test_create_opts) != 0) {
                return NULL;
            }
            if (g_drivers[i].ops->create_rw("2", "1", &g_drivers[i], &test_create_opts) != 0) {
                return NULL;
            }
            if (g_drivers[i].ops->create_rw("3", "2", &g_drivers[i], &test_create_opts) != 0) {
                return NULL;
            }

            if (g_drivers[i].ops->create_rw("4", "3", &g_drivers[i], &test_create_opts) != 0) {
                return NULL;
            }
            char *test_merged = g_drivers[i].ops->mount_layer("4", &g_drivers[i], &test_mount_opts);
            if (test_merged == NULL) {
                return NULL;
            }
            ERROR("mount: %s", test_merged);

            if (test_archive() != 0) {
                ERROR("Failed!!!");
            }

            //if (g_drivers[i].ops->rm_layer("3", &g_drivers[i]) != 0) {
            //    return NULL;
            // }
            // end test

            return &g_drivers[i];
        }
    }

    ERROR("Invalid storage driver name: '%s'", name);
    return NULL;
}

struct graphdriver *graphdriver_get(const char *name)
{
    size_t i = 0;

    if (name == NULL) {
        return NULL;
    }

    for (i = 0; i < g_numdrivers; i++) {
        if (strcmp(name, g_drivers[i].name) == 0) {
            return &g_drivers[i];
        }
    }

    isulad_set_error_message("Invalid storage driver name: '%s'", name);
    return NULL;
}

struct graphdriver_status *graphdriver_get_status(void)
{
    struct graphdriver_status *status = NULL;
    int ret = -1;
    im_storage_status_response *resp = NULL;

    ret = im_get_storage_status(IMAGE_TYPE_OCI, &resp);
    if (ret != 0) {
        return NULL;
    }

    status = util_common_calloc_s(sizeof(struct graphdriver_status));
    if (status == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }

    status->backing_fs = util_strdup_s(resp->backing_fs);
    status->status = util_strdup_s(resp->status);

    ret = 0;
free_out:
    free_im_storage_status_response(resp);
    if (ret != 0) {
        free_graphdriver_status(status);
        return NULL;
    }
    return status;
}

container_inspect_graph_driver *graphdriver_get_metadata(char *id)
{
    container_inspect_graph_driver *inspect_driver = NULL;
    int ret = -1;
    im_storage_metadata_response *resp = NULL;
    int i = 0;

    ret = im_get_storage_metadata(IMAGE_TYPE_OCI, id, &resp);
    if (ret != 0) {
        goto free_out;
    }

    if (resp->name == NULL || resp->metadata == NULL) {
        ERROR("Failed to get metadata or name");
        ret = -1;
        goto free_out;
    }

    inspect_driver = util_common_calloc_s(sizeof(container_inspect_graph_driver));
    if (inspect_driver == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }
    inspect_driver->data = util_common_calloc_s(sizeof(container_inspect_graph_driver_data));
    if (inspect_driver->data == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }

    inspect_driver->name = util_strdup_s(resp->name);

    if (!strcmp(resp->name, DRIVER_OVERLAY_NAME) || !strcmp(resp->name, DRIVER_OVERLAY2_NAME)) {
        for (i = 0; i < resp->metadata->len; i++) {
            if (!strcmp(resp->metadata->keys[i], "LowerDir")) {
                inspect_driver->data->lower_dir = util_strdup_s(resp->metadata->values[i]);
            } else if (!strcmp(resp->metadata->keys[i], "MergedDir")) {
                inspect_driver->data->merged_dir = util_strdup_s(resp->metadata->values[i]);
            } else if (!strcmp(resp->metadata->keys[i], "UpperDir")) {
                inspect_driver->data->upper_dir = util_strdup_s(resp->metadata->values[i]);
            } else if (!strcmp(resp->metadata->keys[i], "WorkDir")) {
                inspect_driver->data->work_dir = util_strdup_s(resp->metadata->values[i]);
            }
        }
    } else if (!strcmp(resp->name, DRIVER_DEVMAPPER_NAME)) {
        for (i = 0; i < resp->metadata->len; i++) {
            if (!strcmp(resp->metadata->keys[i], "DeviceId")) {
                inspect_driver->data->device_id = util_strdup_s(resp->metadata->values[i]);
            } else if (!strcmp(resp->metadata->keys[i], "DeviceName")) {
                inspect_driver->data->device_name = util_strdup_s(resp->metadata->values[i]);
            } else if (!strcmp(resp->metadata->keys[i], "DeviceSize")) {
                inspect_driver->data->device_size = util_strdup_s(resp->metadata->values[i]);
            }
        }
    } else {
        ERROR("Unsupported driver %s", resp->name);
        ret = -1;
        goto free_out;
    }

    ret = 0;
free_out:
    free_im_storage_metadata_response(resp);
    if (ret != 0) {
        free_container_inspect_graph_driver(inspect_driver);
        return NULL;
    }
    return inspect_driver;
}

int update_graphdriver_status(struct graphdriver **driver)
{
    struct graphdriver_status *status = NULL;
    int ret = 0;

    if (driver == NULL) {
        return -1;
    }

    status = graphdriver_get_status();
    if (status == NULL) {
        ERROR("Can not get driver status");
        return -1;
    }
    if (*driver == NULL) {
        *driver = util_common_calloc_s(sizeof(struct graphdriver));
        if (*driver == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
    }
    free((*driver)->backing_fs);
    (*driver)->backing_fs = util_strdup_s(status->backing_fs);
out:
    free_graphdriver_status(status);
    return ret;
}

void graphdriver_umount_mntpoint(void)
{
    char *root = NULL;
    char *driver_name = NULL;
    char mp[PATH_MAX] = { 0 };
    int nret = 0;

    root = conf_get_graph_rootpath();
    driver_name = conf_get_isulad_storage_driver();
    if (root == NULL || driver_name == NULL) {
        WARN("No root or driver name specified");
        goto cleanup;
    }
    if (strcmp(driver_name, "overlay2") == 0) {
        driver_name[strlen(driver_name) - 1] = '\0';
    }
    nret = snprintf(mp, sizeof(mp), "%s/%s", root, driver_name);
    if (nret < 0 || (size_t)nret >= sizeof(mp)) {
        WARN("Failed to print string");
        goto cleanup;
    }
    if (umount(mp) < 0 && errno != EINVAL) {
        WARN("Can not umount: %s: %s", mp, strerror(errno));
    }
cleanup:
    free(root);
    free(driver_name);
}

void free_graphdriver_status(struct graphdriver_status *status)
{
    if (status == NULL) {
        return;
    }
    free(status->backing_fs);
    free(status->status);
    free(status);
}

