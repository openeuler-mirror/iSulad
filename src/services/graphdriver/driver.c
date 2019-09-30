/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
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
#include "utils.h"
#include "liblcrd.h"
#include "log.h"
#include "isula_imtool_interface.h"
#include "lcrd_config.h"

/* overlay2 */

#define DRIVER_OVERLAY2_NAME "overlay2"
static const struct graphdriver_ops g_overlay2_ops = {
    .init = overlay2_init,
    .parse_options = overlay2_parse_options,
    .is_quota_options = overlay2_is_quota_options,
};

static struct graphdriver g_drivers[] = {
    {.name = DRIVER_OVERLAY2_NAME, .ops = &g_overlay2_ops}
};

static const size_t g_numdrivers = sizeof(g_drivers) / sizeof(struct graphdriver);

struct graphdriver *graphdriver_init(const char *name, char **storage_opts, size_t storage_opts_len)
{
    size_t i = 0;

    if (name == NULL || storage_opts == NULL) {
        return NULL;
    }

    for (i = 0; i < g_numdrivers; i++) {
        if (strcmp(name, g_drivers[i].name) == 0) {
            if (g_drivers[i].ops->init(&g_drivers[i])) {
                return NULL;
            }
            if (g_drivers[i].ops->parse_options(&g_drivers[i], (const char **)storage_opts, storage_opts_len)) {
                return NULL;
            }
            return &g_drivers[i];
        }
    }

    lcrd_set_error_message("Invalid storage driver name: '%s'", name);
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

    lcrd_set_error_message("Invalid storage driver name: '%s'", name);
    return NULL;
}

// format: [status xx: val]
static int get_graphdriver_status_line_value(const char *line, char **start, char **end)
{
    char *pstart = NULL;
    char *pend = NULL;

    pstart = strchr(line, ':');
    if (pstart == NULL) {
        ERROR("Invalid output: %s", line);
        return -1;
    }
    pstart++;
    if (*pstart != ' ') {
        ERROR("Invalid output: %s", line);
        return -1;
    }
    pstart++;

    pend = strchr(pstart, '\n');
    if (pend == NULL) {
        ERROR("Invalid output: %s", pstart);
        return -1;
    }
    *pend++ = '\0';

    *start = pstart;
    *end = pend;
    return 0;
}

struct graphdriver_status *graphdriver_get_status(void)
{
    struct graphdriver_status *status = NULL;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    char *pstart = NULL;
    char *pend = NULL;
    int ret = -1;
    int nret = -1;

    command_ret = util_exec_cmd(execute_storage_status, NULL, NULL, &stdout_buffer, &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            ERROR("Failed to get storage status with error: %s", stderr_buffer);
            lcrd_set_error_message("Failed to get storage status with error: %s", stderr_buffer);
        } else {
            ERROR("Failed to exec storage status command");
            lcrd_set_error_message("Failed to storage status command");
        }
        goto free_out;
    }

    if (stdout_buffer == NULL) {
        ERROR("Failed to get storage status because can not get stdoutput");
        lcrd_set_error_message("Failed to get storage status because can not get stdoutput");
        goto free_out;
    }

    status = util_common_calloc_s(sizeof(struct graphdriver_status));
    if (status == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }

    // Backing Filesystem: extfs
    if (get_graphdriver_status_line_value(stdout_buffer, &pstart, &pend) != 0) {
        goto free_out;
    }
    status->backing_fs = util_strdup_s(pstart);

    // Supports d_type: true
    if (get_graphdriver_status_line_value(pend, &pstart, &pend) != 0) {
        goto free_out;
    }
    nret = util_str_to_bool(pstart, &status->supports_d_type);
    if (nret < 0) {
        ERROR("Invalid output: %s", pstart);
        goto free_out;
    }

    // Native Overlay Diff: true
    if (get_graphdriver_status_line_value(pend, &pstart, &pend) != 0) {
        goto free_out;
    }
    nret = util_str_to_bool(pstart, &status->native_overlay_diff);
    if (nret < 0) {
        ERROR("Invalid output: %s", pstart);
        goto free_out;
    }

    ret = 0;
free_out:
    free(stderr_buffer);
    free(stdout_buffer);
    if (ret != 0) {
        free_graphdriver_status(status);
        return NULL;
    }
    return status;
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
    driver_name = conf_get_lcrd_storage_driver();
    if (root == NULL || driver_name == NULL) {
        WARN("No root or driver name specified");
        goto cleanup;
    }
    if (strcmp(driver_name, "overlay2") == 0) {
        driver_name[strlen(driver_name) - 1] = '\0';
    }
    nret = sprintf_s(mp, sizeof(mp), "%s/%s", root, driver_name);
    if (nret < 0) {
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
    free(status);
}

