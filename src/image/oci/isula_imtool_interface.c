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
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide imtool interface
 ******************************************************************************/

#define _GNU_SOURCE /* See feature_test_macros(7) */
#include "isula_imtool_interface.h"
#include <fcntl.h> /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "securec.h"
#include "utils.h"
#include "log.h"
#include "liblcrd.h"
#include "lcrd_config.h"
#include "image.h"
#include "oci_image_pull.h"
#include "oci_image_status.h"
#include "oci_fs_info.h"
#include "oci_rootfs_prepare.h"
#include "oci_rootfs_mount.h"
#include "oci_rootfs_umount.h"
#include "oci_rootfs_remove.h"
#include "oci_rootfs_export.h"
#include "driver.h"

#define PARAM_NUM 100

/* image tool name */
#define ISULA_IMTOOL "isulad_kit"

/* global options */
#define IMTOOL_GB_OPTION_GRAPH_ROOT "--graph-root"
#define IMTOOL_GB_OPTION_RUN_ROOT "--run-root"
#define IMTOOL_GB_OPTION_DRIVER_NAME "--driver-name"
#define IMTOOL_GB_OPTION_DRIVER_OPTIONS "--driver-options"
#define IMTOOL_GB_OPTION_STORAGE_OPTIONS "--storage-opt"
#define IMTOOL_GB_OPTION_REGISTRY "--registry"
#define IMTOOL_GB_OPTION_INSEC_REGISTRY "--insecure-registry"
#define IMTOOL_GB_OPTION_OPT_TIMEOUT "--command-timeout"
#define IMTOOL_GB_OPTION_LOG_LEVEL "--log-level"

/* sub command */
#define IMTOOL_SUB_CMD_PULL "pull"
#define IMTOOL_CMD_PULL_OPTION_CREDS "--creds"
#define IMTOOL_CMD_PULL_OPTION_AUTH "--auth"
#define IMTOOL_CMD_PULL_DISABLE_TLS_VERIFY "--tls-verify=false"
#define IMTOOL_CMD_PULL_DISABLE_USE_DECRYPTED "--use-decrypted-key=false"

#define IMTOOL_SUB_CMD_STATUS "status"

#define IMTOOL_SUB_CMD_REMOVE_IMAGE "rmi"

#define IMTOOL_SUB_CMD_FS_INFO "fsinfo"

#define IMTOOL_SUB_CMD_LIST_IMAGES "images"
#define IMTOOL_CMD_IMAGES_OPTION_FILTER "--filter"
#define IMTOOL_CMD_IMAGES_OPTION_CHECK "--check"

#define IMTOOL_SUB_CMD_PREPARE_ROOTFS "prepare"
#define IMTOOL_CMD_PREPARE_OPTION_IMAGE "--image"
#define IMTOOL_CMD_PREPARE_OPTION_NAME "--name"
#define IMTOOL_CMD_PREPARE_OPTION_ID "--id"

#define IMTOOL_SUB_CMD_MOUNT_ROOTFS "mount"

#define IMTOOL_SUB_CMD_UMOUNT_ROOTFS "umount"

#define IMTOOL_SUB_CMD_REMOVE_ROOTFS "rm"

#define IMTOOL_SUB_CMD_INFO_IMAGE "info"

#define IMTOOL_SUB_CMD_STORAGE_STATUS "storage_status"

#define IMTOOL_SUB_CMD_UMOUNT_STORAGE "storage_umount"

#define IMTOOL_SUB_CMD_CONTAINER_FS_INFO "filesystemusage"

#define IMTOOL_SUB_CMD_EXPORT_ROOTFS "export"
#define IMTOOL_CMD_OUTPUT_OPTION_ROOTFS "--output"

#define IMTOOL_SUB_CMD_LOAD_IMAGE "load"
#define IMTOOL_CMD_INPUT_OPTION_IMAGE "--input"
#define IMTOOL_CMD_TAG_OPTION_IMAGE "--tag"

#define IMTOOL_SUB_CMD_LOGIN "login"
#define IMTOOL_SUB_CMD_LOGOUT "logout"

static inline void add_array_elem(char **array, size_t total, size_t *pos, const char *elem)
{
    if (*pos + 1 >= total - 1) {
        return;
    }
    array[*pos] = util_strdup_s(elem);
    *pos += 1;
}

static inline void add_array_kv(char **array, size_t total, size_t *pos, const char *k, const char *v)
{
    if (k == NULL || v == NULL) {
        return;
    }
    add_array_elem(array, total, pos, k);
    add_array_elem(array, total, pos, v);
}

static int pack_global_graph_driver(char *params[], size_t *count, bool ignore_storage_opt_size)
{
    int ret = -1;
    char *graph_driver = NULL;
    struct graphdriver *driver = NULL;
    char **graph_opts = NULL;
    char **p = NULL;
    size_t i = 0;

    i = *count;

    graph_driver = conf_get_lcrd_storage_driver();
    if (graph_driver == NULL) {
        COMMAND_ERROR("Failed to get graph driver");
        goto out;
    }
    driver = graphdriver_get(graph_driver);
    if (strcmp(graph_driver, "overlay2") == 0) {
        // Treating overlay2 as overlay cause image was downloaded always
        // in '/var/lib/lcrd/storage/overlay' directory.
        // See iSulad-kit/vendor/github.com/containers/storage/drivers/overlay/overlay.go,
        // Driver is inited by name "overlay".
        graph_driver[strlen(graph_driver) - 1] = '\0';
    }
    add_array_kv(params, PARAM_NUM, &i, IMTOOL_GB_OPTION_DRIVER_NAME, graph_driver);

    graph_opts = conf_get_storage_opts();
    // since iSulad-kit will set quota when pull image, which is differ from docker,
    // and we may get some error if setted, ignore it if neccessary.
    for (p = graph_opts; (p != NULL) && (*p != NULL); p++) {
        if (ignore_storage_opt_size && driver != NULL && driver->ops->is_quota_options(driver, *p)) {
            continue;
        }
        add_array_kv(params, PARAM_NUM, &i, IMTOOL_GB_OPTION_DRIVER_OPTIONS, *p);
    }

    ret = 0;
    *count = i;
out:
    free(graph_driver);
    util_free_array(graph_opts);
    return ret;
}

static int pack_global_graph_root(char *params[], size_t *count)
{
    int ret = -1;
    char *graph_root = NULL;
    size_t i = 0;

    i = *count;

    graph_root = conf_get_graph_rootpath();
    if (graph_root == NULL) {
        COMMAND_ERROR("Failed to get graph root directory");
        goto out;
    }
    add_array_kv(params, PARAM_NUM, &i, IMTOOL_GB_OPTION_GRAPH_ROOT, graph_root);

    ret = 0;
    *count = i;
out:
    free(graph_root);
    return ret;
}

static int pack_global_graph_run(char *params[], size_t *count)
{
    int ret = -1;
    char *graph_run = NULL;
    size_t i = 0;

    i = *count;

    graph_run = conf_get_graph_run_path();
    if (graph_run == NULL) {
        COMMAND_ERROR("Failed to get graph run directory");
        goto out;
    }
    add_array_kv(params, PARAM_NUM, &i, IMTOOL_GB_OPTION_RUN_ROOT, graph_run);

    ret = 0;
    *count = i;
out:
    free(graph_run);
    return ret;
}

static int pack_global_graph_registry(char *params[], size_t *count)
{
    int ret = -1;
    size_t i = 0;
    char **registry = NULL;
    char **insecure_registry = NULL;
    char **p = NULL;

    i = *count;

    registry = conf_get_registry_list();
    for (p = registry; (p != NULL) && (*p != NULL); p++) {
        add_array_kv(params, PARAM_NUM, &i, IMTOOL_GB_OPTION_REGISTRY, *p);
    }

    insecure_registry = conf_get_insecure_registry_list();
    for (p = insecure_registry; (p != NULL) && (*p != NULL); p++) {
        add_array_kv(params, PARAM_NUM, &i, IMTOOL_GB_OPTION_INSEC_REGISTRY, *p);
    }

    ret = 0;
    *count = i;

    util_free_array(registry);
    util_free_array(insecure_registry);
    return ret;
}

static int pack_global_opt_time(char *params[], size_t *count)
{
    int ret = -1;
    size_t i = 0;
    unsigned int opt_timeout = 0;
    char timeout_str[UINT_LEN + 2] = { 0 }; /*format: XXXs*/

    i = *count;

    opt_timeout = conf_get_im_opt_timeout();
    if (opt_timeout != 0) {
        add_array_elem(params, PARAM_NUM, &i, IMTOOL_GB_OPTION_OPT_TIMEOUT);
        if (sprintf_s(timeout_str, UINT_LEN, "%us", opt_timeout) < 0) {
            COMMAND_ERROR("Failed to print string");
            goto out;
        }
        add_array_elem(params, PARAM_NUM, &i, timeout_str);
    }

    ret = 0;
    *count = i;
out:
    return ret;
}

static int pack_global_option(char *params[], size_t *count, bool ignore_storage_opt_size)
{
    int ret = -1;
    size_t i = 0;

    i = *count;

    add_array_elem(params, PARAM_NUM, &i, ISULA_IMTOOL);

    if (pack_global_graph_root(params, &i) != 0) {
        goto out;
    }

    if (pack_global_graph_run(params, &i) != 0) {
        goto out;
    }

    if (pack_global_graph_driver(params, &i, ignore_storage_opt_size) != 0) {
        goto out;
    }

    if (pack_global_graph_registry(params, &i) != 0) {
        goto out;
    }

    if (pack_global_opt_time(params, &i) != 0) {
        goto out;
    }

    ret = 0;
    *count = i;

out:
    return ret;
}

void execute_pull_image(void *args)
{
    image_pull_request *request = (image_pull_request *)args;
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (request == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(params, &i, true) != 0) {
        goto out;
    }

    if (request->auth.server_address != NULL) {
        add_array_kv(params, PARAM_NUM, &i, IMTOOL_GB_OPTION_REGISTRY, request->auth.server_address);
    }

    add_array_elem(params, PARAM_NUM, &i, IMTOOL_SUB_CMD_PULL);

    if (conf_get_use_decrypted_key_flag() == false) {
        add_array_elem(params, PARAM_NUM, &i, IMTOOL_CMD_PULL_DISABLE_USE_DECRYPTED);
    }

    if (conf_get_skip_insecure_verify_flag() == true) {
        add_array_elem(params, PARAM_NUM, &i, IMTOOL_CMD_PULL_DISABLE_TLS_VERIFY);
    }

    add_array_elem(params, PARAM_NUM, &i, request->image.image);

    execvp(ISULA_IMTOOL, params);

    COMMAND_ERROR("Cannot pull image with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_status_image(void *args)
{
    oci_image_status_request *request = (oci_image_status_request *)args;
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (request == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(params, &i, true) != 0) {
        goto out;
    }

    add_array_elem(params, PARAM_NUM, &i, IMTOOL_SUB_CMD_STATUS);

    add_array_elem(params, PARAM_NUM, &i, request->image.image);

    execvp(ISULA_IMTOOL, params);

    COMMAND_ERROR("Cannot status image with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_remove_image(void *args)
{
    im_remove_request *request = (im_remove_request *)args;
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (request == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(params, &i, true) != 0) {
        goto out;
    }

    add_array_elem(params, PARAM_NUM, &i, IMTOOL_SUB_CMD_REMOVE_IMAGE);

    add_array_elem(params, PARAM_NUM, &i, request->image.image);

    execvp(ISULA_IMTOOL, params);

    COMMAND_ERROR("Cannot remove image with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_list_images(void *args)
{
    im_list_request *request = (im_list_request *)args;
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;
    const char *log_level = "error";

    if (request == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(params, &i, true) != 0) {
        goto out;
    }

    add_array_kv(params, PARAM_NUM, &i, IMTOOL_GB_OPTION_LOG_LEVEL, log_level);

    add_array_elem(params, PARAM_NUM, &i, IMTOOL_SUB_CMD_LIST_IMAGES);

    if (request->filter.image.image != NULL) {
        add_array_kv(params, PARAM_NUM, &i, IMTOOL_CMD_IMAGES_OPTION_FILTER, request->filter.image.image);
    }

    if (request->check) {
        add_array_elem(params, PARAM_NUM, &i, IMTOOL_CMD_IMAGES_OPTION_CHECK);
    }

    execvp(ISULA_IMTOOL, params);

    COMMAND_ERROR("Cannot list images with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_fs_info(void *args)
{
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(params, &i, true) != 0) {
        goto out;
    }

    add_array_elem(params, PARAM_NUM, &i, IMTOOL_SUB_CMD_FS_INFO);

    execvp(ISULA_IMTOOL, params);

    COMMAND_ERROR("Cannot get image filesystem info with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_prepare_rootfs(void *args)
{
    rootfs_prepare_request *request = (rootfs_prepare_request *)args;
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (request == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(params, &i, false) != 0) {
        goto out;
    }

    if (request->storage_opts != NULL && request->storage_opts_len > 0) {
        int j;
        for (j = 0; j < (int)request->storage_opts_len; j++) {
            add_array_kv(params, PARAM_NUM, &i, IMTOOL_GB_OPTION_STORAGE_OPTIONS, request->storage_opts[j]);
        }
    }

    add_array_elem(params, PARAM_NUM, &i, IMTOOL_SUB_CMD_PREPARE_ROOTFS);

    add_array_kv(params, PARAM_NUM, &i, IMTOOL_CMD_PREPARE_OPTION_IMAGE, request->image);

    add_array_kv(params, PARAM_NUM, &i, IMTOOL_CMD_PREPARE_OPTION_NAME, request->name);

    add_array_kv(params, PARAM_NUM, &i, IMTOOL_CMD_PREPARE_OPTION_ID, request->id);

    execvp(ISULA_IMTOOL, params);

    COMMAND_ERROR("Cannot prepare rootfs with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_mount_rootfs(void *args)
{
    rootfs_mount_request *mount_request = (rootfs_mount_request *)args;
    char *mount_params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (mount_request == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(mount_params, &i, false) != 0) {
        goto out;
    }

    add_array_elem(mount_params, PARAM_NUM, &i, IMTOOL_SUB_CMD_MOUNT_ROOTFS);

    if (mount_request->name_id != NULL) {
        add_array_elem(mount_params, PARAM_NUM, &i, mount_request->name_id);
    }

    execvp(ISULA_IMTOOL, mount_params);

    COMMAND_ERROR("Cannot mount rootfs with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_umount_rootfs(void *args)
{
    rootfs_umount_request *umount_request = (rootfs_umount_request *)args;
    char *umount_params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (umount_request == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(umount_params, &i, false) != 0) {
        goto out;
    }

    add_array_elem(umount_params, PARAM_NUM, &i, IMTOOL_SUB_CMD_UMOUNT_ROOTFS);

    if (umount_request->name_id != NULL) {
        add_array_elem(umount_params, PARAM_NUM, &i, umount_request->name_id);
    }

    execvp(ISULA_IMTOOL, umount_params);

    COMMAND_ERROR("Cannot umount rootfs with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_remove_rootfs(void *args)
{
    rootfs_remove_request *remove_request = (rootfs_remove_request *)args;
    char *remove_params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (remove_request == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(remove_params, &i, true) != 0) {
        goto out;
    }

    add_array_elem(remove_params, PARAM_NUM, &i, IMTOOL_SUB_CMD_REMOVE_ROOTFS);

    if (remove_request->name_id != NULL) {
        add_array_elem(remove_params, PARAM_NUM, &i, remove_request->name_id);
    }

    execvp(ISULA_IMTOOL, remove_params);

    COMMAND_ERROR("Cannot remove rootfs with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_storage_status(void *args)
{
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(params, &i, true) != 0) {
        goto out;
    }

    add_array_elem(params, PARAM_NUM, &i, IMTOOL_SUB_CMD_STORAGE_STATUS);

    execvp(ISULA_IMTOOL, params);

    COMMAND_ERROR("Cannot get storage status with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_container_fs_info(void *args)
{
    const char *id = (const char *)args;
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (id == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(params, &i, true) != 0) {
        goto out;
    }

    add_array_elem(params, PARAM_NUM, &i, IMTOOL_SUB_CMD_CONTAINER_FS_INFO);

    add_array_elem(params, PARAM_NUM, &i, id);

    execvp(ISULA_IMTOOL, params);

    COMMAND_ERROR("Cannot get filesystem usage with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_export_rootfs(void *args)
{
    rootfs_export_request *request = (rootfs_export_request *)args;
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (request == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(params, &i, true) != 0) {
        goto out;
    }

    add_array_elem(params, PARAM_NUM, &i, IMTOOL_SUB_CMD_EXPORT_ROOTFS);

    add_array_kv(params, PARAM_NUM, &i, IMTOOL_CMD_OUTPUT_OPTION_ROOTFS, request->file);

    add_array_elem(params, PARAM_NUM, &i, request->id);

    execvp(ISULA_IMTOOL, params);

    COMMAND_ERROR("Cannot export rootfs with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_load_image(void *args)
{
    im_load_request *request = (im_load_request *)args;
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (request == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(params, &i, true) != 0) {
        goto out;
    }

    add_array_elem(params, PARAM_NUM, &i, IMTOOL_SUB_CMD_LOAD_IMAGE);

    add_array_kv(params, PARAM_NUM, &i, IMTOOL_CMD_INPUT_OPTION_IMAGE, request->file);

    if (request->tag != NULL) {
        add_array_kv(params, PARAM_NUM, &i, IMTOOL_CMD_TAG_OPTION_IMAGE, request->tag);
    }

    execvp(ISULA_IMTOOL, params);

    COMMAND_ERROR("Cannot load image with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_login(void *args)
{
    im_login_request *request = (im_login_request *)args;
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (request == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(params, &i, true) != 0) {
        goto out;
    }

    add_array_elem(params, PARAM_NUM, &i, IMTOOL_SUB_CMD_LOGIN);

    if (conf_get_use_decrypted_key_flag() == false) {
        add_array_elem(params, PARAM_NUM, &i, IMTOOL_CMD_PULL_DISABLE_USE_DECRYPTED);
    }

    if (conf_get_skip_insecure_verify_flag() == true) {
        add_array_elem(params, PARAM_NUM, &i, IMTOOL_CMD_PULL_DISABLE_TLS_VERIFY);
    }

    add_array_elem(params, PARAM_NUM, &i, request->server);

    execvp(ISULA_IMTOOL, params);

    COMMAND_ERROR("Cannot login with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}

void execute_logout(void *args)
{
    im_logout_request *request = (im_logout_request *)args;
    char *params[PARAM_NUM] = { NULL };
    size_t i = 0;

    if (request == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        return;
    }

    if (util_check_inherited(true, -1) != 0) {
        COMMAND_ERROR("Close inherited fds failed");
        goto out;
    }

    if (pack_global_option(params, &i, true) != 0) {
        goto out;
    }

    add_array_elem(params, PARAM_NUM, &i, IMTOOL_SUB_CMD_LOGOUT);

    if (conf_get_use_decrypted_key_flag() == false) {
        add_array_elem(params, PARAM_NUM, &i, IMTOOL_CMD_PULL_DISABLE_USE_DECRYPTED);
    }

    if (conf_get_skip_insecure_verify_flag() == true) {
        add_array_elem(params, PARAM_NUM, &i, IMTOOL_CMD_PULL_DISABLE_TLS_VERIFY);
    }

    add_array_elem(params, PARAM_NUM, &i, request->server);

    execvp(ISULA_IMTOOL, params);

    COMMAND_ERROR("Cannot logout with '%s':%s", ISULA_IMTOOL, strerror(errno));

out:
    exit(EXIT_FAILURE);
}
