/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: provide oci image operator definition
*******************************************************************************/
#include "oci_image.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "isula_libutils/log.h"
#include "oci_pull.h"
#include "oci_login.h"
#include "oci_logout.h"
#include "registry.h"
#include "utils.h"
#include "utils_images.h"
#include "storage.h"
#include "oci_load.h"
#include "oci_import.h"
#include "oci_export.h"
#include "err_msg.h"
#include "oci_common_operators.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_string.h"
#include "isulad_config.h"

#define IMAGE_NOT_KNOWN_ERR "image not known"

struct oci_image_module_data g_oci_image_module_data = { 0 };

static void free_oci_image_data(void)
{
    free(g_oci_image_module_data.root_dir);
    g_oci_image_module_data.root_dir = NULL;

    g_oci_image_module_data.use_decrypted_key = false;
    g_oci_image_module_data.insecure_skip_verify_enforce = false;

    util_free_array_by_len(g_oci_image_module_data.registry_mirrors, g_oci_image_module_data.registry_mirrors_len);
    g_oci_image_module_data.registry_mirrors = NULL;
    g_oci_image_module_data.registry_mirrors_len = 0;

    util_free_array_by_len(g_oci_image_module_data.insecure_registries, g_oci_image_module_data.insecure_registries_len);
    g_oci_image_module_data.insecure_registries = NULL;
    g_oci_image_module_data.insecure_registries_len = 0;
}

static int oci_image_data_init(const isulad_daemon_configs *args)
{
    int nret = 0;
    size_t i;
    char *p = NULL;

    if (args->graph == NULL) {
        ERROR("args graph NULL");
        return -1;
    }
    g_oci_image_module_data.root_dir = util_strdup_s(args->graph);

    if (args->use_decrypted_key == NULL) {
        g_oci_image_module_data.use_decrypted_key = true;
    } else {
        g_oci_image_module_data.use_decrypted_key = *(args->use_decrypted_key);
    }

    g_oci_image_module_data.insecure_skip_verify_enforce = args->insecure_skip_verify_enforce;

    if (util_array_len((const char **)args->registry_mirrors) != args->registry_mirrors_len) {
        ERROR("registry_mirrors_len is not the length of registry_mirrors");
        goto free_out;
    }
    if (args->registry_mirrors_len != 0) {
        for (i = 0; i < args->registry_mirrors_len; i++) {
            p = args->registry_mirrors[i];
            if (p == NULL) {
                break;
            }
            nret = util_array_append(&g_oci_image_module_data.registry_mirrors, p);
            if (nret != 0) {
                ERROR("Out of memory");
                goto free_out;
            }
            g_oci_image_module_data.registry_mirrors_len++;
        }
    }

    if (util_array_len((const char **)args->insecure_registries) != args->insecure_registries_len) {
        ERROR("insecure_registries_len is not the length of insecure_registries");
        goto free_out;
    }
    if (args->insecure_registries_len != 0) {
        for (i = 0; i < args->insecure_registries_len; i++) {
            p = args->insecure_registries[i];
            if (p == NULL) {
                break;
            }
            nret = util_array_append(&g_oci_image_module_data.insecure_registries, p);
            if (nret != 0) {
                ERROR("Out of memory");
                goto free_out;
            }
            g_oci_image_module_data.insecure_registries_len++;
        }
    }

    return 0;

free_out:
    free_oci_image_data();
    return -1;
}

struct oci_image_module_data *get_oci_image_data(void)
{
    return &g_oci_image_module_data;
}

// only use overlay as the driver name if specify overlay2 or overlay
static char *format_driver_name(const char *driver)
{
    if (driver == NULL) {
        return NULL;
    }

    if (strcmp(driver, "overlay") == 0 || strcmp(driver, "overlay2") == 0) {
        return util_strdup_s("overlay");
    } else {
        return util_strdup_s(driver);
    }
}

#ifndef LIB_ISULAD_IMG_SO
static int do_integration_of_images_check(bool image_layer_check, struct storage_module_init_options *opts)
{
    char *check_file = NULL;
    int fd = -1;
    int ret = 0;

    check_file = conf_get_graph_check_flag_file();
    if (check_file == NULL) {
        ERROR("Failed to get oci image checked flag");
        return -1;
    }
    opts->integration_check = util_file_exists(check_file) && image_layer_check;
    if (opts->integration_check) {
        INFO("OCI image checked flag %s exist, need to check image integrity", check_file);
    }

    if (util_build_dir(check_file) != 0) {
        ERROR("Failed to create directory for checked flag file: %s", check_file);
        ret = -1;
        goto out;
    }

    fd = util_open(check_file, O_RDWR | O_CREAT, SECURE_CONFIG_FILE_MODE);
    if (fd < 0) {
        ERROR("Failed to create checked file: %s", check_file);
        ret = -1;
        goto out;
    }

out:
    if (fd >= 0) {
        close(fd);
    }
    free(check_file);
    return ret;
}
#endif // LIB_ISULAD_IMG_SO

static int storage_module_init_helper(const isulad_daemon_configs *args)
{
    int ret = 0;
    struct storage_module_init_options *storage_opts = NULL;

    storage_opts = util_common_calloc_s(sizeof(struct storage_module_init_options));
    if (storage_opts == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    storage_opts->driver_name = format_driver_name(args->storage_driver);
    if (storage_opts->driver_name == NULL) {
        ERROR("Failed to get storage driver name");
        ret = -1;
        goto out;
    }

    storage_opts->storage_root = util_path_join(args->graph, OCI_IMAGE_GRAPH_ROOTPATH_NAME);
    if (storage_opts->storage_root == NULL) {
        ERROR("Failed to get storage root dir");
        ret = -1;
        goto out;
    }

    storage_opts->storage_run_root = util_path_join(args->state, OCI_IMAGE_GRAPH_ROOTPATH_NAME);
    if (storage_opts->storage_run_root == NULL) {
        ERROR("Failed to get storage run root dir");
        ret = -1;
        goto out;
    }

    if (util_dup_array_of_strings((const char **)args->storage_opts, args->storage_opts_len, &storage_opts->driver_opts,
                                  &storage_opts->driver_opts_len) != 0) {
        ERROR("Failed to get storage storage opts");
        ret = -1;
        goto out;
    }

#ifndef LIB_ISULAD_IMG_SO
    if (do_integration_of_images_check(args->image_layer_check, storage_opts) != 0) {
        ret = -1;
        goto out;
    }
#endif // LIB_ISULAD_IMG_SO

    if (storage_module_init(storage_opts) != 0) {
        ERROR("Failed to init storage module");
        ret = -1;
        goto out;
    }

out:
    free_storage_module_init_options(storage_opts);
    return ret;
}

static int recreate_image_tmpdir()
{
    char *image_tmp_path = NULL;
    int ret = 0;

    image_tmp_path = oci_get_isulad_tmpdir(g_oci_image_module_data.root_dir);
    if (image_tmp_path == NULL) {
        ERROR("failed to get image tmp path");
        ret = -1;
        goto out;
    }

    if (util_recursive_rmdir(image_tmp_path, 0)) {
        ERROR("failed to remove directory %s", image_tmp_path);
        ret = -1;
        goto out;
    }

    if (util_mkdir_p(image_tmp_path, TEMP_DIRECTORY_MODE)) {
        ERROR("failed to create directory %s", image_tmp_path);
        ret = -1;
        goto out;
    }

out:
    free(image_tmp_path);

    return ret;
}

int oci_init(const isulad_daemon_configs *args)
{
    int ret = 0;

    if (args == NULL) {
        ERROR("Invalid image config");
        return ret;
    }

    ret = oci_image_data_init(args);
    if (ret != 0) {
        ERROR("Failed to init oci image");
        goto out;
    }

    ret = recreate_image_tmpdir();
    if (ret != 0) {
        goto out;
    }

    ret = registry_init(NULL, NULL);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    if (storage_module_init_helper(args) != 0) {
        ret = -1;
        goto out;
    }

out:

    return ret;
}

void oci_exit()
{
    storage_module_exit();
    free_oci_image_data();
}

int oci_pull_rf(const im_pull_request *request, im_pull_response *response)
{
    return oci_do_pull_image(request, response);
}

int oci_prepare_rf(const im_prepare_request *request, char **real_rootfs)
{
    int ret = 0;

    if (request == NULL) {
        ERROR("Bim is NULL");
        return -1;
    }

    if (storage_rootfs_create(request->container_id, request->image_name, request->mount_label, request->storage_opt,
                              real_rootfs) != 0) {
        ERROR("Failed to create container rootfs:%s", request->container_id);
        isulad_try_set_error_message("Failed to create container rootfs:%s", request->container_id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

int oci_merge_conf_rf(const char *img_name, container_config *container_spec)
{
    int ret = 0;

    if (img_name == NULL || container_spec == NULL) {
        ERROR("Invalid input arguments for oci_merge_conf_rf");
        return -1;
    }

    ret = oci_image_conf_merge_into_spec(img_name, container_spec);
    if (ret != 0) {
        ERROR("Failed to merge oci config for image: %s", img_name);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

int oci_delete_rf(const im_delete_rootfs_request *request)
{
    if (request == NULL) {
        ERROR("Request is NULL");
        return -1;
    }

    return storage_rootfs_delete(request->name_id);
}

int oci_mount_rf(const im_mount_request *request)
{
    char *mount_point = NULL;

    if (request == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    mount_point = storage_rootfs_mount(request->name_id);
    if (mount_point == NULL) {
        ERROR("Failed to mount rootfs %s", request->name_id);
        return -1;
    }

    free(mount_point);
    return 0;
}

int oci_umount_rf(const im_umount_request *request)
{
    if (request == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    return storage_rootfs_umount(request->name_id, request->force);
}

int oci_rmi(const im_rmi_request *request)
{
    int ret = 0;
    char *image_ID = NULL;
    char *real_image_name = NULL;
    char **image_names = NULL;
    size_t image_names_len = 0;
    char **reduced_image_names = NULL;
    size_t reduced_image_names_len = 0;
    size_t i;

    if (request == NULL || request->image.image == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    real_image_name = oci_resolve_image_name(request->image.image);
    if (real_image_name == NULL) {
        ERROR("Failed to resolve image name");
        ret = -1;
        goto out;
    }

    if (storage_img_get_names(real_image_name, &image_names, &image_names_len) != 0) {
        ERROR("Get image %s names failed", real_image_name);
        ret = -1;
        goto out;
    }

    image_ID = storage_img_get_image_id(real_image_name);
    if (image_ID == NULL) {
        ERROR("Get id of image %s failed", real_image_name);
        ret = -1;
        goto out;
    }

    if (image_names_len == 1 || util_has_prefix(image_ID, real_image_name)) {
        ret = storage_img_delete(real_image_name, true);
        if (ret != 0) {
            ERROR("Failed to remove image '%s'", real_image_name);
        }
        goto out;
    }

    reduced_image_names = (char **)util_smart_calloc_s(sizeof(char *), image_names_len - 1);
    if (reduced_image_names == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < image_names_len; i++) {
        if (strcmp(image_names[i], real_image_name) != 0) {
            reduced_image_names[reduced_image_names_len] = util_strdup_s(image_names[i]);
            if (reduced_image_names[reduced_image_names_len] == NULL) {
                ERROR("Out of memory");
                ret = -1;
                goto out;
            }
            reduced_image_names_len++;
        }
    }

    ret = storage_img_set_names(real_image_name, (const char **)reduced_image_names, reduced_image_names_len);
    if (ret != 0) {
        ERROR("Failed to set names of image '%s'", real_image_name);
        goto out;
    }

out:
    free(real_image_name);
    free(image_ID);
    util_free_array_by_len(image_names, image_names_len);
    util_free_array_by_len(reduced_image_names, image_names_len - 1);
    return ret;
}

int oci_import(const im_import_request *request, char **id)
{
    int ret = -1;
    char *dest_name = NULL;
    char *errmsg = NULL;

    if (request == NULL || request->file == NULL || request->tag == NULL || id == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    dest_name = oci_normalize_image_name(request->tag);
    if (dest_name == NULL) {
        ret = -1;
        ERROR("Failed to resolve image name");
        goto err_out;
    }

    ret = oci_do_import(request->file, dest_name, id);
    if (ret != 0) {
        goto err_out;
    }

    goto out;

err_out:
    free(*id);
    *id = NULL;
out:
    free(dest_name);
    free(errmsg);
    return ret;
}

int oci_tag(const im_tag_request *request)
{
    int ret = -1;
    char *src_name = NULL;
    char *dest_name = NULL;
    const char *errmsg = NULL;

    if (request == NULL || request->src_name.image == NULL || request->dest_name.image == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    src_name = oci_resolve_image_name(request->src_name.image);
    if (src_name == NULL) {
        ret = -1;
        ERROR("Failed to resolve source image name");
        goto out;
    }
    dest_name = oci_normalize_image_name(request->dest_name.image);
    if (dest_name == NULL) {
        ret = -1;
        ERROR("Failed to resolve dest image name");
        goto out;
    }

    ret = storage_img_add_name(src_name, dest_name);
    if (ret != 0) {
        errmsg = "add name failed when run isula tag";
        isulad_set_error_message("Failed to tag image with error: %s", errmsg);
        ERROR("Failed to tag image '%s' to '%s' with error: %s", src_name, dest_name, errmsg);
        goto out;
    }

out:
    free(src_name);
    free(dest_name);
    return ret;
}

int oci_container_filesystem_usage(const im_container_fs_usage_request *request, imagetool_fs_info **fs_usage)
{
    int ret = 0;
    imagetool_fs_info *layer_fs_tmp = NULL;

    if (request == NULL || fs_usage == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    layer_fs_tmp = util_common_calloc_s(sizeof(imagetool_fs_info));
    if (layer_fs_tmp == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    ret = storage_rootfs_fs_usgae(request->name_id, layer_fs_tmp);
    if (ret != 0) {
        ERROR("Failed to inspect container filesystem info");
        ret = -1;
        goto out;
    }

    *fs_usage = layer_fs_tmp;
    layer_fs_tmp = NULL;

out:
    free_imagetool_fs_info(layer_fs_tmp);
    return ret;
}

int oci_get_filesystem_info(im_fs_info_response **response)
{
    int ret = -1;

    if (response == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    *response = (im_fs_info_response *)util_common_calloc_s(sizeof(im_fs_info_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    (*response)->fs_info = util_common_calloc_s(sizeof(imagetool_fs_info));
    if ((*response)->fs_info == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }

    ret = storage_get_images_fs_usage((*response)->fs_info);
    if (ret != 0) {
        ERROR("Failed to inspect image filesystem info");
        goto err_out;
    }

    return 0;

err_out:
    free_im_fs_info_response(*response);
    *response = NULL;
    return -1;
}

int oci_load_image(const im_load_request *request)
{
    int ret = 0;

    if (request == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    ret = oci_do_load(request);
    if (ret != 0) {
        ERROR("Failed to load image");
        goto out;
    }

out:
    return ret;
}

int oci_export_rf(const im_export_request *request)
{
    int ret = 0;

    if (request == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    ret = oci_do_export(request->name_id, request->file);
    if (ret != 0) {
        ERROR("Failed to export container: %s", request->name_id);
    }

    return ret;
}

int oci_login(const im_login_request *request)
{
    int ret = 0;

    if (request == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    ret = oci_do_login(request->server, request->username, request->password);
    if (ret != 0) {
        ERROR("Login failed");
    }

    return ret;
}

int oci_logout(const im_logout_request *request)
{
    int ret = 0;

    if (request == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    ret = oci_do_logout(request->server);
    if (ret != 0) {
        ERROR("Logout failed");
    }

    return ret;
}
