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

#include <pthread.h>
#include <semaphore.h>

#include "isula_libutils/log.h"
#include "log.h"
#include "oci_pull.h"
#include "oci_login.h"
#include "oci_logout.h"
#include "registry.h"

#include "containers_store.h"

#include "isulad_config.h"
#include "utils.h"

#define IMAGE_NOT_KNOWN_ERR "image not known"


static int storage_module_init_helper(const struct service_arguments *args)
{
    int ret = 0;
    struct storage_module_init_options *storage_opts = NULL;

    storage_opts = util_common_calloc_s(sizeof(struct storage_module_init_options));
    if (storage_opts == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    storage_opts->driver_name = util_strdup_s(args->json_confs->storage_driver);
    storage_opts->storage_root = util_path_join(args->json_confs->graph, GRAPH_ROOTPATH_NAME);
    if (storage_opts->storage_root == NULL) {
        ERROR("Failed to get storage root dir");
        ret = -1;
        goto out;
    }

    storage_opts->storage_run_root = util_path_join(args->json_confs->state, GRAPH_ROOTPATH_NAME);
    if (storage_opts->storage_run_root == NULL) {
        ERROR("Failed to get storage run root dir");
        ret = -1;
        goto out;
    }

    if (dup_array_of_strings((const char **)args->json_confs->storage_opts,
                             args->json_confs->storage_opts_len, &storage_opts->driver_opts, &storage_opts->driver_opts_len) != 0) {
        ERROR("Failed to get storage storage opts");
        ret = -1;
        goto out;
    }

    if (storage_module_init(storage_opts) != 0) {
        ERROR("Failed to init storage module");
        ret = -1;
        goto out;
    }

out:
    free_storage_module_init_options(storage_opts);
    return ret;
}

int oci_init(const struct service_arguments *args)
{
    int ret = 0;

    if (args == NULL) {
        ERROR("Invalid image config");
        return ret;
    }

    ret = registry_init();
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

int oci_pull_rf(const im_pull_request *request, im_pull_response **response)
{
    return oci_do_pull_image(request, response);
}

int oci_prepare_rf(const im_prepare_request *request, char **real_rootfs)
{
    if (request == NULL) {
        ERROR("Bim is NULL");
        return -1;
    }

    // TODO call storage rootfs prepare interface
    //return isula_rootfs_prepare_and_get_image_conf(request->container_id, request->image_name, request->storage_opt,
    //                                              real_rootfs, NULL);
    return 0;
}

int oci_merge_conf_rf(const host_config *host_spec, container_config *container_spec,
                      const im_prepare_request *request, char **real_rootfs)
{
    oci_image_spec *image = NULL;
    int ret = -1;

    if (request == NULL) {
        ERROR("Bim is NULL");
        return -1;
    }

    // TODO call storage rootfs prepare interface
    //ret = isula_rootfs_prepare_and_get_image_conf(request->container_id, request->image_name, host_spec->storage_opt,
    //                                              real_rootfs, &image);
    if (ret != 0) {
        ERROR("Get prepare rootfs failed of image: %s", request->image_name);
        goto out;
    }
    ret = oci_image_conf_merge_into_spec(request->image_name, container_spec);
    if (ret != 0) {
        ERROR("Failed to merge oci config for image: %s", request->image_name);
        goto out;
    }

out:
    free_oci_image_spec(image);
    return ret;
}

int oci_delete_rf(const im_delete_request *request)
{
    if (request == NULL) {
        ERROR("Request is NULL");
        return -1;
    }

    // TODO call storage rootfs remove interface
    //return isula_rootfs_remove(request->name_id);
    return 0;
}

int oci_mount_rf(const im_mount_request *request)
{
    if (request == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }
    // TODO call storage rootfs mount interface
    //return isula_rootfs_mount(request->name_id);
    return 0;
}

int oci_umount_rf(const im_umount_request *request)
{
    if (request == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }
    // TODO call storage rootfs umount interface
    //return isula_rootfs_umount(request->name_id, request->force);
    return 0;
}

int oci_rmi(const im_remove_request *request)
{
    int ret = -1;
    char *real_image_name = NULL;

    if (request == NULL || request->image.image == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    real_image_name = oci_resolve_image_name(request->image.image);
    if (real_image_name == NULL) {
        ERROR("Failed to resolve image name");
        goto out;
    }

    ret = storage_img_delete(real_image_name, true);
    if (ret != 0) {
        ERROR("Failed to remove image '%s'", real_image_name);
        goto out;
    }

out:
    free(real_image_name);
    return ret;
}

int isula_import(const im_import_request *request, char **id)
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

    ret = isula_do_import(request->file, dest_name, id);
    if (ret != 0) {
        goto err_out;
    }

    ret = register_new_oci_image_into_memory(dest_name);
    if (ret != 0) {
        ERROR("Register image %s into store failed", dest_name);
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
    char *errmsg = NULL;

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
    if (src_name == NULL) {
        ret = -1;
        ERROR("Failed to resolve source image name");
        goto out;
    }

    // TODO call storage rootfs tag interface
    // ret = isula_image_tag(src_name, dest_name, &errmsg);
    if (ret != 0) {
        isulad_set_error_message("Failed to tag image with error: %s", errmsg);
        ERROR("Failed to tag image '%s' to '%s' with error: %s", src_name, dest_name, errmsg);
        goto out;
    }

out:
    free(src_name);
    free(dest_name);
    free(errmsg);
    return ret;
}

int oci_container_filesystem_usage(const im_container_fs_usage_request *request, imagetool_fs_info **fs_usage)
{
    int ret = 0;
    char *output = NULL;
    parser_error err = NULL;

    if (request == NULL || fs_usage == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    // TODO call storage container fs interface
    // ret = isula_container_fs_usage(request->name_id, &output);
    if (ret != 0) {
        ERROR("Failed to inspect container filesystem info");
        goto out;
    }

    *fs_usage = imagetool_fs_info_parse_data(output, NULL, &err);
    if (*fs_usage == NULL) {
        ERROR("Failed to parse output json: %s", err);
        isulad_set_error_message("Failed to parse output json:%s", err);
        ret = -1;
    }

out:
    free(output);
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

int oci_get_storage_status(im_storage_status_response **response)
{
    int ret = -1;

    if (response == NULL) {
        ERROR("Invalid input arguments");
        return ret;
    }

    *response = (im_storage_status_response *)util_common_calloc_s(sizeof(im_storage_status_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return ret;
    }

    // TODO call storage image status interface
    //ret = isula_do_storage_status(*response);
    if (ret != 0) {
        ERROR("Get get storage status failed");
        ret = -1;
        goto err_out;
    }

    return 0;
err_out:
    free_im_storage_status_response(*response);
    *response = NULL;
    return ret;
}

int oci_get_storage_metadata(char *id, im_storage_metadata_response **response)
{
    int ret = -1;

    if (response == NULL || id == NULL) {
        ERROR("Invalid input arguments");
        return ret;
    }

    *response = (im_storage_metadata_response *)util_common_calloc_s(sizeof(im_storage_metadata_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return ret;
    }

    // TODO call storage metadata status interface
    //ret = isula_do_storage_metadata(id, *response);
    if (ret != 0) {
        ERROR("Get get storage metadata failed");
        ret = -1;
        goto err_out;
    }

    return 0;
err_out:
    free_im_storage_metadata_response(*response);
    *response = NULL;
    return ret;
}

int oci_load_image(const im_load_request *request)
{
    int ret = 0;

    if (request == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    // TODO call storage metadata load interface
    //ret = isula_image_load(request->file, request->tag, &refs);
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

    // TODO call storage export load interface
    //ret = isula_container_export(request->name_id, request->file, 0, 0, 0);
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

static inline void cleanup_container_rootfs(const char *name_id, bool mounted)
{
    // TODO call storage umount interface
    //if (mounted && isula_rootfs_umount(name_id, true) != 0) {
    //    WARN("Remove rootfs: %s failed", name_id);
    //}

    // TODO call storage rootfs rm interface
    //if (isula_rootfs_remove(name_id) != 0) {
    //    WARN("Remove rootfs: %s failed", name_id);
    //}
}
