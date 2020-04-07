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
* Description: provide isula image operator definition
*******************************************************************************/
#include "isula_image.h"

#include <pthread.h>
#include <semaphore.h>

#include "isula_libutils/log.h"
#include "isula_image_connect.h"
#include "isula_image_pull.h"
#include "isula_rootfs_prepare.h"
#include "isula_rootfs_remove.h"
#include "isula_rootfs_mount.h"
#include "isula_rootfs_umount.h"
#include "isula_image_rmi.h"
#include "isula_image_tag.h"
#include "isula_import.h"
#include "isula_container_fs_usage.h"
#include "isula_image_fs_info.h"
#include "isula_storage_status.h"
#include "isula_image_load.h"
#include "isula_container_export.h"
#include "isula_login.h"
#include "isula_logout.h"
#include "isula_health_check.h"
#include "isula_images_list.h"
#include "isula_containers_list.h"
#include "isula_storage_metadata.h"

#include "containers_store.h"
#include "oci_images_store.h"

#include "isulad_config.h"
#include "utils.h"

#define IMAGE_NOT_KNOWN_ERR "image not known"

/*
 * start isula image grpc server
 * */
int isula_init(const struct im_configs *conf)
{
    int ret = -1;

    if (conf == NULL) {
        ERROR("Invalid image config");
        return ret;
    }

    /* init grpc client */
    ret = isula_image_ops_init();
    if (ret != 0) {
        ERROR("Init grpc client for isula image server failed");
        goto out;
    }

    ret = oci_image_store_init();
out:
    return ret;
}

int isula_pull_rf(const im_pull_request *request, im_pull_response **response)
{
    return isula_pull_image(request, response);
}

int isula_prepare_rf(const im_prepare_request *request, char **real_rootfs)
{
    if (request == NULL) {
        ERROR("Bim is NULL");
        return -1;
    }

    return isula_rootfs_prepare_and_get_image_conf(request->container_id, request->image_name, request->storage_opt,
                                                   real_rootfs, NULL);
}

int isula_merge_conf_rf(const host_config *host_spec, container_config *container_spec,
                        const im_prepare_request *request, char **real_rootfs)
{
    oci_image_spec *image = NULL;
    int ret = -1;

    if (request == NULL) {
        ERROR("Bim is NULL");
        return -1;
    }

    ret = isula_rootfs_prepare_and_get_image_conf(request->container_id, request->image_name, host_spec->storage_opt,
                                                  real_rootfs, &image);
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

int isula_delete_rf(const im_delete_request *request)
{
    if (request == NULL) {
        ERROR("Request is NULL");
        return -1;
    }
    return isula_rootfs_remove(request->name_id);
}

int isula_mount_rf(const im_mount_request *request)
{
    if (request == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }
    return isula_rootfs_mount(request->name_id);
}

int isula_umount_rf(const im_umount_request *request)
{
    if (request == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    return isula_rootfs_umount(request->name_id, request->force);
}

int isula_rmi(const im_remove_request *request)
{
    int ret = -1;
    char *real_image_name = NULL;
    oci_image_t *image_info = NULL;
    char *errmsg = NULL;

    if (request == NULL || request->image.image == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    real_image_name = oci_resolve_image_name(request->image.image);
    if (real_image_name == NULL) {
        ERROR("Failed to resolve image name");
        goto out;
    }
    image_info = oci_images_store_get(real_image_name);
    if (image_info == NULL) {
        INFO("No such image exist %s", real_image_name);
        ret = 0;
        goto out;
    }
    oci_image_lock(image_info);

    ret = isula_image_rmi(real_image_name, request->force, &errmsg);
    if (ret != 0) {
        if (strstr(errmsg, IMAGE_NOT_KNOWN_ERR) != NULL) {
            DEBUG("Image %s may already removed", real_image_name);
            ret = 0;
            goto clean_memory;
        }
        isulad_set_error_message("Failed to remove image with error: %s", errmsg);
        ERROR("Failed to remove image '%s' with error: %s", real_image_name, errmsg);
        goto unlock;
    }

clean_memory:
    ret = remove_oci_image_from_memory(real_image_name);
    if (ret != 0) {
        ERROR("Failed to remove image %s from memory", real_image_name);
    }
unlock:
    oci_image_unlock(image_info);
out:
    oci_image_unref(image_info);
    free(real_image_name);
    free(errmsg);
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

int isula_tag(const im_tag_request *request)
{
    int ret = -1;
    char *src_name = NULL;
    char *dest_name = NULL;
    oci_image_t *image_info = NULL;
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

    image_info = oci_images_store_get(src_name);
    if (image_info == NULL) {
        INFO("No such image exist %s", src_name);
        ret = -1;
        goto out;
    }
    oci_image_lock(image_info);

    ret = isula_image_tag(src_name, dest_name, &errmsg);
    if (ret != 0) {
        isulad_set_error_message("Failed to tag image with error: %s", errmsg);
        ERROR("Failed to tag image '%s' to '%s' with error: %s", src_name, dest_name, errmsg);
        goto out;
    }

    ret = register_new_oci_image_into_memory(dest_name);
    if (ret != 0) {
        ERROR("Register image %s into store failed", dest_name);
        goto out;
    }

out:
    oci_image_unlock(image_info);
    oci_image_unref(image_info);
    free(src_name);
    free(dest_name);
    free(errmsg);
    return ret;
}

int isula_container_filesystem_usage(const im_container_fs_usage_request *request, imagetool_fs_info **fs_usage)
{
    int ret = 0;
    char *output = NULL;
    parser_error err = NULL;

    if (request == NULL || fs_usage == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    ret = isula_container_fs_usage(request->name_id, &output);
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

int isula_get_filesystem_info(im_fs_info_response **response)
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
    ret = isula_image_fs_info(*response);
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

int isula_get_storage_status(im_storage_status_response **response)
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

    ret = isula_do_storage_status(*response);
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

int isula_get_storage_metadata(char *id, im_storage_metadata_response **response)
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

    ret = isula_do_storage_metadata(id, *response);
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

int isual_load_image(const im_load_request *request)
{
    char **refs = NULL;
    int ret = 0;
    int ret2 = 0;
    size_t i = 0;

    if (request == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    ret = isula_image_load(request->file, request->tag, &refs);
    if (ret != 0) {
        ERROR("Failed to load image");
        goto out;
    }

out:
    // If some of images are loaded, registery it.
    for (i = 0; i < util_array_len((const char **)refs); i++) {
        ret2 = register_new_oci_image_into_memory(refs[i]);
        if (ret2 != 0) {
            ERROR("Failed to register new image %s to images store", refs[i]);
            ret = -1;
            break;
        }
    }

    util_free_array(refs);
    refs = NULL;
    return ret;
}

int isula_export_rf(const im_export_request *request)
{
    int ret = 0;

    if (request == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    ret = isula_container_export(request->name_id, request->file, 0, 0, 0);
    if (ret != 0) {
        ERROR("Failed to export container: %s", request->name_id);
    }

    return ret;
}

int isula_login(const im_login_request *request)
{
    int ret = 0;

    if (request == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    ret = isula_do_login(request->server, request->username, request->password);
    if (ret != 0) {
        ERROR("Login failed");
    }

    return ret;
}

int isula_logout(const im_logout_request *request)
{
    int ret = 0;

    if (request == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    ret = isula_do_logout(request->server);
    if (ret != 0) {
        ERROR("Logout failed");
    }

    return ret;
}

int isula_health_check(void)
{
    return isula_do_health_check();
}

int isula_sync_images(void)
{
    int ret = 0;
    size_t i = 0;
    im_list_request *im_request = NULL;
    imagetool_images_list *image_list = NULL;
    oci_image_t *oci_image = NULL;
    char *errmsg = NULL;

    im_request = (im_list_request *)util_common_calloc_s(sizeof(im_list_request));
    if (im_request == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ret = isula_list_images(im_request, &image_list);
    if (ret != 0) {
        ERROR("Get remote images list failed");
        goto out;
    }

    for (i = 0; i < image_list->images_len; i++) {
        oci_image = oci_images_store_get((image_list->images[i])->id);
        if (oci_image != NULL) {
            continue;
        }
        WARN("Cleanup surplus image: %s in remote", (image_list->images[i])->id);
        ret = isula_image_rmi((image_list->images[i])->id, true, &errmsg);
        if (ret != 0) {
            WARN("Remove image: %s failed: %s", (image_list->images[i])->id, errmsg);
        }
        free(errmsg);
        errmsg = NULL;
        oci_image_unref(oci_image);
    }

    ret = 0;
out:
    free_im_list_request(im_request);
    free_imagetool_images_list(image_list);
    return ret;
}

static inline void cleanup_container_rootfs(const char *name_id, bool mounted)
{
    if (mounted && isula_rootfs_umount(name_id, true) != 0) {
        WARN("Remove rootfs: %s failed", name_id);
    }

    if (isula_rootfs_remove(name_id) != 0) {
        WARN("Remove rootfs: %s failed", name_id);
    }
}

int isula_sync_containers(void)
{
    int ret = 0;
    size_t i = 0;
    json_map_string_bool *remote_containers_list = NULL;
    container_t *cont = NULL;

    ret = isula_list_containers(&remote_containers_list);
    if (ret != 0) {
        ERROR("Get remote containers list failed");
        goto out;
    }

    if (remote_containers_list == NULL) {
        goto out;
    }

    for (i = 0; i < remote_containers_list->len; i++) {
        cont = containers_store_get(remote_containers_list->keys[i]);
        // cannot found container in local map, then unmount and remove remote rootfs
        if (cont == NULL) {
            WARN("Cleanup surplus container: %s in remote", remote_containers_list->keys[i]);
            cleanup_container_rootfs(remote_containers_list->keys[i], remote_containers_list->values[i]);
            continue;
        }

        // local container is stopped, but remote container is mounted. So unmount it.
        if (!is_running(cont->state) && remote_containers_list->values[i]) {
            WARN("Unmount unstarted container: %s", remote_containers_list->keys[i]);
            ret = isula_rootfs_umount(remote_containers_list->keys[i], true);
            if (ret != 0) {
                WARN("Unmount rootfs: %s failed", remote_containers_list->keys[i]);
            }
        }
        container_unref(cont);
    }

    ret = 0;
out:
    free_json_map_string_bool(remote_containers_list);
    return ret;
}

