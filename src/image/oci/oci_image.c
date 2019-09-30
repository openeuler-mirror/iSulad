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
 * Description: provide image function definition
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <sys/utsname.h>
#include <ctype.h>

#include "log.h"
#include "utils.h"
#include "securec.h"
#include "oci_images_store.h"
#include "oci_image.h"
#include "oci_rootfs_prepare.h"
#include "oci_rootfs_mount.h"
#include "oci_rootfs_umount.h"
#include "oci_rootfs_remove.h"
#include "oci_config_merge.h"
#include "oci_container_fs_usage.h"
#include "oci_image_pull.h"
#include "specs_extend.h"

static int oci_image_prepare_rootfs(const char *image, const char *name, const json_map_string_string *storage_opt,
                                    rootfs_prepare_and_get_image_conf_response **response)
{
    int ret = 0;
    rootfs_prepare_request *request = NULL;

    if (image == NULL || name == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    request = util_common_calloc_s(sizeof(rootfs_prepare_request));
    if (request == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    request->image = util_strdup_s(image);
    request->name = util_strdup_s(name);
    request->id = util_strdup_s(name);
    if (map_to_key_value_string(storage_opt, &request->storage_opts, &request->storage_opts_len) != 0) {
        ret = -1;
        goto out;
    }

    ret = prepare_rootfs_and_get_image_conf(request, response);
    if (ret != 0) {
        ERROR("Failed to prepare rootfs for %s with image %s", name, image);
        ret = -1;
        goto out;
    }

out:
    free_rootfs_prepare_request(request);
    return ret;
}

static int oci_image_mount_rootfs(const char *name)
{
    int ret = 0;
    rootfs_mount_request *request = NULL;
    rootfs_mount_response *response = NULL;

    if (name == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    request = util_common_calloc_s(sizeof(rootfs_mount_request));
    if (request == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    request->name_id = util_strdup_s(name);

    ret = mount_rootfs(request, &response);
    if (ret != 0 || response == NULL) {
        ERROR("Failed to mount rootfs for %s", name);
        ret = -1;
        goto out;
    }

out:
    free_rootfs_mount_request(request);
    free_rootfs_mount_response(response);
    return ret;
}

static int oci_image_umount_rootfs(const char *name)
{
    int ret = 0;
    rootfs_umount_request *request = NULL;
    rootfs_umount_response *response = NULL;

    if (name == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    request = util_common_calloc_s(sizeof(rootfs_umount_request));
    if (request == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    request->name_id = util_strdup_s(name);

    ret = umount_rootfs(request, &response);
    if (ret != 0) {
        ERROR("Failed to umount rootfs for %s", name);
        ret = -1;
        goto out;
    }

out:
    free_rootfs_umount_request(request);
    free_rootfs_umount_response(response);
    return ret;
}

static int oci_image_remove_rootfs(const char *name)
{
    int ret = 0;
    rootfs_remove_request *request = NULL;
    rootfs_remove_response *response = NULL;

    if (name == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    request = util_common_calloc_s(sizeof(rootfs_remove_request));
    if (request == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    request->name_id = util_strdup_s(name);

    ret = remove_rootfs(request, &response);
    if (ret != 0) {
        ERROR("Failed to remove rootfs for %s", name);
        ret = -1;
        goto out;
    }

out:
    free_rootfs_remove_request(request);
    free_rootfs_remove_response(response);
    return ret;
}

static bool oci_image_exist(const char *image_name)
{
    bool ret = false;
    oci_image_t *image_info = NULL;

    image_info = oci_images_store_get(image_name);
    if (image_info != NULL) {
        ret = true;
        oci_image_unref(image_info);
    }

    return ret;
}

bool oci_detect(const char *image_name)
{
    if (image_name == NULL) {
        return false;
    }

    return oci_image_exist(image_name);
}

int oci_filesystem_usage(struct bim *bim, imagetool_fs_info **fs_usage)
{
    int ret = 0;
    imagetool_fs_info *container_fs_usage = NULL;

    if (bim == NULL || fs_usage == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    EVENT("Event: {Object: sysinfo, Type: inspecting}");

    if (!do_oci_container_fs_info(bim->container_id, &container_fs_usage)) {
        ERROR("Failed to inspect cotainer filesystem info");
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: sysinfo, Type: inspected}");

pack_response:
    *fs_usage = container_fs_usage;

    return ret;
}

int oci_prepare_and_get_conf_rf(struct bim *bim, const json_map_string_string *storage_opt,
                                rootfs_prepare_and_get_image_conf_response **response)
{
    return oci_image_prepare_rootfs(bim->image_name, bim->container_id, storage_opt, response);
}

int oci_prepare_rf(struct bim *bim, const json_map_string_string *storage_opt, char **real_rootfs)
{
    int ret = 0;
    rootfs_prepare_and_get_image_conf_response *response = NULL;

    if (bim == NULL || real_rootfs == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    ret = oci_image_prepare_rootfs(bim->image_name, bim->container_id, storage_opt, &response);
    if (ret == 0) {
        *real_rootfs = response->raw_response->mount_point;
        response->raw_response->mount_point = NULL;
    }
    free_rootfs_prepare_and_get_image_conf_response(response);
    return ret;
}

int oci_mount_rf(struct bim *bim)
{
    return oci_image_mount_rootfs(bim->container_id);
}

int oci_umount_rf(struct bim *bim)
{
    return oci_image_umount_rootfs(bim->container_id);
}

int oci_delete_rf(struct bim *bim)
{
    return oci_image_remove_rootfs(bim->container_id);
}

// normalize the unqualified image to be domain/repo/image...
char *oci_normalize_image_name(const char *name)
{
#define DEFAULT_TAG ":latest"
#define DEFAULT_HOSTNAME "docker.io/"
#define DEFAULT_REPO_PREFIX "library/"

    char temp[PATH_MAX] = { 0 };


    if (strstr(name, "/") == NULL) {
        if (sprintf_s(temp, sizeof(temp), "%s%s", DEFAULT_HOSTNAME, DEFAULT_REPO_PREFIX) < 0) {
            ERROR("sprint temp image name failed");
            return NULL;
        }
    }

    if (sprintf_s(temp + strlen(temp), sizeof(temp) - strlen(temp), "%s", name) < 0) {
        ERROR("sprint temp image name failed");
        return NULL;
    }

    if (util_tag_pos(name) == NULL) {
        if (sprintf_s(temp + strlen(temp), sizeof(temp) - strlen(temp), "%s", DEFAULT_TAG) < 0) {
            ERROR("sprint temp image name failed");
            return NULL;
        }
    }

    return util_strdup_s(temp);
}

char *oci_resolve_image_name(const char *name)
{
    if (util_valid_short_sha256_id(name) && oci_image_exist(name)) {
        return util_strdup_s(name);
    }

    return oci_normalize_image_name(name);
}

static int merge_oci_image_conf(const char *image_name, oci_runtime_spec *oci_spec,
                                container_custom_config *custom_spec)
{
    int ret = 0;
    oci_image_t *image_info = NULL;
    char *resolved_name = NULL;

    if (oci_spec == NULL || image_name == NULL) {
        ERROR("invalid NULL param");
        return -1;
    }

    resolved_name = oci_resolve_image_name(image_name);
    if (resolved_name == NULL) {
        ERROR("Resolve external config image name failed, image name is %s", image_name);
        ret = -1;
        goto out;
    }

    image_info = oci_images_store_get(resolved_name);
    if (image_info == NULL) {
        ERROR("Get image from image store failed, image name is %s", resolved_name);
        ret = -1;
        goto out;
    }

    ret = oci_image_merge_config(image_info->info, oci_spec, custom_spec);
    if (ret != 0) {
        ERROR("Failed to merge oci config for image %s", resolved_name);
        ret = -1;
        goto out;
    }

out:
    oci_image_unref(image_info);
    free(resolved_name);
    resolved_name = NULL;
    return ret;
}


int oci_merge_conf(oci_runtime_spec *oci_spec, const host_config *host_spec, container_custom_config *custom_spec,
                   struct bim *bim, char **real_rootfs)
{
    int ret = 0;
    int nret = 0;
    rootfs_prepare_and_get_image_conf_response *response = NULL;

    nret = oci_prepare_and_get_conf_rf(bim, host_spec->storage_opt, &response);
    if (nret != 0) {
        ret = nret;
        goto free_out;
    }

    nret = merge_oci_image_conf(bim->image_name, oci_spec, custom_spec);
    if (nret != 0) {
        ret = nret;
        goto free_out;
    }


    *real_rootfs = response->raw_response->mount_point;
    response->raw_response->mount_point = NULL;

free_out:
    free_rootfs_prepare_and_get_image_conf_response(response);
    return ret;
}

int oci_get_user_conf(const char *basefs, host_config *hc, const char *userstr, oci_runtime_spec_process_user *puser)
{
    if (basefs == NULL || puser == NULL) {
        ERROR("Empty basefs or puser");
        return -1;
    }
    return get_user(basefs, hc, userstr, puser);
}

static int dup_oci_image_info(const imagetool_image *src, imagetool_image **dest)
{
    int ret = -1;
    char *json = NULL;
    parser_error err = NULL;

    if (src == NULL) {
        *dest = NULL;
        return 0;
    }

    json = imagetool_image_generate_json(src, NULL, &err);
    if (json == NULL) {
        ERROR("Failed to generate json: %s", err);
        goto out;
    }
    *dest = imagetool_image_parse_data(json, NULL, &err);
    if (*dest == NULL) {
        ERROR("Failed to parse json: %s", err);
        goto out;
    }
    ret = 0;

out:
    free(err);
    free(json);
    return ret;
}

static int oci_list_all_images(imagetool_images_list *images_list)
{
    int ret = 0;
    size_t i = 0;
    oci_image_t **images_info = NULL;
    size_t images_num = 0;

    ret = oci_images_store_list(&images_info, &images_num);
    if (ret != 0) {
        ERROR("query all oci images info failed");
        return -1;
    }

    if (images_num == 0) {
        ret = 0;
        goto out;
    }

    if (images_num > (SIZE_MAX / sizeof(imagetool_image *))) {
        ERROR("Get too many images:%d", images_num);
        ret = -1;
        goto out;
    }

    images_list->images = util_common_calloc_s(images_num * sizeof(imagetool_image *));
    if (images_list->images == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < images_num; i++) {
        ret = dup_oci_image_info(images_info[i]->info, &images_list->images[i]);
        if (ret != 0) {
            ERROR("Failed to dup oci image %s info", images_info[i]->info->id);
            ret = -1;
            goto out;
        }
        oci_image_unref(images_info[i]);
        images_list->images_len++;
    }
out:
    if (ret != 0) {
        for (; i < images_num; i++) {
            oci_image_unref(images_info[i]);
        }
    }

    free(images_info);
    return ret;
}

static int oci_list_images_by_filter(const char *filter, imagetool_images_list *images_list)
{
    int ret = 0;
    char *tmp = NULL;
    oci_image_t *image_info = NULL;

    tmp = oci_resolve_image_name(filter);
    if (tmp == NULL) {
        ERROR("Failed to resolve image name");
        ret = -1;
        goto out;
    }

    image_info = oci_images_store_get(tmp);
    if (image_info == NULL) {
        ret = 0;
        goto out;
    }

    images_list->images = util_common_calloc_s(1 * sizeof(imagetool_image *));
    if (images_list->images == NULL) {
        oci_image_unref(image_info);
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ret = dup_oci_image_info(image_info->info, &images_list->images[0]);
    oci_image_unref(image_info);
    if (ret != 0) {
        ERROR("Failed to dup oci image %s info", tmp);
        ret = -1;
        goto out;
    }
    images_list->images_len++;

out:
    free(tmp);
    return ret;
}

int oci_list_images(im_list_request *request, imagetool_images_list **images)
{
    int ret = 0;
    char *filter = NULL;

    if (request != NULL && request->filter.image.image != NULL) {
        filter = request->filter.image.image;
    }

    *images = util_common_calloc_s(sizeof(imagetool_images_list));
    if (*images == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (filter != NULL) {
        ret = oci_list_images_by_filter(filter, *images);
    } else {
        ret = oci_list_all_images(*images);
    }

    if (ret != 0) {
        goto out;
    }

out:
    if (ret != 0) {
        free_imagetool_images_list(*images);
        *images = NULL;
    }
    return ret;
}

int oci_status_image(oci_image_status_request *request, oci_image_status_response **response)
{
    int ret = 0;
    imagetool_image_status *image = NULL;
    char *image_ref = NULL;
    oci_image_t *image_info = NULL;
    char *resolved_name = NULL;

    *response = util_common_calloc_s(sizeof(oci_image_status_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    image = util_common_calloc_s(sizeof(imagetool_image_status));
    if (image == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto pack_response;
    }
    (*response)->image_info = image;

    image_ref = request->image.image;
    if (image_ref == NULL) {
        ERROR("Inspect image requires image ref");
        lcrd_set_error_message("Inspect image requires image ref");
        ret = -1;
        goto pack_response;
    }

    resolved_name = oci_resolve_image_name(image_ref);
    if (resolved_name == NULL) {
        ERROR("Failed to reslove image name %s", image_ref);
        lcrd_set_error_message("Failed to reslove image name %s", image_ref);
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: statusing image}", resolved_name);

    image_info = oci_images_store_get(resolved_name);
    if (image_info == NULL) {
        ERROR("No such image:%s", resolved_name);
        lcrd_set_error_message("No such image:%s", resolved_name);
        ret = -1;
        goto pack_response;
    }

    ret = dup_oci_image_info(image_info->info, &((*response)->image_info->image));
    oci_image_unref(image_info);
    if (ret != 0) {
        ERROR("Failed to dup image info:%s", resolved_name);
        lcrd_set_error_message("Failed to dup image info:%s", resolved_name);
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: statused image}", resolved_name);

pack_response:
    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }
    free(resolved_name);

    return ret;
}

int oci_inspect_image(struct bim *bim, char **inspected_json)
{
    int ret = 0;
    oci_image_status_request request;
    oci_image_status_response *response = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;

    if (bim == NULL || inspected_json == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    ret = memset_s(&request, sizeof(oci_image_status_request), 0x00, sizeof(oci_image_status_request));
    if (ret != EOK) {
        ERROR("Failed to set memory");
        return -1;
    }
    request.image.image = bim->image_name;

    ret = oci_status_image(&request, &response);
    if (ret != 0) {
        goto out;
    }

    *inspected_json = imagetool_image_status_generate_json(response->image_info, &ctx, &err);
    if (*inspected_json == NULL) {
        ERROR("Failed to generate image status request json:%s", err);
        ret = -1;
        goto out;
    }

out:
    free(err);
    free_oci_image_status_response(response);
    return ret;
}

static int im_request_to_oci_request(const im_pull_request *req, image_pull_request **oci_req)
{
    *oci_req = util_common_calloc_s(sizeof(image_pull_request));
    if (*oci_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    (*oci_req)->image.image = util_strdup_s(req->image);

    if (req->username != NULL) {
        (*oci_req)->auth.username = util_strdup_s(req->username);
    }
    if (req->password != NULL) {
        (*oci_req)->auth.password = util_strdup_s(req->password);
    }
    if (req->auth != NULL) {
        (*oci_req)->auth.auth = util_strdup_s(req->auth);
    }
    if (req->server_address != NULL) {
        (*oci_req)->auth.server_address = util_strdup_s(req->server_address);
    }
    if (req->identity_token != NULL) {
        (*oci_req)->auth.identity_token = util_strdup_s(req->identity_token);
    }
    if (req->registry_token != NULL) {
        (*oci_req)->auth.registry_token = util_strdup_s(req->registry_token);
    }

    return 0;
}

int oci_pull_image(const im_pull_request *request, im_pull_response **response)
{
    int ret = -1;
    image_pull_response *oci_resp = NULL;
    image_pull_request *oci_req = NULL;

    ret = im_request_to_oci_request(request, &oci_req);
    if (ret != 0) {
        goto free_out;
    }

    ret = pull_image(oci_req, &oci_resp);
    if (ret != 0) {
        ERROR("Pull image failed: %s", oci_resp->errmsg);
        goto free_out;
    }
    *response = util_common_calloc_s(sizeof(im_pull_response));
    if (*response == NULL) {
        ret = -1;
        ERROR("Out of memory");
        goto free_out;
    }
    (*response)->image_ref = util_strdup_s(oci_resp->image_ref);
    (*response)->errmsg = util_strdup_s(oci_resp->errmsg);

free_out:
    free_image_pull_request(oci_req);
    free_image_pull_response(oci_resp);
    return ret;
}

int oci_init(const char *rootpath)
{
    int ret = 0;

    ret = oci_images_store_init();
    if (ret != 0) {
        ERROR("Failed to init oci images store");
        goto out;
    }

    ret = image_name_id_init();
    if (ret != 0) {
        ERROR("Failed to init oci name id store");
        goto out;
    }

    ret = load_all_oci_images();

out:
    return ret;
}
