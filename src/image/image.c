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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <sys/utsname.h>
#include <ctype.h>

#include "securec.h"
#include "image.h"
#include "liblcrd.h"
#include "log.h"
#include "utils.h"

#include "ext_image.h"

#ifdef ENABLE_OCI_IMAGE
#include "oci_image.h"
#include "oci_image_status.h"
#include "oci_image_load.h"
#include "oci_login.h"
#include "oci_logout.h"
#endif

#ifdef ENABLE_EMBEDDED_IMAGE
#include "embedded_image.h"
#include "db_all.h"

/* embedded */
static const struct bim_ops g_embedded_ops = {
    .init = embedded_init,
    .detect = embedded_detect,

    .prepare_rf = embedded_prepare_rf,
    .mount_rf = embedded_mount_rf,
    .umount_rf = embedded_umount_rf,
    .delete_rf = embedded_delete_rf,

    .merge_conf = embedded_merge_conf,
    .get_user_conf = embedded_get_user_conf,

    .list_ims = embedded_list_images,
    .rm_image = embedded_remove_image,
    .inspect_image = embedded_inspect_image,
    .resolve_image_name = embedded_resolve_image_name,
    .filesystem_usage = embedded_filesystem_usage,
    .load_image = embedded_load_image,
    .pull_image = NULL,
};
#endif

#ifdef ENABLE_OCI_IMAGE
/* oci */
static const struct bim_ops g_oci_ops = {
    .init = oci_init,
    .detect = oci_detect,

    .prepare_rf = oci_prepare_rf,
    .mount_rf = oci_mount_rf,
    .umount_rf = oci_umount_rf,
    .delete_rf = oci_delete_rf,

    .merge_conf = oci_merge_conf,
    .get_user_conf = oci_get_user_conf,

    .list_ims = oci_list_images,
    .rm_image = oci_remove_image,
    .inspect_image = oci_inspect_image,
    .resolve_image_name = oci_resolve_image_name,
    .filesystem_usage = oci_filesystem_usage,
    .load_image = oci_load_image,
    .pull_image = oci_pull_image,
    .login = oci_login,
    .logout = oci_logout,
};
#endif

/* external */
static const struct bim_ops g_ext_ops = {
    .init = ext_init,
    .detect = ext_detect,

    .prepare_rf = ext_prepare_rf,
    .mount_rf = ext_mount_rf,
    .umount_rf = ext_umount_rf,
    .delete_rf = ext_delete_rf,

    .merge_conf = ext_merge_conf,
    .get_user_conf = ext_get_user_conf,

    .list_ims = ext_list_images,
    .rm_image = ext_remove_image,
    .inspect_image = ext_inspect_image,
    .resolve_image_name = ext_resolve_image_name,
    .filesystem_usage = ext_filesystem_usage,
    .load_image = ext_load_image,
    .pull_image = NULL,
    .login = ext_login,
    .logout = ext_logout,
};

static const struct bim_type g_bims[] = {
#ifdef ENABLE_OCI_IMAGE
    {
        .image_type = IMAGE_TYPE_OCI,
        .ops = &g_oci_ops,
    },
#endif
    { .image_type = IMAGE_TYPE_EXTERNAL, .ops = &g_ext_ops },
#ifdef ENABLE_EMBEDDED_IMAGE
    { .image_type = IMAGE_TYPE_EMBEDDED, .ops = &g_embedded_ops },
#endif
};

static const size_t g_numbims = sizeof(g_bims) / sizeof(struct bim_type);

static const struct bim_type *bim_query(const char *image_name)
{
    size_t i;
    char *temp = NULL;

    for (i = 0; i < g_numbims; i++) {
        temp = g_bims[i].ops->resolve_image_name(image_name);
        if (temp == NULL) {
            lcrd_append_error_message("Failed to resovle image name%s", image_name);
            return NULL;
        }
        int r = g_bims[i].ops->detect(temp);

        free(temp);
        temp = NULL;

        if (r != 0) {
            break;
        }
    }

    if (i == g_numbims) {
        return NULL;
    }
    return &g_bims[i];
}

static const struct bim_type *get_bim_by_type(const char *image_type)
{
    size_t i;

    for (i = 0; i < g_numbims; i++) {
        if (strcmp(g_bims[i].image_type, image_type) == 0) {
            return &g_bims[i];
        }
    }

    ERROR("Backing store %s unknown but not caught earlier\n", image_type);
    return NULL;
}

static void bim_put(struct bim *bim)
{
    if (bim == NULL) {
        return;
    }

    free(bim->image_name);
    bim->image_name = NULL;
    free(bim->ext_config_image);
    bim->ext_config_image = NULL;
    free(bim->container_id);
    bim->container_id = NULL;
    free(bim);
}

static struct bim *bim_get(const char *image_type, const char *image_name, const char *ext_config_image,
                           const char *container_id)
{
    struct bim *bim = NULL;
    const struct bim_type *q = NULL;

    if (image_type == NULL) {
        return NULL;
    }

    q = get_bim_by_type(image_type);
    if (q == NULL) {
        return NULL;
    }

    bim = util_common_calloc_s(sizeof(struct bim));
    if (bim == NULL) {
        return NULL;
    }

    bim->ops = q->ops;
    bim->type = q->image_type;

    if (image_name != NULL) {
        bim->image_name = bim->ops->resolve_image_name(image_name);
        if (bim->image_name == NULL) {
            lcrd_append_error_message("Failed to resovle image name%s", bim->image_name);
            bim_put(bim);
            return NULL;
        }
    }
    if (ext_config_image != NULL) {
        bim->ext_config_image = util_strdup_s(ext_config_image);
        if (bim->ext_config_image == NULL) {
            lcrd_append_error_message("Failed to strdup external config image %s", bim->ext_config_image);
            bim_put(bim);
            return NULL;
        }
    }
    if (container_id != NULL) {
        bim->container_id = util_strdup_s(container_id);
    }
    return bim;
}

int im_get_container_filesystem_usage(const char *image_type, const char *id, imagetool_fs_info **fs_usage)
{
    int ret = 0;
    imagetool_fs_info *filesystemusage = NULL;
    const struct bim_type *q = NULL;
    struct bim *bim = NULL;

    if (image_type == NULL || id == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    q = get_bim_by_type(image_type);
    if (q == NULL) {
        ret = -1;
        goto out;
    }

    bim = util_common_calloc_s(sizeof(struct bim));
    if (bim == NULL) {
        ret = -1;
        goto out;
    }

    bim->ops = q->ops;
    bim->type = q->image_type;

    if (id != NULL) {
        bim->container_id = util_strdup_s(id);
    }

    ret = bim->ops->filesystem_usage(bim, &filesystemusage);
    if (ret != 0) {
        ERROR("Failed to get filesystem usage for container %s", id);
        ret = -1;
        goto out;
    }

    *fs_usage = filesystemusage;

out:
    bim_put(bim);
    return ret;
}

int im_remove_container_rootfs(const char *image_type, const char *container_id)
{
    int ret = 0;
    struct bim *bim = NULL;

    if (container_id == NULL || image_type == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    bim = bim_get(image_type, NULL, NULL, container_id);
    if (bim == NULL) {
        ERROR("Failed to init bim for container %s", container_id);
        ret = -1;
        goto out;
    }

    ret = bim->ops->delete_rf(bim);
    if (ret != 0) {
        ERROR("Failed to delete rootfs for container %s", container_id);
        ret = -1;
        goto out;
    }

out:
    bim_put(bim);
    return ret;
}

int im_umount_container_rootfs(const char *image_type, const char *image_name, const char *container_id)
{
    int ret = 0;
    struct bim *bim = NULL;

    if (container_id == NULL || image_type == NULL || image_name == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    bim = bim_get(image_type, image_name, NULL, container_id);
    if (bim == NULL) {
        ERROR("Failed to init bim for container %s", container_id);
        ret = -1;
        goto out;
    }

    ret = bim->ops->umount_rf(bim);
    if (ret != 0) {
        ERROR("Failed to umount rootfs for container %s", container_id);
        ret = -1;
        goto out;
    }

out:
    bim_put(bim);
    return ret;
}

int im_mount_container_rootfs(const char *image_type, const char *image_name, const char *container_id)
{
    int ret = 0;
    struct bim *bim = NULL;

    if (image_name == NULL || container_id == NULL || image_type == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    bim = bim_get(image_type, image_name, NULL, container_id);
    if (bim == NULL) {
        ERROR("Failed to init bim for container %s", container_id);
        ret = -1;
        goto out;
    }

    ret = bim->ops->mount_rf(bim);
    if (ret != 0) {
        ERROR("Failed to mount rootfs for container %s", container_id);
        ret = -1;
        goto out;
    }

out:
    bim_put(bim);
    return ret;
}

char *im_get_image_type(const char *image, const char *external_rootfs)
{
    const char *image_name = NULL;
    const struct bim_type *bim_type = NULL;

    image_name = (external_rootfs != NULL) ? external_rootfs : image;
    if (image_name == NULL) {
        ERROR("Should specify the image name or external rootfs");
        return NULL;
    }

    bim_type = bim_query(image_name);
    if (bim_type == NULL) {
        ERROR("Failed to query type of image %s", image_name);
        lcrd_set_error_message("No such image:%s", image_name);
        return NULL;
    }

    return util_strdup_s(bim_type->image_type);
}

bool im_config_image_exist(const char *image_name)
{
    const struct bim_type *bim_type = NULL;

    bim_type = bim_query(image_name);
    if (bim_type == NULL) {
        ERROR("Config image %s not exist", image_name);
        lcrd_set_error_message("Image %s not exist", image_name);
        return false;
    }

    return true;
}

int im_merge_image_config(const char *id, const char *image_type, const char *image_name,
                          const char *ext_config_image, oci_runtime_spec *oci_spec,
                          host_config *host_spec, container_custom_config *custom_spec,
                          char **real_rootfs)
{
    int ret = 0;
    struct bim *bim = NULL;

    if (real_rootfs == NULL || oci_spec == NULL || image_type == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    bim = bim_get(image_type, image_name, ext_config_image, id);
    if (bim == NULL) {
        ERROR("Failed to init bim of image %s", image_name);
        ret = -1;
        goto out;
    }

    ret = bim->ops->merge_conf(oci_spec, host_spec, custom_spec, bim, real_rootfs);
    if (ret != 0) {
        ERROR("Failed to merge image %s config, config image is %s", image_name, ext_config_image);
        ret = -1;
        goto out;
    }
    INFO("Use real rootfs: %s with type: %s", *real_rootfs, image_type);

out:
    bim_put(bim);
    return ret;
}

int im_get_user_conf(const char *image_type, const char *basefs, host_config *hc, const char *userstr,
                     oci_runtime_spec_process_user *puser)
{
    int ret = 0;
    struct bim *bim = NULL;

    if (basefs == NULL || hc == NULL || image_type == NULL || puser == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    bim = bim_get(image_type, NULL, NULL, NULL);
    if (bim == NULL) {
        ERROR("Failed to init bim for image type: %s", image_type);
        ret = -1;
        goto out;
    }

    ret = bim->ops->get_user_conf(basefs, hc, userstr, puser);
    if (ret != 0) {
        ERROR("Failed to get user config");
        ret = -1;
        goto out;
    }

out:
    bim_put(bim);
    return ret;
}

static int append_images_to_response(im_list_response *response, imagetool_images_list *images_in)
{
    int ret = 0;
    size_t images_num = 0;
    size_t old_num = 0;
    imagetool_image **tmp = NULL;
    size_t i = 0;
    size_t new_size = 0;
    size_t old_size = 0;

    if (images_in == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    if (response->images == NULL) {
        response->images = util_common_calloc_s(sizeof(imagetool_images_list));
        if (response->images == NULL) {
            ERROR("Memeory out");
            ret = -1;
            goto out;
        }
    }

    images_num = images_in->images_len;

    // no images need to append
    if (images_num == 0) {
        goto out;
    }
    if (images_num > SIZE_MAX / sizeof(imagetool_image *) - response->images->images_len) {
        ERROR("Too many images to append!");
        ret = -1;
        goto out;
    }

    old_num = response->images->images_len;

    new_size = (old_num + images_num) * sizeof(imagetool_image *);
    old_size = old_num * sizeof(imagetool_image *);
    ret = mem_realloc((void **)(&tmp), new_size, response->images->images, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for append images");
        ret = -1;
        goto out;
    }
    response->images->images = tmp;
    for (i = 0; i < images_num; i++) {
        response->images->images[old_num + i] = images_in->images[i];
        images_in->images[i] = NULL;
        images_in->images_len--;
        response->images->images_len++;
    }

out:
    return ret;
}

int im_list_images(im_list_request *request, im_list_response **response)
{
    char *filter = NULL;
    size_t i;
    imagetool_images_list *images_tmp = NULL;

    filter = request->filter.image.image;

    *response = util_common_calloc_s(sizeof(im_list_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    EVENT("Event: {Object: list images, Type: listing, Filter: %s}", filter ? filter : "");

    for (i = 0; i < g_numbims; i++) {
        int ret = g_bims[i].ops->list_ims(request, &images_tmp);
        if (ret != 0) {
            ERROR("Failed to list all images with type:%s", g_bims[i].image_type);
            continue;
        }
        ret = append_images_to_response(*response, images_tmp);
        if (ret != 0) {
            ERROR("Failed to append images with type:%s", g_bims[i].image_type);
        }
        free_imagetool_images_list(images_tmp);
        images_tmp = NULL;
    }

    EVENT("Event: {Object: list images, Type: listed, Filter: %s}", filter ? filter : "");

    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }

    return 0;
}

void free_im_list_request(im_list_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->filter.image.image);
    ptr->filter.image.image = NULL;

    free(ptr);
}

void free_im_list_response(im_list_response *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free_imagetool_images_list(ptr->images);
    ptr->images = NULL;
    free(ptr->errmsg);
    ptr->errmsg = NULL;

    free(ptr);
}

static bool check_im_pull_args(const im_pull_request *req, im_pull_response * const *resp)
{
    if (req == NULL || resp == NULL) {
        ERROR("Request or response is NULL");
        return false;
    }
    if (req->image == NULL) {
        ERROR("Empty image required");
        lcrd_set_error_message("Empty image required");
        return false;
    }
    return true;
}

int im_pull_image(const im_pull_request *request, im_pull_response **response)
{
    int ret = -1;
    struct bim *bim = NULL;

    if (!check_im_pull_args(request, response)) {
        return ret;
    }

    bim = bim_get(request->type, NULL, NULL, NULL);
    if (bim == NULL) {
        ERROR("Failed to init bim, image type: %s", request->type);
        goto out;
    }

    if (bim->ops->pull_image == NULL) {
        WARN("Unimplements pull image in %s", bim->type);
        ret = 0;
        goto out;
    }

    ret = bim->ops->pull_image(request, response);
    if (ret != 0) {
        ERROR("Pull image %s failed", request->image);
        ret = -1;
        goto out;
    }

out:
    bim_put(bim);
    return ret;
}

void free_im_pull_request(im_pull_request *req)
{
    if (req == NULL) {
        return;
    }
    free(req->type);
    req->type = NULL;
    free(req->image);
    req->image = NULL;
    free_sensitive_string(req->username);
    req->username = NULL;
    free_sensitive_string(req->password);
    req->password = NULL;
    free_sensitive_string(req->auth);
    req->auth = NULL;
    free_sensitive_string(req->server_address);
    req->server_address = NULL;
    free_sensitive_string(req->registry_token);
    req->registry_token = NULL;
    free_sensitive_string(req->identity_token);
    req->identity_token = NULL;
    free(req);
}

void free_im_pull_response(im_pull_response *resp)
{
    if (resp == NULL) {
        return;
    }
    free(resp->image_ref);
    resp->image_ref = NULL;
    free(resp->errmsg);
    resp->errmsg = NULL;
    free(resp);
}

int im_load_image(im_load_request *request, im_load_response **response)
{
    int ret = -1;
    struct bim *bim = NULL;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(im_load_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (request->file == NULL) {
        ERROR("Load image requires image tarball file path");
        lcrd_set_error_message("Load image requires image tarball file path");
        goto pack_response;
    }

    if (request->type == NULL) {
        ERROR("Missing image type");
        lcrd_set_error_message("Missing image type");
        goto pack_response;
    }

    bim = bim_get(request->type, NULL, NULL, NULL);
    if (bim == NULL) {
        ERROR("Failed to init bim, image type:%s", request->type);
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: loading}", request->file);

    ret = bim->ops->load_image(request);
    if (ret != 0) {
        ERROR("Failed to load image from %s with tag %s and type %s", request->file, request->tag, request->type);
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: loaded}", request->file);

pack_response:
    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }

    bim_put(bim);
    return ret;
}

void free_im_load_request(im_load_request *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free(ptr->file);
    ptr->file = NULL;

    free(ptr->tag);
    ptr->file = NULL;

    free(ptr->type);
    ptr->type = NULL;

    free(ptr);
}

void free_im_load_response(im_load_response *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free(ptr->errmsg);
    ptr->errmsg = NULL;

    free(ptr);
}

int im_login(im_login_request *request, im_login_response **response)
{
    int ret = -1;
    struct bim *bim = NULL;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(im_login_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (request->server == NULL) {
        ERROR("Login requires server address");
        lcrd_set_error_message("Login requires server address");
        goto pack_response;
    }

    if (request->type == NULL) {
        ERROR("Login requires image type");
        lcrd_set_error_message("Login requires image type");
        goto pack_response;
    }

    if (request->username == NULL || request->password == NULL) {
        ERROR("Missing username or password");
        lcrd_set_error_message("Missing username or password");
        goto pack_response;
    }

    bim = bim_get(request->type, NULL, NULL, NULL);
    if (bim == NULL) {
        ERROR("Failed to init bim, image type:%s", request->type);
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: logining}", request->server);

    ret = bim->ops->login(request);
    if (ret != 0) {
        ERROR("Failed to login %s", request->server);
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: logined}", request->server);

pack_response:
    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }

    bim_put(bim);
    return ret;
}

void free_im_login_request(im_login_request *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free_sensitive_string(ptr->username);
    ptr->username = NULL;

    free_sensitive_string(ptr->password);
    ptr->password = NULL;

    free(ptr->type);
    ptr->type = NULL;

    free_sensitive_string(ptr->server);
    ptr->server = NULL;

    free(ptr);
}

void free_im_login_response(im_login_response *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free(ptr->errmsg);
    ptr->errmsg = NULL;

    free(ptr);
}

int im_logout(im_logout_request *request, im_logout_response **response)
{
    int ret = -1;
    struct bim *bim = NULL;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(im_logout_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (request->server == NULL) {
        ERROR("Logout requires server address");
        lcrd_set_error_message("Logout requires server address");
        goto pack_response;
    }

    if (request->type == NULL) {
        ERROR("Logout requires image type");
        lcrd_set_error_message("Logout requires image type");
        goto pack_response;
    }

    bim = bim_get(request->type, NULL, NULL, NULL);
    if (bim == NULL) {
        ERROR("Failed to init bim, image type:%s", request->type);
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: logouting}", request->server);

    ret = bim->ops->logout(request);
    if (ret != 0) {
        ERROR("Failed to logout %s", request->server);
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: logouted}", request->server);

pack_response:
    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }

    bim_put(bim);
    return ret;
}

void free_im_logout_request(im_logout_request *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free(ptr->type);
    ptr->type = NULL;

    free(ptr->server);
    ptr->server = NULL;

    free(ptr);
}

void free_im_logout_response(im_logout_response *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free(ptr->errmsg);
    ptr->errmsg = NULL;

    free(ptr);
}

int im_rm_image(im_remove_request *request, im_remove_response **response)
{
    int ret = -1;
    char *image_ref = NULL;
    const struct bim_type *bim_type = NULL;
    struct bim *bim = NULL;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(im_remove_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (request->image.image == NULL) {
        ERROR("remove image requires image ref");
        lcrd_set_error_message("remove image requires image ref");
        goto pack_response;
    }

    image_ref = util_strdup_s(request->image.image);

    EVENT("Event: {Object: %s, Type: removing}", image_ref);

    bim_type = bim_query(image_ref);
    if (bim_type == NULL) {
        ERROR("No such image:%s", image_ref);
        lcrd_set_error_message("No such image:%s", image_ref);
        goto pack_response;
    }

    bim = bim_get(bim_type->image_type, image_ref, NULL, NULL);
    if (bim == NULL) {
        ERROR("Failed to init bim for image %s", image_ref);
        goto pack_response;
    }

    ret = bim->ops->rm_image(request);
    if (ret != 0) {
        ERROR("Failed to remove image %s", image_ref);
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: removed}", image_ref);

pack_response:
    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }
    free(image_ref);
    bim_put(bim);
    return ret;
}

void free_im_remove_request(im_remove_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->image.image);
    ptr->image.image = NULL;

    free(ptr);
}

void free_im_remove_response(im_remove_response *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free(ptr->errmsg);
    ptr->errmsg = NULL;

    free(ptr);
}

int im_inspect_image(const im_inspect_request *request, im_inspect_response **response)
{
    int ret = 0;
    char *image_ref = NULL;
    char *inspected_json = NULL;
    const struct bim_type *bim_type = NULL;
    struct bim *bim = NULL;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(im_inspect_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (request->image.image == NULL) {
        ERROR("inspect image requires image ref");
        lcrd_set_error_message("inspect image requires image ref");
        ret = -1;
        goto pack_response;
    }

    image_ref = util_strdup_s(request->image.image);

    EVENT("Event: {Object: %s, Type: inspecting}", image_ref);

    bim_type = bim_query(image_ref);
    if (bim_type == NULL) {
        ERROR("No such image:%s", image_ref);
        lcrd_set_error_message("No such image:%s", image_ref);
        ret = -1;
        goto pack_response;
    }

    bim = bim_get(bim_type->image_type, image_ref, NULL, NULL);
    if (bim == NULL) {
        ERROR("Failed to init bim for image %s", image_ref);
        ret = -1;
        goto pack_response;
    }

    ret = bim->ops->inspect_image(bim, &inspected_json);
    if (ret != 0) {
        ERROR("Failed to inspect image %s", image_ref);
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: inspected}", image_ref);

pack_response:
    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }
    if (inspected_json != NULL) {
        (*response)->im_inspect_json = util_strdup_s(inspected_json);
    }
    free(image_ref);
    free(inspected_json);
    bim_put(bim);
    return ret;
}

void free_im_inspect_request(im_inspect_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->image.image);
    ptr->image.image = NULL;

    free(ptr);
}

void free_im_inspect_response(im_inspect_response *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free(ptr->im_inspect_json);
    ptr->im_inspect_json = NULL;

    free(ptr->errmsg);
    ptr->errmsg = NULL;

    free(ptr);
}

static int bims_init(const char *rootpath)
{
    int ret = 0;
    size_t i;

    for (i = 0; i < g_numbims; i++) {
        ret = g_bims[i].ops->init(rootpath);
        if (ret != 0) {
            ERROR("Failed to init bim %s", g_bims[i].image_type);
            break;
        }
    }

    return ret;
}

int image_module_init(const char *rootpath)
{
    return bims_init(rootpath);
}

int map_to_key_value_string(const json_map_string_string *map, char ***array, size_t *array_len)
{
    char **strings = NULL;
    size_t strings_len = 0;
    size_t i;
    int ret;

    if (map == NULL) {
        return 0;
    }
    for (i = 0; i < map->len; i++) {
        char *str = NULL;
        size_t len;
        if (strlen(map->keys[i]) > (SIZE_MAX - strlen(map->values[i])) - 2) {
            ERROR("Invalid keys/values");
            goto cleanup;
        }
        len = strlen(map->keys[i]) + strlen(map->values[i]) + 2;
        str = util_common_calloc_s(len);
        if (str == NULL) {
            ERROR("Out of memory");
            goto cleanup;
        }
        ret = sprintf_s(str, len, "%s=%s", map->keys[i], map->values[i]);
        if (ret < 0) {
            ERROR("Failed to print string");
            free(str);
            goto cleanup;
        }
        ret = util_array_append(&strings, str);
        free(str);
        if (ret != 0) {
            ERROR("Failed to append array");
            goto cleanup;
        }
        strings_len++;
    }
    *array = strings;
    *array_len = strings_len;
    return 0;

cleanup:
    util_free_array(strings);
    return -1;
}

