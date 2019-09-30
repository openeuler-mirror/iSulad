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
 * Author: weiwei
 * Create: 2017-11-22
 * Description: provide image function definition
 ******************************************************************************/
#ifndef __IMAGE_H
#define __IMAGE_H

#include <stdint.h>

#include "oci_image_manifest.h"
#include "oci_image_index.h"
#include "oci_image_spec.h"
#include "oci_runtime_spec.h"
#include "container_custom_config.h"
#include "host_config.h"
#include "liblcrd.h"

#ifdef ENABLE_OCI_IMAGE
#include "oci_image_type.h"
#endif

#include "imagetool_images_list.h"
#include "imagetool_fs_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IMAGE_TYPE_OCI "oci"
#ifdef ENABLE_EMBEDDED_IMAGE
#define IMAGE_TYPE_EMBEDDED "embedded"
#endif
#define IMAGE_TYPE_EXTERNAL "external"

#ifndef ENABLE_OCI_IMAGE
typedef struct {
    char *image;
} image_spec;

typedef struct {
    image_spec image;
} image_filter;
#endif

typedef struct {
    image_filter filter;
    bool check;
} im_list_request;

typedef struct {
    imagetool_images_list *images;
    char *errmsg;
} im_list_response;

typedef struct {
    // Spec of the image.
    image_spec image;

    bool force;
} im_remove_request;

typedef struct {
    char *errmsg;
} im_remove_response;

typedef struct {
    // Spec of the image.
    image_spec image;
} im_inspect_request;

typedef struct {
    char *im_inspect_json;
    char *errmsg;
} im_inspect_response;

typedef struct {
    char *file;
    char *tag;
    char *type;
} im_load_request;

typedef struct {
    char *errmsg;
} im_load_response;

typedef struct {
    char *type;
    char *image;

    /* auth configs */
    char *username;
    char *password;
    char *auth;
    char *server_address;
    char *identity_token;
    char *registry_token;
} im_pull_request;

typedef struct {
    char *image_ref;
    char *errmsg;
} im_pull_response;

typedef struct {
    char *server;
    char *username;
    char *password;
    char *type;
} im_login_request;

typedef struct {
    char *errmsg;
} im_login_response;

typedef struct {
    char *server;
    char *type;
} im_logout_request;

typedef struct {
    char *errmsg;
} im_logout_response;

struct bim;


struct bim_ops {
    int (*init)(const char *rootpath);
    /* detect whether image is of this bim type */
    bool (*detect)(const char *image_name);

    /* rootfs ops*/
    int (*prepare_rf)(struct bim *bim, const json_map_string_string *storage_opt, char **real_rootfs);
    int (*mount_rf)(struct bim *bim);
    int (*umount_rf)(struct bim *bim);
    int (*delete_rf)(struct bim *bim);
    char *(*resolve_image_name)(const char *image_name);

    /* merge image config ops*/
    int (*merge_conf)(oci_runtime_spec *oci_spec, const host_config *host_spec, container_custom_config *custom_spec,
                      struct bim *bim, char **real_rootfs);

    /* get user config ops */
    int (*get_user_conf)(const char *basefs, host_config *hc,
                         const char *userstr, oci_runtime_spec_process_user *puser);

    /* list images */
    int (*list_ims)(im_list_request *request, imagetool_images_list **images);

    /* remove image */
    int (*rm_image)(im_remove_request *request);

    /* inspect image */
    int (*inspect_image)(struct bim *bim, char **inpected_json);

    int (*filesystem_usage)(struct bim *bim, imagetool_fs_info **fs_usage);

    /* load image */
    int (*load_image)(im_load_request *request);

    /* pull image */
    int (*pull_image)(const im_pull_request *request, im_pull_response **response);

    /* login */
    int (*login)(im_login_request *request);

    /* logout */
    int (*logout)(im_logout_request *request);
};

struct bim {
    /* common arguments */
    const struct bim_ops *ops;
    const char *type;

    char *image_name;
    char *ext_config_image;
    char *container_id;
};

struct bim_type {
    const char *image_type;
    const struct bim_ops *ops;
};

int image_module_init(const char *rootpath);

int im_get_container_filesystem_usage(const char *image_type, const char *id, imagetool_fs_info **fs_usage);

int im_mount_container_rootfs(const char *image_type, const char *image_name, const char *container_id);

int im_umount_container_rootfs(const char *image_type, const char *image_name,
                               const char *container_id);

int im_remove_container_rootfs(const char *image_type, const char *container_id);

int im_merge_image_config(const char *id, const char *image_type, const char *image_name,
                          const char *ext_config_image, oci_runtime_spec *oci_spec, host_config *host_spec,
                          container_custom_config *custom_spec, char **real_rootfs);

int im_get_user_conf(const char *image_type, const char *basefs, host_config *hc, const char *userstr,
                     oci_runtime_spec_process_user *puser);

int im_list_images(im_list_request *request, im_list_response **response);

void free_im_list_request(im_list_request *ptr);

void free_im_list_response(im_list_response *ptr);

int im_rm_image(im_remove_request *request, im_remove_response **response);

void free_im_remove_request(im_remove_request *ptr);

void free_im_remove_response(im_remove_response *ptr);

int im_inspect_image(const im_inspect_request *request, im_inspect_response **response);

void free_im_inspect_request(im_inspect_request *ptr);

void free_im_inspect_response(im_inspect_response *ptr);

int map_to_key_value_string(const json_map_string_string *map, char ***array, size_t *array_len);

int im_load_image(im_load_request *request, im_load_response **response);

void free_im_load_request(im_load_request *ptr);

void free_im_load_response(im_load_response *ptr);

int im_pull_image(const im_pull_request *request, im_pull_response **response);

void free_im_pull_request(im_pull_request *req);

void free_im_pull_response(im_pull_response *resp);

char *im_get_image_type(const char *image, const char *external_rootfs);

bool im_config_image_exist(const char *image_name);

int im_login(im_login_request *request, im_login_response **response);

void free_im_login_request(im_login_request *ptr);

void free_im_login_response(im_login_response *ptr);

int im_logout(im_logout_request *request, im_logout_response **response);

void free_im_logout_request(im_logout_request *ptr);

void free_im_logout_response(im_logout_response *ptr);


#ifdef __cplusplus
}
#endif

#endif
