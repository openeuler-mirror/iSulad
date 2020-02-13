/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
* Author: liuhao
* Create: 2019-07-12
* Description: provide isula image connect command definition
*******************************************************************************/
#ifndef __ISULA_IMAGE_CONNECT_H
#define __ISULA_IMAGE_CONNECT_H

#include <stdint.h>
#include <unistd.h>

#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct image_spec {
    char *image;
};

struct isula_auth_config {
    char *username;
    char *password;
    char *auth;
    char *server_address;
    char *identity_token;
    char *registry_token;
};

struct isula_pull_request {
    struct image_spec *image;
    struct isula_auth_config *auth;
};

struct isula_pull_response {
    char *image_ref;
    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_prepare_request {
    char *image;
    char *id;
    char *name;
    char **storage_opts;
    size_t storage_opts_len;
};

struct isula_prepare_response {
    char *mount_point;
    char *image_conf;
    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_remove_request {
    char *name_id;
};

struct isula_remove_response {
    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_mount_request {
    char *name_id;
};

struct isula_mount_response {
    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_umount_request {
    char *name_id;
    bool force;
};

struct isula_umount_response {
    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct image_metadata {
    char *id;

    char **repo_tags;
    size_t repo_tags_len;

    char **repo_digests;
    size_t repo_digests_len;

    uint64_t size;

    int64_t uid;

    char *username;

    char *created;

    char *loaded;

    char *oci_spec;
};

struct isula_status_request {
    struct image_spec *image;
    bool verbose;
};

struct isula_status_response {
    struct image_metadata *image;
    json_map_string_string *info;

    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_list_request {
    char *filter;
    bool check;
};

struct isula_list_response {
    struct image_metadata **images;
    size_t images_len;

    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_rmi_request {
    struct image_spec *image;
    bool force;
};

struct isula_rmi_response {
    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_load_request {
    char *file;
    char *tag;
};

struct isula_load_response {
    char *outmsg;

    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_login_request {
    char *server;
    char *username;
    char *password;
};

struct isula_login_response {
    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_logout_request {
    char *server;
};

struct isula_logout_response {
    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_export_request {
    char *name_id;
    char *output;
    uint32_t uid;
    uint32_t gid;
    uint32_t offset;
};

struct isula_export_response {
    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_containers_list_request {
    char unuseful;
};

struct isula_containers_list_response {
    json_map_string_bool *containers;

    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_storage_status_request {
    char unuseful;
};

struct isula_storage_status_response {
    char *status;

    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_container_fs_usage_request {
    char *name_id;
};

struct isula_container_fs_usage_response {
    char *usage;

    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_image_fs_info_request {
    char unuseful;
};

struct filesystem_usage {
    int64_t timestamp;
    char *uuid;
    uint64_t *used_bytes;
    uint64_t *inodes_used;
};

struct isula_image_fs_info_response {
    struct filesystem_usage **image_filesystems;
    size_t image_filesystems_len;

    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

struct isula_health_check_request {
    char unuseful;
};

struct isula_health_check_response {
    char *errmsg;
    uint32_t cc;
    uint32_t server_errono;
};

typedef struct {
    int (*pull)(const struct isula_pull_request *req, struct isula_pull_response *resp, void *arg);
    int (*rmi)(const struct isula_rmi_request *req, struct isula_rmi_response *resp, void *arg);
    int (*load)(const struct isula_load_request *req, struct isula_load_response *resp, void *arg);
    int (*login)(const struct isula_login_request *req, struct isula_login_response *resp, void *arg);
    int (*logout)(const struct isula_logout_request *req, struct isula_logout_response *resp, void *arg);
    int (*image_fs_info)(const struct isula_image_fs_info_request *req, struct isula_image_fs_info_response *resp,
                         void *arg);

    int (*prepare)(const struct isula_prepare_request *req, struct isula_prepare_response *resp, void *arg);
    int (*remove)(const struct isula_remove_request *req, struct isula_remove_response *resp, void *arg);
    int (*mount)(const struct isula_mount_request *req, struct isula_mount_response *resp, void *arg);
    int (*umount)(const struct isula_umount_request *req, struct isula_umount_response *resp, void *arg);
    int (*containers_list)(const struct isula_containers_list_request *req, struct isula_containers_list_response *resp,
                           void *arg);
    int (*container_export)(const struct isula_export_request *req, struct isula_export_response *resp, void *arg);
    int (*container_fs_usage)(const struct isula_container_fs_usage_request *req,
                              struct isula_container_fs_usage_response *resp, void *arg);

    int (*status)(const struct isula_status_request *req, struct isula_status_response *resp, void *arg);
    int (*list)(const struct isula_list_request *req, struct isula_list_response *resp, void *arg);

    int (*storage_status)(const struct isula_storage_status_request *req, struct isula_storage_status_response *resp,
                          void *arg);

    int (*health_check)(const struct isula_health_check_request *req,
                        struct isula_health_check_response *resp, void *arg);
} isula_image_ops;


/* init isula image function pointer */
int isula_image_ops_init(void);

/* return initilized isula image ops */
isula_image_ops *get_isula_image_ops(void);

void free_image_spec(struct image_spec *spec);
void free_isula_auth_config(struct isula_auth_config *auth);
void free_isula_pull_request(struct isula_pull_request *req);
void free_isula_pull_response(struct isula_pull_response *resp);
void free_isula_prepare_request(struct isula_prepare_request *req);
void free_isula_prepare_response(struct isula_prepare_response *resp);
void free_isula_remove_request(struct isula_remove_request *req);
void free_isula_remove_response(struct isula_remove_response *resp);
void free_isula_mount_request(struct isula_mount_request *req);
void free_isula_mount_response(struct isula_mount_response *resp);
void free_isula_umount_request(struct isula_umount_request *req);
void free_isula_umount_response(struct isula_umount_response *resp);

void free_isula_containers_list_request(struct isula_containers_list_request *req);
void free_isula_containers_list_response(struct isula_containers_list_response *resp);

void free_image_metadata(struct image_metadata *data);
void free_isula_status_request(struct isula_status_request *req);
void free_isula_status_response(struct isula_status_response *resp);
void free_isula_list_request(struct isula_list_request *req);
void free_isula_list_response(struct isula_list_response *resp);

void free_isula_rmi_request(struct isula_rmi_request *ptr);
void free_isula_rmi_response(struct isula_rmi_response *ptr);

void free_isula_load_request(struct isula_load_request *ptr);
void free_isula_load_response(struct isula_load_response *ptr);

void free_isula_login_request(struct isula_login_request *ptr);
void free_isula_login_response(struct isula_login_response *ptr);

void free_isula_logout_request(struct isula_logout_request *ptr);
void free_isula_logout_response(struct isula_logout_response *ptr);

void free_filesystem_usage(struct filesystem_usage *usage);
void free_isula_image_fs_info_request(struct isula_image_fs_info_request *ptr);
void free_isula_image_fs_info_response(struct isula_image_fs_info_response *ptr);

void free_isula_export_request(struct isula_export_request *ptr);
void free_isula_export_response(struct isula_export_response *ptr);

void free_isula_container_fs_usage_request(struct isula_container_fs_usage_request *ptr);
void free_isula_container_fs_usage_response(struct isula_container_fs_usage_response *ptr);

void free_isula_storage_status_request(struct isula_storage_status_request *ptr);
void free_isula_storage_status_response(struct isula_storage_status_response *ptr);

void free_isula_health_check_request(struct isula_health_check_request *ptr);
void free_isula_health_check_response(struct isula_health_check_response *ptr);

#ifdef __cplusplus
}
#endif

#endif /* __ISULA_IMAGE_CONNECT_H */
