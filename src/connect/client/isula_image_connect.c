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
#include "isula_image_connect.h"

#include "utils.h"
#include "grpc_isula_image_client.h"

static isula_image_ops g_image_ops;

int isula_image_ops_init(void)
{
    (void)memset(&g_image_ops, 0, sizeof(isula_image_ops));

    return grpc_isula_image_client_ops_init(&g_image_ops);
}

isula_image_ops *get_isula_image_ops(void)
{
    return &g_image_ops;
}

void free_image_spec(struct image_spec *spec)
{
    if (spec == NULL) {
        return;
    }
    free(spec->image);
    spec->image = NULL;
    free(spec);
}

void free_isula_auth_config(struct isula_auth_config *auth)
{
    if (auth == NULL) {
        return;
    }
    free_sensitive_string(auth->username);
    auth->username = NULL;
    free_sensitive_string(auth->password);
    auth->password = NULL;
    free_sensitive_string(auth->auth);
    auth->auth = NULL;
    free_sensitive_string(auth->server_address);
    auth->server_address = NULL;
    free_sensitive_string(auth->identity_token);
    auth->identity_token = NULL;
    free_sensitive_string(auth->registry_token);
    auth->registry_token = NULL;
    free(auth);
}

void free_isula_pull_request(struct isula_pull_request *req)
{
    if (req == NULL) {
        return;
    }
    free_image_spec(req->image);
    req->image = NULL;
    free_isula_auth_config(req->auth);
    req->auth = NULL;
    free(req);
}

void free_isula_pull_response(struct isula_pull_response *resp)
{
    if (resp == NULL) {
        return;
    }
    free(resp->image_ref);
    resp->image_ref = NULL;
    free(resp->errmsg);
    resp->errmsg = NULL;
    resp->cc = 0;
    free(resp);
}

void free_isula_prepare_request(struct isula_prepare_request *req)
{
    if (req == NULL) {
        return;
    }
    free(req->id);
    req->id = NULL;
    free(req->name);
    req->name = NULL;
    free(req->image);
    req->image = NULL;
    util_free_array_by_len(req->storage_opts, req->storage_opts_len);
    req->storage_opts = NULL;
    req->storage_opts_len = 0;
    free(req);
}

void free_isula_prepare_response(struct isula_prepare_response *resp)
{
    if (resp == NULL) {
        return;
    }
    free(resp->mount_point);
    resp->mount_point = NULL;
    free(resp->image_conf);
    resp->image_conf = NULL;
    free(resp->errmsg);
    resp->errmsg = NULL;
    resp->cc = 0;
    free(resp);
}

void free_isula_remove_request(struct isula_remove_request *req)
{
    if (req == NULL) {
        return;
    }
    free(req->name_id);
    req->name_id = NULL;
    free(req);
}

void free_isula_remove_response(struct isula_remove_response *resp)
{
    if (resp == NULL) {
        return;
    }
    free(resp->errmsg);
    resp->errmsg = NULL;
    resp->cc = 0;
    free(resp);
}

void free_isula_mount_request(struct isula_mount_request *req)
{
    if (req == NULL) {
        return;
    }
    free(req->name_id);
    req->name_id = NULL;
    free(req);
}

void free_isula_mount_response(struct isula_mount_response *resp)
{
    if (resp == NULL) {
        return;
    }
    free(resp->errmsg);
    resp->errmsg = NULL;
    resp->cc = 0;
    free(resp);
}

void free_isula_umount_request(struct isula_umount_request *req)
{
    if (req == NULL) {
        return;
    }
    free(req->name_id);
    req->name_id = NULL;
    free(req);
}

void free_isula_umount_response(struct isula_umount_response *resp)
{
    if (resp == NULL) {
        return;
    }
    free(resp->errmsg);
    resp->errmsg = NULL;
    resp->cc = 0;
    free(resp);
}

void free_isula_containers_list_request(struct isula_containers_list_request *req)
{
    if (req == NULL) {
        return;
    }
    free(req);
}

void free_isula_containers_list_response(struct isula_containers_list_response *resp)
{
    if (resp == NULL) {
        return;
    }

    free_json_map_string_bool(resp->containers);

    free(resp->errmsg);
    resp->errmsg = NULL;
    resp->cc = 0;
    free(resp);
}

void free_image_metadata(struct image_metadata *data)
{
    if (data == NULL) {
        return;
    }
    free(data->id);
    data->id = NULL;
    util_free_array_by_len(data->repo_tags, data->repo_tags_len);
    data->repo_tags = NULL;
    data->repo_tags_len = 0;
    util_free_array_by_len(data->repo_digests, data->repo_digests_len);
    data->repo_digests = NULL;
    data->repo_digests_len = 0;
    free(data->username);
    data->username = NULL;
    free(data->created);
    data->created = NULL;
    free(data->loaded);
    data->loaded = NULL;
    free(data->oci_spec);
    data->oci_spec = NULL;
    free(data);
}

void free_isula_status_request(struct isula_status_request *req)
{
    if (req == NULL) {
        return;
    }
    free_image_spec(req->image);
    req->image = NULL;
    free(req);
}

void free_isula_status_response(struct isula_status_response *resp)
{
    if (resp == NULL) {
        return;
    }
    free_image_metadata(resp->image);
    resp->image = NULL;
    free_json_map_string_string(resp->info);
    resp->info = NULL;
    free(resp->errmsg);
    resp->errmsg = NULL;
    free(resp);
}

void free_isula_list_request(struct isula_list_request *req)
{
    if (req == NULL) {
        return;
    }
    free(req->filter);
    req->filter = NULL;
    free(req);
}

void free_isula_list_response(struct isula_list_response *resp)
{
    size_t i = 0;

    if (resp == NULL) {
        return;
    }
    for (; i < resp->images_len; i++) {
        free_image_metadata(resp->images[i]);
        resp->images[i] = NULL;
    }
    free(resp->images);
    resp->images = NULL;
    resp->images_len = 0;
    free(resp->errmsg);
    resp->errmsg = NULL;
    free(resp);
}

void free_isula_rmi_request(struct isula_rmi_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free_image_spec(ptr->image);
    ptr->image = NULL;
    free(ptr);
}

void free_isula_rmi_response(struct isula_rmi_response *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->errmsg);
    ptr->errmsg = NULL;
    free(ptr);
}

void free_isula_load_request(struct isula_load_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->file);
    ptr->file = NULL;
    free(ptr->tag);
    ptr->tag = NULL;
    free(ptr);
}

void free_isula_load_response(struct isula_load_response *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->outmsg);
    ptr->outmsg = NULL;
    free(ptr->errmsg);
    ptr->errmsg = NULL;
    free(ptr);
}

void free_isula_login_request(struct isula_login_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free_sensitive_string(ptr->password);
    ptr->password = NULL;
    free_sensitive_string(ptr->username);
    ptr->username = NULL;
    free(ptr->server);
    ptr->server = NULL;
    free(ptr);
}

void free_isula_login_response(struct isula_login_response *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->errmsg);
    ptr->errmsg = NULL;
    free(ptr);
}

void free_isula_logout_request(struct isula_logout_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->server);
    ptr->server = NULL;
    free(ptr);
}
void free_isula_logout_response(struct isula_logout_response *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->errmsg);
    ptr->errmsg = NULL;
    free(ptr);
}

void free_filesystem_usage(struct filesystem_usage *usage)
{
    if (usage == NULL) {
        return;
    }
    free(usage->uuid);
    usage->uuid = NULL;
    free(usage->used_bytes);
    usage->used_bytes = NULL;
    free(usage->inodes_used);
    usage->inodes_used = NULL;
    free(usage);
}

void free_isula_image_fs_info_request(struct isula_image_fs_info_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr);
}

void free_isula_image_fs_info_response(struct isula_image_fs_info_response *ptr)
{
    size_t i = 0;

    if (ptr == NULL) {
        return;
    }
    for (; i < ptr->image_filesystems_len; i++) {
        free_filesystem_usage(ptr->image_filesystems[i]);
        ptr->image_filesystems[i] = NULL;
    }
    ptr->image_filesystems_len = 0;
    free(ptr->image_filesystems);
    ptr->image_filesystems = NULL;
    free(ptr);
}

void free_isula_export_request(struct isula_export_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->name_id);
    ptr->name_id = NULL;
    free(ptr->output);
    ptr->output = NULL;
    free(ptr);
}

void free_isula_export_response(struct isula_export_response *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->errmsg);
    ptr->errmsg = NULL;
    free(ptr);
}

void free_isula_container_fs_usage_request(struct isula_container_fs_usage_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->name_id);
    ptr->name_id = NULL;
    free(ptr);
}

void free_isula_container_fs_usage_response(struct isula_container_fs_usage_response *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->usage);
    ptr->usage = NULL;
    free(ptr->errmsg);
    ptr->errmsg = NULL;
    free(ptr);
}

void free_isula_storage_status_request(struct isula_storage_status_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr);
}

void free_isula_storage_status_response(struct isula_storage_status_response *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->status);
    ptr->status = NULL;
    free(ptr->errmsg);
    ptr->errmsg = NULL;
    free(ptr);
}

void free_isula_health_check_request(struct isula_health_check_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr);
}

void free_isula_health_check_response(struct isula_health_check_response *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->errmsg);
    ptr->errmsg = NULL;
    free(ptr);
}
