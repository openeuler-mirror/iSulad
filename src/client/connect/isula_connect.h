/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: maoweiyong
 * Create: 2018-11-08
 * Description: provide isula connect command definition
 ******************************************************************************/
#ifndef CLIENT_CONNECT_ISULA_CONNECT_H
#define CLIENT_CONNECT_ISULA_CONNECT_H

#include "connect.h"
#include "protocol_type.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int (*version)(const struct isula_version_request *request, struct isula_version_response *response, void *arg);

    int (*info)(const struct isula_info_request *request, struct isula_info_response *response, void *arg);

    int (*create)(const struct isula_create_request *request, struct isula_create_response *response, void *arg);

    int (*start)(const struct isula_start_request *request, struct isula_start_response *response, void *arg);

    int (*remote_start)(const struct isula_start_request *request, struct isula_start_response *response, void *arg);

    int (*stop)(const struct isula_stop_request *request, struct isula_stop_response *response, void *arg);

    int (*restart)(const struct isula_restart_request *request, struct isula_restart_response *response, void *arg);

    int (*kill)(const struct isula_kill_request *request, struct isula_kill_response *response, void *arg);

    int (*remove)(const struct isula_delete_request *request, struct isula_delete_response *response, void *arg);

    int (*pause)(const struct isula_pause_request *request, struct isula_pause_response *response, void *arg);

    int (*resume)(const struct isula_resume_request *request, struct isula_resume_response *response, void *arg);

    int (*list)(const struct isula_list_request *request, struct isula_list_response *response, void *arg);

    int (*inspect)(const struct isula_inspect_request *request, struct isula_inspect_response *response, void *arg);

    int (*stats)(const struct isula_stats_request *request, struct isula_stats_response *response, void *arg);

    int (*events)(const struct isula_events_request *request, struct isula_events_response *response, void *arg);

    int (*copy_from_container)(const struct isula_copy_from_container_request *request,
                               struct isula_copy_from_container_response *response, void *arg);

    int (*copy_to_container)(const struct isula_copy_to_container_request *request,
                             struct isula_copy_to_container_response *response, void *arg);

    int (*exec)(const struct isula_exec_request *request, struct isula_exec_response *response, void *arg);

    int (*remote_exec)(const struct isula_exec_request *request, struct isula_exec_response *response, void *arg);

    int (*update)(const struct isula_update_request *request, struct isula_update_response *response, void *arg);

    int (*attach)(const struct isula_attach_request *request, struct isula_attach_response *response, void *arg);

    int (*wait)(const struct isula_wait_request *request, struct isula_wait_response *response, void *arg);

    int (*export_rootfs)(const struct isula_export_request *request, struct isula_export_response *response, void *arg);
    int (*top)(const struct isula_top_request *request, struct isula_top_response *response, void *arg);
    int (*rename)(const struct isula_rename_request *request, struct isula_rename_response *response, void *arg);
    int (*resize)(const struct isula_resize_request *request, struct isula_resize_response *response, void *arg);
    int (*logs)(const struct isula_logs_request *request, struct isula_logs_response *response, void *arg);
} container_ops;

typedef struct {
    int (*list)(const struct isula_list_images_request *request, struct isula_list_images_response *response,
                void *arg);

    int (*remove)(const struct isula_rmi_request *request, struct isula_rmi_response *response, void *arg);

    int (*load)(const struct isula_load_request *request, struct isula_load_response *response, void *arg);

    int (*pull)(const struct isula_pull_request *request, struct isula_pull_response *response, void *arg);

    int (*inspect)(const struct isula_inspect_request *request, struct isula_inspect_response *response, void *arg);
    int (*login)(const struct isula_login_request *request, struct isula_login_response *response, void *arg);
    int (*logout)(const struct isula_logout_request *request, struct isula_logout_response *response, void *arg);
    int (*tag)(const struct isula_tag_request *request, struct isula_tag_response *response, void *arg);
    int (*import)(const struct isula_import_request *request, struct isula_import_response *response, void *arg);
} image_ops;

typedef struct {
    int (*list)(const struct isula_list_volume_request *request, struct isula_list_volume_response *response,
                void *arg);

    int (*remove)(const struct isula_remove_volume_request *request, struct isula_remove_volume_response *response,
                  void *arg);

    int (*prune)(const struct isula_prune_volume_request *request, struct isula_prune_volume_response *response,
                 void *arg);
} volume_ops;

typedef struct {
    int (*check)(const struct isula_health_check_request *request, struct isula_health_check_response *response,
                 void *arg);
} health_ops;

typedef struct {
    int (*create)(const struct isula_network_create_request *request, struct isula_network_create_response *response,
                  void *arg);
} network_ops;

typedef struct {
    container_ops container;
    image_ops image;
    volume_ops volume;
    health_ops health;
    network_ops network;
} isula_connect_ops;

int connect_client_ops_init(void);

isula_connect_ops *get_connect_client_ops(void);

#ifdef __cplusplus
}
#endif

#endif // CLIENT_CONNECT_ISULA_CONNECT_H
