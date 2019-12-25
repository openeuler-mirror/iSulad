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
 * Author: maoweiyong
 * Create: 2018-11-08
 * Description: provide lcrc connect command definition
 ******************************************************************************/
#ifndef __LCRC_CONNECT_H
#define __LCRC_CONNECT_H

#include "liblcrc.h"
#include "connect.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int(*version)(const struct lcrc_version_request *request,
                  struct lcrc_version_response *response, void *arg);

    int(*info)(const struct lcrc_info_request *request,
               struct lcrc_info_response *response, void *arg);

    int(*create)(const struct lcrc_create_request *request,
                 struct lcrc_create_response *response, void *arg);

    int(*start)(const struct lcrc_start_request *request,
                struct lcrc_start_response *response, void *arg);

    int(*remote_start)(const struct lcrc_start_request *request,
                       struct lcrc_start_response *response, void *arg);

    int(*stop)(const struct lcrc_stop_request *request,
               struct lcrc_stop_response *response, void *arg);

    int(*restart)(const struct lcrc_restart_request *request,
                  struct lcrc_restart_response *response, void *arg);

    int(*kill)(const struct lcrc_kill_request *request,
               struct lcrc_kill_response *response, void *arg);

    int(*remove)(const struct lcrc_delete_request *request,
                 struct lcrc_delete_response *response, void *arg);

    int(*pause)(const struct lcrc_pause_request *request,
                struct lcrc_pause_response *response, void *arg);

    int(*resume)(const struct lcrc_resume_request *request,
                 struct lcrc_resume_response *response, void *arg);

    int(*list)(const struct lcrc_list_request *request,
               struct lcrc_list_response *response, void *arg);

    int(*inspect)(const struct lcrc_inspect_request *request,
                  struct lcrc_inspect_response *response, void *arg);

    int(*stats)(const struct lcrc_stats_request *request,
                struct lcrc_stats_response *response, void *arg);

    int(*events)(const struct lcrc_events_request *request,
                 struct lcrc_events_response *response, void *arg);

    int(*copy_from_container)(const struct lcrc_copy_from_container_request *request,
                              struct lcrc_copy_from_container_response *response, void *arg);

    int(*copy_to_container)(const struct lcrc_copy_to_container_request *request,
                            struct lcrc_copy_to_container_response *response, void *arg);

    int(*exec)(const struct lcrc_exec_request *request,
               struct lcrc_exec_response *response, void *arg);

    int(*remote_exec)(const struct lcrc_exec_request *request,
                      struct lcrc_exec_response *response, void *arg);

    int(*update)(const struct lcrc_update_request *request,
                 struct lcrc_update_response *response, void *arg);

    int(*conf)(const struct lcrc_container_conf_request *request,
               struct lcrc_container_conf_response *response, void *arg);

    int(*attach)(const struct lcrc_attach_request *request,
                 struct lcrc_attach_response *response, void *arg);

    int(*wait)(const struct lcrc_wait_request *request,
               struct lcrc_wait_response *response, void *arg);

    int(*export_rootfs)(const struct lcrc_export_request *request,
                        struct lcrc_export_response *response, void *arg);
    int(*top)(const struct lcrc_top_request *request,
              struct lcrc_top_response *response, void *arg);
    int(*rename)(const struct lcrc_rename_request *request,
                 struct lcrc_rename_response *response, void *arg);

    int(*logs)(const struct lcrc_logs_request *request, struct lcrc_logs_response *response, void *arg);
} container_ops;

typedef struct {
    int(*list)(const struct lcrc_list_images_request *request,
               struct lcrc_list_images_response *response, void *arg);

    int(*remove)(const struct lcrc_rmi_request *request,
                 struct lcrc_rmi_response *response, void *arg);

    int(*load)(const struct lcrc_load_request *request,
               struct lcrc_load_response *response, void *arg);

    int(*pull)(const struct lcrc_pull_request *request,
               struct lcrc_pull_response *response, void *arg);

    int(*inspect)(const struct lcrc_inspect_request *request,
                  struct lcrc_inspect_response *response, void *arg);
    int(*login)(const struct lcrc_login_request *request,
                struct lcrc_login_response *response, void *arg);
    int(*logout)(const struct lcrc_logout_request *request,
                 struct lcrc_logout_response *response, void *arg);
} image_ops;

typedef struct {
    int(*check)(const struct lcrc_health_check_request *request,
                struct lcrc_health_check_response *response, void *arg);
} health_ops;

typedef struct {
    container_ops container;
    image_ops image;
    health_ops health;
} lcrc_connect_ops;

int connect_client_ops_init(void);

lcrc_connect_ops *get_connect_client_ops(void);

#ifdef __cplusplus
}
#endif

#endif /* __LCRC_CONNECT_H */

