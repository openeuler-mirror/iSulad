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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container callback definition
 ******************************************************************************/
#ifndef DAEMON_EXECUTOR_CALLBACK_H
#define DAEMON_EXECUTOR_CALLBACK_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "io_wrapper.h"
#include "isula_libutils/container_get_id_request.h"
#include "isula_libutils/container_get_id_response.h"
#include "isula_libutils/container_get_runtime_response.h"
#include "isula_libutils/container_create_request.h"
#include "isula_libutils/container_create_response.h"
#include "isula_libutils/container_start_request.h"
#include "isula_libutils/container_start_response.h"
#include "isula_libutils/container_top_request.h"
#include "isula_libutils/container_top_response.h"
#include "isula_libutils/container_stop_request.h"
#include "isula_libutils/container_stop_response.h"
#include "isula_libutils/container_update_request.h"
#include "isula_libutils/container_update_response.h"
#include "isula_libutils/container_kill_request.h"
#include "isula_libutils/container_kill_response.h"
#include "isula_libutils/container_delete_request.h"
#include "isula_libutils/container_delete_response.h"
#include "isula_libutils/container_restart_request.h"
#include "isula_libutils/container_restart_response.h"
#include "isula_libutils/container_exec_request.h"
#include "isula_libutils/container_exec_response.h"
#include "isula_libutils/container_inspect_request.h"
#include "isula_libutils/container_inspect_response.h"
#include "isula_libutils/container_attach_request.h"
#include "isula_libutils/container_attach_response.h"
#include "isula_libutils/container_pause_request.h"
#include "isula_libutils/container_pause_response.h"
#include "isula_libutils/container_list_request.h"
#include "isula_libutils/container_list_response.h"
#include "isula_libutils/container_resume_request.h"
#include "isula_libutils/container_resume_response.h"
#include "isula_libutils/container_stats_request.h"
#include "isula_libutils/container_stats_response.h"
#include "isula_libutils/container_wait_request.h"
#include "isula_libutils/container_wait_response.h"
#include "isula_libutils/container_version_request.h"
#include "isula_libutils/container_version_response.h"
#include "isula_libutils/container_path_stat.h"
#include "isula_libutils/container_copy_to_request.h"
#include "isula_libutils/host_info_request.h"
#include "isula_libutils/host_info_response.h"
#include "isula_libutils/image_delete_image_request.h"
#include "isula_libutils/image_delete_image_response.h"
#include "isula_libutils/image_import_request.h"
#include "isula_libutils/image_import_response.h"
#include "isula_libutils/image_tag_image_request.h"
#include "isula_libutils/image_tag_image_response.h"
#include "isula_libutils/image_load_image_request.h"
#include "isula_libutils/image_load_image_response.h"
#include "isula_libutils/image_inspect_request.h"
#include "isula_libutils/image_inspect_response.h"
#include "isula_libutils/image_list_images_request.h"
#include "isula_libutils/image_list_images_response.h"
#include "isula_libutils/container_export_request.h"
#include "isula_libutils/container_export_response.h"
#include "isula_libutils/image_login_request.h"
#include "isula_libutils/image_login_response.h"
#include "isula_libutils/image_logout_request.h"
#include "isula_libutils/image_logout_response.h"
#include "isula_libutils/volume_list_volume_request.h"
#include "isula_libutils/volume_list_volume_response.h"
#include "isula_libutils/volume_remove_volume_request.h"
#include "isula_libutils/volume_remove_volume_response.h"
#include "isula_libutils/volume_prune_volume_request.h"
#include "isula_libutils/volume_prune_volume_response.h"
#include "events_format.h"
#include "stream_wrapper.h"
#include "utils_timestamp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void(handle_events_callback_t)(struct isulad_events_format *event);

struct isulad_events_request {
    handle_events_callback_t *cb;
    bool storeonly;
    char *id;
    types_timestamp_t since;
    types_timestamp_t until;
};

struct isulad_events_response {
    uint32_t server_errono;
    uint32_t cc;
    char *errmsg;
};

struct isulad_copy_from_container_request {
    char *id;
    char *runtime;
    char *srcpath;
};

struct isulad_copy_from_container_response {
    char *data;
    size_t data_len;
};

struct isulad_copy_to_container_data {
    char *data;
    size_t data_len;
};

struct isulad_logs_request {
    char *id;
    char *runtime;

    char *since;
    char *until;
    bool timestamps;
    bool follow;
    int64_t tail;
    bool details;
};

struct isulad_logs_response {
    uint32_t cc;
    char *errmsg;
};

struct isulad_container_rename_request {
    char *old_name;
    char *new_name;
};

struct isulad_container_rename_response {
    char *id;
    uint32_t cc;
    char *errmsg;
};

struct isulad_container_resize_request {
    char *id;
    char *suffix;
    uint32_t height;
    uint32_t width;
};

struct isulad_container_resize_response {
    char *id;
    uint32_t cc;
    char *errmsg;
};

void isulad_events_request_free(struct isulad_events_request *request);

void isulad_copy_from_container_request_free(struct isulad_copy_from_container_request *request);

void isulad_copy_from_container_response_free(struct isulad_copy_from_container_response *response);

void isulad_container_rename_request_free(struct isulad_container_rename_request *request);

void isulad_container_rename_response_free(struct isulad_container_rename_response *response);

void isulad_container_resize_request_free(struct isulad_container_resize_request *request);

void isulad_container_resize_response_free(struct isulad_container_resize_response *response);

void isulad_logs_request_free(struct isulad_logs_request *request);
void isulad_logs_response_free(struct isulad_logs_response *response);

typedef struct {
    int (*version)(const container_version_request *request, container_version_response **response);

    int (*info)(const host_info_request *request, host_info_response **response);

    int (*get_id)(const container_get_id_request *request, container_get_id_response **response);

    int (*get_runtime)(const char *real_id, container_get_runtime_response **response);

    int (*create)(const container_create_request *request, container_create_response **response);

    int (*start)(const container_start_request *request, container_start_response **response, int stdinfd,
                 struct io_write_wrapper *stdout, struct io_write_wrapper *stderr);

    int (*top)(container_top_request *request, container_top_response **response);

    int (*stop)(const container_stop_request *request, container_stop_response **response);

    int (*restart)(const container_restart_request *request, container_restart_response **response);

    int (*kill)(const container_kill_request *request, container_kill_response **response);

    int (*remove)(const container_delete_request *request, container_delete_response **response);

    int (*list)(const container_list_request *request, container_list_response **response);

    int (*exec)(const container_exec_request *request, container_exec_response **response, int stdinfd,
                struct io_write_wrapper *stdout, struct io_write_wrapper *stderr);

    int (*attach)(const container_attach_request *request, container_attach_response **response, int stdinfd,
                  struct io_write_wrapper *stdout, struct io_write_wrapper *stderr);

    int (*update)(const container_update_request *request, container_update_response **response);

    int (*stats)(const container_stats_request *request, container_stats_response **response);

    int (*pause)(const container_pause_request *request, container_pause_response **response);

    int (*resume)(const container_resume_request *request, container_resume_response **response);

    int (*inspect)(const container_inspect_request *request, container_inspect_response **response);

    int (*wait)(const container_wait_request *request, container_wait_response **response);

    int (*events)(const struct isulad_events_request *request, const stream_func_wrapper *stream);

    int (*export_rootfs)(const container_export_request *request, container_export_response **response);

    int (*copy_from_container)(const struct isulad_copy_from_container_request *request,
                               const stream_func_wrapper *stream, char **err);

    int (*copy_to_container)(const container_copy_to_request *request, stream_func_wrapper *stream, char **err);

    int (*rename)(const struct isulad_container_rename_request *request,
                  struct isulad_container_rename_response **response);

    int (*logs)(const struct isulad_logs_request *request, stream_func_wrapper *stream,
                struct isulad_logs_response **response);

    int (*resize)(const struct isulad_container_resize_request *request,
                  struct isulad_container_resize_response **response);
} service_container_callback_t;

typedef struct {
    int (*list)(const image_list_images_request *request, image_list_images_response **response);

    int (*remove)(const image_delete_image_request *request, image_delete_image_response **response);

    int (*import)(const image_import_request *request, image_import_response **response);

    int (*load)(const image_load_image_request *request, image_load_image_response **response);

    int (*inspect)(const image_inspect_request *request, image_inspect_response **response);

    int (*login)(const image_login_request *request, image_login_response **response);

    int (*logout)(const image_logout_request *request, image_logout_response **response);

    int (*tag)(const image_tag_image_request *request, image_tag_image_response **response);
} service_image_callback_t;

typedef struct {
    int (*list)(const volume_list_volume_request *request, volume_list_volume_response **response);

    int (*remove)(const volume_remove_volume_request *request, volume_remove_volume_response **response);

    int (*prune)(const volume_prune_volume_request *request, volume_prune_volume_response **response);
} service_volume_callback_t;

typedef struct {
    service_container_callback_t container;
    service_image_callback_t image;
    service_volume_callback_t volume;
} service_executor_t;

int service_callback_init(void);

service_executor_t *get_service_executor(void);

#ifdef __cplusplus
}
#endif

#endif
