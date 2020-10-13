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
 * Author: lifeng
 * Create: 2020-10-12
 * Description: provide container isula protocol definition
 ******************************************************************************/
#ifndef CLIENT_CONNECT_PROTOCOL_H
#define CLIENT_CONNECT_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "constants.h"
#include "io_wrapper.h"
#include "isula_libutils/container_path_stat.h"
#include "isula_libutils/json_common.h"
#include "isula_libutils/mount_spec.h"
#include "utils_timestamp.h"

#ifdef __cplusplus
extern "C" {
#endif

struct isula_filters {
    char **keys;
    char **values;
    size_t len;
};

struct isula_create_request {
    char *name;
    char *rootfs;
    char *image;
    char *runtime;
    char *host_spec_json;
    char *container_spec_json;
};

struct isula_create_response {
    char *id;
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_start_request {
    char *name;
    char *stdin;
    bool attach_stdin;
    char *stdout;
    bool attach_stdout;
    char *stderr;
    bool attach_stderr;
};

struct isula_start_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_top_request {
    char *name;
    int ps_argc;
    char **ps_args;
};

struct isula_top_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
    char *titles;
    char **processes;
    size_t processes_len;
};

struct isula_stop_request {
    char *name;
    bool force;
    int timeout;
};

struct isula_stop_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_restart_request {
    char *name;
    unsigned int timeout;
};

struct isula_restart_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_kill_request {
    char *name;
    uint32_t signal;
};

struct isula_kill_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_delete_request {
    char *name;
    bool force;
    bool volumes;
};

struct isula_delete_response {
    char *name;
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_pause_request {
    char *name;
};

struct isula_pause_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_resume_request {
    char *name;
};

struct isula_resume_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_container_info {
    char *id;
    uint64_t pids_current;
    // CPU usage
    uint64_t cpu_use_nanos;
    uint64_t cpu_system_use;
    uint32_t online_cpus;
    // BlkIO usage
    uint64_t blkio_read;
    uint64_t blkio_write;
    // Memory usage
    uint64_t mem_used;
    uint64_t mem_limit;
    // Kernel Memory usage
    uint64_t kmem_used;
    uint64_t kmem_limit;

    char *name;
    char *status;
    // Cache usage
    uint64_t cache;
    uint64_t cache_total;
    uint64_t inactive_file_total;
};

struct isula_inspect_request {
    char *name;
    bool bformat;
    int timeout;
};

struct isula_inspect_response {
    uint32_t cc;
    uint32_t server_errono;
    char *json;
    char *errmsg;
};

struct isula_list_request {
    struct isula_filters *filters;
    bool all;
};

struct isula_container_summary_info {
    char *id;
    char *image;
    char *command;
    char *name;
    Container_Status status;
    uint32_t exit_code;
    uint32_t has_pid;
    uint32_t pid;
    uint32_t restart_count;
    char *startat;
    char *finishat;
    char *runtime;
    char *health_state;
    int64_t created;
};

struct isula_list_response {
    uint32_t cc;
    uint32_t server_errono;
    size_t container_num;
    struct isula_container_summary_info **container_summary;
    char *errmsg;
};

struct isula_stats_request {
    char **containers;
    size_t containers_len;
    bool all;
};

struct isula_stats_response {
    uint32_t cc;
    uint32_t server_errono;
    size_t container_num;
    struct isula_container_info *container_stats;
    char *errmsg;
};

typedef struct container_events_format {
    types_timestamp_t timestamp;
    char *opt;
    char *id;
    char **annotations;
    char annotations_len;
} container_events_format_t;

typedef void (*container_events_callback_t)(const container_events_format_t *event);
struct isula_events_request {
    container_events_callback_t cb;
    bool storeonly;
    char *id;
    types_timestamp_t since;
    types_timestamp_t until;
};

struct isula_events_response {
    uint32_t server_errono;
    uint32_t cc;
    char *errmsg;
};

struct isula_copy_from_container_request {
    char *id;
    char *runtime;
    char *srcpath;
};

struct isula_copy_from_container_response {
    uint32_t server_errono;
    uint32_t cc;
    char *errmsg;
    container_path_stat *stat;
    struct io_read_wrapper reader;
};

struct isula_copy_to_container_request {
    char *id;
    char *runtime;
    char *srcpath;
    char *srcrebase;
    bool srcisdir;
    char *dstpath;
    struct io_read_wrapper reader;
};

struct isula_copy_to_container_response {
    uint32_t server_errono;
    uint32_t cc;
    char *errmsg;
};

struct isula_logs_request {
    char *id;
    char *runtime;

    char *since;
    char *until;
    bool timestamps;
    bool follow;
    int64_t tail;
    bool details;
};

struct isula_logs_response {
    uint32_t server_errono;
    uint32_t cc;
    char *errmsg;
};

struct isula_wait_request {
    char *id;
    uint32_t condition;
};

struct isula_wait_response {
    int exit_code;
    uint32_t server_errono;
    uint32_t cc;
    char *errmsg;
};

struct isula_exec_request {
    char *name;
    char *suffix;
    bool tty;
    bool open_stdin;
    bool attach_stdin;
    bool attach_stdout;
    bool attach_stderr;
    char *stdin;
    char *stdout;
    char *stderr;
    int argc;
    char **argv;
    size_t env_len;
    char **env;
    int64_t timeout;
    char *user;
    char *workdir;
};

struct isula_exec_response {
    uint32_t cc;
    uint32_t server_errono;
    uint32_t exit_code;
    char *errmsg;
};

struct isula_attach_request {
    char *name;
    char *stdin;
    char *stdout;
    char *stderr;
    bool attach_stdin;
    bool attach_stdout;
    bool attach_stderr;
};

struct isula_attach_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_health_check_request {
    char *service;
};

struct isula_health_check_response {
    Health_Serving_Status health_status;
    uint32_t cc;
    char *errmsg;
};

struct isula_version_request {
    char unuseful;
};

struct isula_version_response {
    uint32_t cc;
    uint32_t server_errono;
    char *version;
    char *git_commit;
    char *build_time;
    char *root_path;
    char *errmsg;
};

struct isula_info_request {
    char unuseful;
};

struct isula_info_response {
    uint32_t cc;
    uint32_t server_errono;
    char *version;
    char *kversion;
    char *os_type;
    char *architecture;
    char *nodename;
    char *operating_system;
    char *cgroup_driver;
    char *logging_driver;
    char *huge_page_size;
    char *isulad_root_dir;
    char *http_proxy;
    char *https_proxy;
    char *no_proxy;
    char *driver_name;
    char *driver_status;
    uint32_t total_mem;
    uint32_t containers_num;
    uint32_t c_running;
    uint32_t c_paused;
    uint32_t c_stopped;
    uint32_t images_num;
    uint32_t cpus;
    char *errmsg;
};

struct isula_update_request {
    char *name;
    char *host_spec_json;
};

struct isula_update_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_image_info {
    char *imageref;
    char *type;
    char *digest;
    int64_t created; /* seconds */
    int32_t created_nanos;
    int64_t size; /* Bytes */
};

struct isula_create_image_request {
    struct isula_image_info image_info;
};

struct isula_create_image_response {
    uint32_t cc;
    uint32_t server_errono;
    struct isula_image_info image_info;
    char *errmsg;
};

struct isula_list_images_request {
    struct isula_filters *filters;
    // unuseful definition to avoid generate empty struct which will get 0 if we call sizeof
    char unuseful;
};

struct isula_list_images_response {
    uint32_t cc;
    uint32_t server_errono;
    size_t images_num;
    struct isula_image_info *images_list;
    char *errmsg;
};

struct isula_rmi_request {
    char *image_name;
    bool force;
};

struct isula_rmi_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_pull_request {
    char *image_name;
};

struct isula_tag_request {
    char *src_name;
    char *dest_name;
};

struct isula_tag_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_pull_response {
    char *image_ref;
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_import_request {
    char *socketname;
    char *file;
    char *type;
    char *tag;
};

struct isula_import_response {
    char *id;
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_load_request {
    char *socketname;
    char *file;
    char *type;
    char *tag;
};

struct isula_load_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_login_request {
    char *socketname;
    char *username;
    char *password;
    char *server;
    char *type;
};

struct isula_login_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_logout_request {
    char *socketname;
    char *server;
    char *type;
};

struct isula_logout_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_export_request {
    char *name;
    char *file;
};

struct isula_export_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_rename_request {
    char *old_name;
    char *new_name;
};

struct isula_rename_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_resize_request {
    char *id;
    char *suffix;
    uint32_t height;
    uint32_t width;
};

struct isula_resize_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_list_volume_request {
    char unuseful;
};

struct isula_volume_info {
    char *driver;
    char *name;
};

struct isula_list_volume_response {
    size_t volumes_len;
    struct isula_volume_info *volumes;
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_remove_volume_request {
    char *name;
};

struct isula_remove_volume_response {
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_prune_volume_request {
    char unuseful;
};

struct isula_prune_volume_response {
    size_t volumes_len;
    char **volumes;
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_network_create_request {
    char *name;
    char *driver;
    char *gateway;
    bool internal;
    char *subnet;
};

struct isula_network_create_response {
    char *path;
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_network_inspect_request {
    char *name;
};

struct isula_network_inspect_response {
    char *json;
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_network_list_request {
    struct isula_filters *filters;
};

struct isula_network_info {
    char *name;
    char *version;
    int plugin_num;
    char **plugins;
};

struct isula_network_list_response {
    size_t network_num;
    struct isula_network_info **network_info;
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

struct isula_network_remove_request {
    char *name;
    bool force;
};

struct isula_network_remove_response {
    char *name;
    int container_num;
    char **containers;
    uint32_t cc;
    uint32_t server_errono;
    char *errmsg;
};

void container_events_format_free(container_events_format_t *value);

struct isula_filters *isula_filters_parse_args(const char **array, size_t len);

void isula_filters_free(struct isula_filters *filters);

void isula_container_info_free(struct isula_container_info *info);

void isula_version_request_free(struct isula_version_request *request);

void isula_version_response_free(struct isula_version_response *response);

void isula_info_request_free(struct isula_info_request *request);

void isula_info_response_free(struct isula_info_response *response);

void isula_create_request_free(struct isula_create_request *request);

void isula_create_response_free(struct isula_create_response *response);

void isula_start_request_free(struct isula_start_request *request);

void isula_start_response_free(struct isula_start_response *response);

void isula_top_request_free(struct isula_top_request *request);

void isula_top_response_free(struct isula_top_response *response);

void isula_stop_request_free(struct isula_stop_request *request);

void isula_stop_response_free(struct isula_stop_response *response);

void isula_restart_request_free(struct isula_restart_request *request);

void isula_restart_response_free(struct isula_restart_response *response);

void isula_delete_request_free(struct isula_delete_request *request);

void isula_delete_response_free(struct isula_delete_response *response);

void isula_list_request_free(struct isula_list_request *request);

void isula_list_response_free(struct isula_list_response *response);

void isula_exec_request_free(struct isula_exec_request *request);

void isula_exec_response_free(struct isula_exec_response *response);

void isula_attach_request_free(struct isula_attach_request *request);

void isula_attach_response_free(struct isula_attach_response *response);

void isula_pause_request_free(struct isula_pause_request *request);

void isula_pause_response_free(struct isula_pause_response *response);

void isula_resume_request_free(struct isula_resume_request *request);

void isula_resume_response_free(struct isula_resume_response *response);

void isula_kill_request_free(struct isula_kill_request *request);

void isula_kill_response_free(struct isula_kill_response *response);

void isula_update_request_free(struct isula_update_request *request);

void isula_update_response_free(struct isula_update_response *response);

void isula_stats_request_free(struct isula_stats_request *request);

void isula_stats_response_free(struct isula_stats_response *response);

void isula_events_request_free(struct isula_events_request *request);

void isula_events_response_free(struct isula_events_response *response);

void isula_copy_from_container_request_free(struct isula_copy_from_container_request *request);

void isula_copy_from_container_response_free(struct isula_copy_from_container_response *response);

void isula_copy_to_container_request_free(struct isula_copy_to_container_request *request);

void isula_copy_to_container_response_free(struct isula_copy_to_container_response *response);

void isula_inspect_request_free(struct isula_inspect_request *request);

void isula_inspect_response_free(struct isula_inspect_response *response);

void isula_wait_request_free(struct isula_wait_request *request);

void isula_wait_response_free(struct isula_wait_response *response);

void isula_health_check_request_free(struct isula_health_check_request *request);

void isula_health_check_response_free(struct isula_health_check_response *response);

void isula_create_image_request_free(struct isula_create_image_request *request);

void isula_create_image_response_free(struct isula_create_image_response *response);

void isula_images_list_free(size_t images_num, struct isula_image_info *images_list);

void isula_list_images_request_free(struct isula_list_images_request *request);

void isula_list_images_response_free(struct isula_list_images_response *response);

void isula_rmi_request_free(struct isula_rmi_request *request);

void isula_rmi_response_free(struct isula_rmi_response *response);

void isula_tag_request_free(struct isula_tag_request *request);

void isula_tag_response_free(struct isula_tag_response *response);

void isula_import_request_free(struct isula_import_request *request);

void isula_import_response_free(struct isula_import_response *response);

void isula_load_request_free(struct isula_load_request *request);

void isula_load_response_free(struct isula_load_response *response);

void isula_login_response_free(struct isula_login_response *response);

void isula_logout_response_free(struct isula_logout_response *response);

void isula_pull_request_free(struct isula_pull_request *request);
void isula_pull_response_free(struct isula_pull_response *response);

void isula_export_request_free(struct isula_export_request *request);

void isula_export_response_free(struct isula_export_response *response);

void isula_rename_request_free(struct isula_rename_request *request);

void isula_rename_response_free(struct isula_rename_response *response);

void isula_resize_request_free(struct isula_resize_request *request);

void isula_resize_response_free(struct isula_resize_response *response);

void isula_logs_request_free(struct isula_logs_request *request);

void isula_logs_response_free(struct isula_logs_response *response);

void isula_volume_list_free(size_t volumes_num, struct isula_volume_info *volumes);

void isula_list_volume_response_free(struct isula_list_volume_response *response);

void isula_remove_volume_response_free(struct isula_remove_volume_response *response);

void isula_prune_volume_response_free(struct isula_prune_volume_response *response);

void isula_network_create_request_free(struct isula_network_create_request *request);

void isula_network_create_response_free(struct isula_network_create_response *response);

void isula_network_inspect_request_free(struct isula_network_inspect_request *request);

void isula_network_inspect_response_free(struct isula_network_inspect_response *response);

void isula_network_list_request_free(struct isula_network_list_request *request);

void isula_network_info_free(struct isula_network_info *info);

void isula_network_list_response_free(struct isula_network_list_response *response);

void isula_network_remove_request_free(struct isula_network_remove_request *request);

void isula_network_remove_response_free(struct isula_network_remove_response *response);

#ifdef __cplusplus
}
#endif

#endif
