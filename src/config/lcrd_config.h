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
 * Description: provide container configure definition
 ******************************************************************************/
#ifndef __LCRD_CONF_H
#define __LCRD_CONF_H

#include <stdint.h>
#include "lcrd/arguments.h"
#include "oci_runtime_spec.h"
#include "isulad_daemon_configs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lcrd_conf {
    pthread_rwlock_t lcrd_conf_rwlock;
    struct service_arguments *server_conf;
};

char *conf_get_lcrd_pidfile();
char *conf_get_engine_rootpath();
char *conf_get_routine_rootdir(const char *runtime);
char *conf_get_routine_statedir(const char *runtime);
char *conf_get_lcrd_rootdir();
char *conf_get_lcrd_statedir();
char *conf_get_lcrd_mount_rootfs();
char *conf_get_lcrd_engine();
char *conf_get_lcrd_loglevel();
char *conf_get_lcrd_logdriver();
int conf_get_daemon_log_config(char **loglevel, char **logdriver, char **engine_log_path);
char *conf_get_lcrd_log_gather_fifo_path();

char *conf_get_lcrd_log_file();
char *conf_get_engine_log_file();
char *conf_get_enable_plugins();

int save_args_to_conf(struct service_arguments *args);

int set_unix_socket_group(const char *socket, const char *group);

int lcrd_server_conf_wrlock();

int lcrd_server_conf_rdlock();

int lcrd_server_conf_unlock();

struct service_arguments *conf_get_server_conf();

int get_system_cpu_usage(uint64_t *val);

int conf_get_lcrd_hooks(oci_runtime_spec_hooks **phooks);

int conf_get_lcrd_default_ulimit(host_config_ulimits_element ***ulimit);

unsigned int conf_get_start_timeout();

int init_cgroups_path(const char *path, int recursive_depth);

char *conf_get_graph_rootpath();

char *conf_get_graph_run_path();

char *conf_get_lcrd_storage_driver();

char *conf_get_lcrd_storage_driver_backing_fs();

char **conf_get_storage_opts();

char **conf_get_insecure_registry_list();

char **conf_get_registry_list();
char *conf_get_lcrd_native_umask();

char *conf_get_lcrd_cgroup_parent();

unsigned int conf_get_im_opt_timeout();

char *conf_get_graph_check_flag_file();

bool conf_get_image_layer_check_flag();

int merge_json_confs_into_global(struct service_arguments *args);

bool conf_get_use_decrypted_key_flag();
bool conf_get_skip_insecure_verify_flag();
int parse_log_opts(struct service_arguments *args, const char *key, const char *value);

#ifdef __cplusplus
}
#endif

#endif /* __LCRD_CONF_H */
