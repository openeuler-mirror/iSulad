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
 * Create: 2018-11-08
 * Description: provide container configure definition
 ******************************************************************************/
#ifndef DAEMON_CONFIG_ISULAD_CONFIG_H
#define DAEMON_CONFIG_ISULAD_CONFIG_H

#include <stdint.h>
#include <isula_libutils/host_config.h>
#include <pthread.h>
#include <stdbool.h>

#include "daemon_arguments.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "isula_libutils/isulad_daemon_configs.h"
#include "isula_libutils/isulad_daemon_constants.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_RUNTIME_NAME "lcr"

struct isulad_conf {
    pthread_rwlock_t isulad_conf_rwlock;
    struct service_arguments *server_conf;
};

#ifdef ENABLE_CRI_API_V1
#define DEFAULT_SANDBOXER_NAME "shim"
char *conf_get_sandbox_rootpath(void);
char *conf_get_sandbox_statepath(void);
#endif

char *conf_get_isulad_pidfile(void);
char *conf_get_engine_rootpath(void);
char *conf_get_routine_rootdir(const char *runtime);
char *conf_get_routine_statedir(const char *runtime);
char *conf_get_isulad_rootdir(void);
char *conf_get_isulad_statedir(void);
char *conf_get_isulad_mount_rootfs(void);
char *conf_get_isulad_loglevel(void);
char *conf_get_isulad_logdriver(void);
int conf_get_daemon_log_config(char **loglevel, char **logdriver, char **engine_log_path);
char *conf_get_isulad_log_gather_fifo_path(void);

int conf_get_cgroup_cpu_rt(int64_t *cpu_rt_period, int64_t *cpu_rt_runtime);

int conf_get_container_log_opts(isulad_daemon_configs_container_log **opts);

char *conf_get_isulad_log_file(void);
char *conf_get_engine_log_file(void);
#ifdef ENABLE_PLUGIN
char *conf_get_enable_plugins(void);
#endif
#ifdef ENABLE_USERNS_REMAP
char *conf_get_isulad_userns_remap(void);
#endif
char *conf_get_cni_conf_dir(void);
int conf_get_cni_bin_dir(char ***dst);
int32_t conf_get_websocket_server_listening_port(void);

int save_args_to_conf(struct service_arguments *args);

int set_unix_socket_group(const char *socket, const char *group);

int isulad_server_conf_wrlock(void);

int isulad_server_conf_rdlock(void);

int isulad_server_conf_unlock(void);

struct service_arguments *conf_get_server_conf(void);

int get_system_cpu_usage(uint64_t *val);

int conf_get_isulad_hooks(oci_runtime_spec_hooks **phooks);

int conf_get_isulad_default_ulimit(host_config_ulimits_element ***ulimit);

unsigned int conf_get_start_timeout(void);

char **conf_get_insecure_registry_list(void);

char **conf_get_registry_list(void);
char *conf_get_isulad_native_umask(void);

char *conf_get_isulad_cgroup_parent(void);

char *conf_get_default_runtime(void);

char *conf_get_graph_check_flag_file(void);

bool conf_get_image_layer_check_flag(void);

int merge_json_confs_into_global(struct service_arguments *args);

bool conf_get_use_decrypted_key_flag(void);
bool conf_get_skip_insecure_verify_flag(void);
int parse_log_opts(struct service_arguments *args, const char *key, const char *value);

char *conf_get_isulad_monitor_fifo_path(void);

int init_isulad_daemon_constants(void);
isulad_daemon_constants *get_isulad_daemon_constants(void);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_CONFIG_ISULAD_CONFIG_H
