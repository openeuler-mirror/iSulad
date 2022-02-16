/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2017-11-22
 * Description: provide container client arguments definition
 ******************************************************************************/

#ifndef CMD_ISULA_CLIENT_ARGUMENTS_H
#define CMD_ISULA_CLIENT_ARGUMENTS_H

#include <stdbool.h>
#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <termios.h> // IWYU pragma: keep
#include <sys/ioctl.h>

#include "command_parser.h"
#include "isula_libutils/json_common.h"
#include "isula_connect.h"
#include "namespace.h"
#include "connect.h"

#ifdef __cplusplus
extern "C" {
#endif

/* max arguments can be specify in client */
#define MAX_CLIENT_ARGS 1000

struct client_arguments;
struct custom_configs;

struct custom_configs {
    /* environment variables */
    char **env;

    /* environment variables file */
    char **env_file;

    /* label */
    char **label;

    /* label file */
    char **label_file;

    /* hugepage limits */
    char **hugepage_limits;

    /* group add */
    char **group_add;

    /* hook-spec file */
    char *hook_spec;

    /* volumes-from container(s) */
    char **volumes_from;

    /* volumes to mount */
    char **volumes;

    /* mounts to attach a filesystem */
    char **mounts;

    /* mount tmpfs to container */
    char **tmpfs;

    /* pids limit */
    int64_t pids_limit;

    /* files limit */
    int64_t files_limit;

    /* shm size */
    int64_t shm_size;

    /* user and group */
    char *user;

    /* hostname */
    char *hostname;

    /* privileged */
    bool privileged;

    /* auto remove */
    bool auto_remove;

    /* readonly rootfs */
    bool readonly;

    /* alldevices */
    bool all_devices;

    /* system container */
    bool system_container;
    char *ns_change_opt;

    /* user remap */
    char *user_remap;

    /* cap add */
    char **cap_adds;

    /* cap drop */
    char **cap_drops;

    /* storage opts */
    char **storage_opts;

    /* sysctls */
    char **sysctls;

    /* extra hosts */
    char **extra_hosts;

    /* dns */
    char **dns;

    /* dns options */
    char **dns_options;

    /* dns search */
    char **dns_search;

    /* tty */
    bool tty;

    /* open stdin of container */
    bool open_stdin;

    /* attach stdin of container */
    bool attach_stdin;

    /* attach stdout of container */
    bool attach_stdout;

    /* attach stderr of container */
    bool attach_stderr;

    /* entrypoint */
    char *entrypoint;

    /* populate devices */
    char **devices;

    /* ulimit options */
    char **ulimits;

    /* blkio weight devices */
    char **weight_devices;

    /* namespace mode */
    char *share_ns[NAMESPACE_MAX];

    /* work dir */
    char *workdir;

    /* security opt */
    char **security;

    /* health cmd */
    char *health_cmd;

    /* health interval */
    int64_t health_interval;

    /* health retries */
    int health_retries;

    /* health timeout */
    int64_t health_timeout;

    /* health start period */
    int64_t health_start_period;

    /* no healthcheck */
    bool no_healthcheck;

    /* exit on unhealthy */
    bool exit_on_unhealthy;

    /* oom kill disable */
    bool oom_kill_disable;

    /* env target file */
    char *env_target_file;

    /* cgroup parent */
    char *cgroup_parent;

    /* device read bps */
    char **blkio_throttle_read_bps_device;

    /* device write bps */
    char **blkio_throttle_write_bps_device;

    /* device read iops */
    char **blkio_throttle_read_iops_device;

    /* device write iops */
    char **blkio_throttle_write_iops_device;

    /* device cgroup rules */
    char **device_cgroup_rules;

    /* Signal to stop a container */
    char *stop_signal;

#ifdef ENABLE_NATIVE_NETWORK
    /* network driver */
    char *driver;

    /* network gateway */
    char *gateway;

    /* container IP */
    char *ip;

    /* container MAC */
    char *mac_address;

    /* container ports exposed to host*/
    char **expose;

    /* publish all exposed container ports to random ports on host */
    bool publish_all;

    /* publish a container's port to the host */
    char **publish;
#endif
};

struct args_cgroup_resources {
    uint16_t blkio_weight;
    int64_t cpu_shares;
    int64_t cpu_period;
    int64_t cpu_quota;
    int64_t cpu_rt_period;
    int64_t cpu_rt_runtime;
    int64_t oom_score_adj;
    char *cpuset_cpus;
    char *cpuset_mems;
    int64_t memory_limit;
    int64_t memory_swap;
    int64_t memory_reservation;
    int64_t kernel_memory_limit;
    int64_t swappiness;
    int64_t nano_cpus;
};

struct client_arguments;

typedef int (*do_resize_call_back_t)(const struct client_arguments *args, unsigned int height, unsigned int width);

struct client_arguments {
    const char *progname; /* main progname name */
    const char *subcommand; /* sub command name */
    const struct option *options;

    // For common options
    char *name; /* container name */

    char *socket;

    char *runtime;

    char *restart;

    char *host_channel;

    bool help;

    // lcr create
    char *external_rootfs;
    char *create_rootfs;
    char *image_name;

    char *log_driver;

    /* notes: we should free the mem in custom_conf by hand */
    struct custom_configs custom_conf;

    // isula run;
    bool detach;

    // attach stdout/stderr
    bool attach;

    bool interactive;
    // stop/kill/delete
    bool force;
    int time;

    // delete
    bool volumes;

    // events
    char *since;
    char *until;

    // health check
    char *service;

    // list
    bool dispname;
    bool list_all;
    bool list_latest;
    /*
     * list_last_n < 0: invalid value list_last_n
     * list_last_n = 0: as the default value
     * list_last_n > 0: show number of containers set by list_last_n
     * */
    uint list_last_n;
    char **filters;
    bool no_trunc;

    // inspect
    char *format;

    // stats
    bool nostream;
    bool showall;
    bool original;

    // update
    struct args_cgroup_resources cr;

    // pull/rmi
    char *ref;
    bool plain_http;
    char *pull;

    // logs
    bool follow;
    bool timestamps;
    /*
     * tail < 0: show all logs
     * tail = 0: do not show log
     * tail > 0: show number of logs set by tail
     * */
    long long tail;

    // kill
    char *signal;

    // load
    char *file;
    char *type;
    char *tag;

    // exec
    char *exec_suffix;

    // login/logout
    char *username;
    char *password;
    char *server;
    bool password_stdin;

    /* extra environment variables used in exec */
    char **extra_env;

    // remaining arguments
    char * const *argv;
    int argc;

    // top
    char *ps_args;

    json_map_string_string *annotations;

    // gRPC tls config
    bool tls;
    bool tls_verify;
    char *ca_file;
    char *cert_file;
    char *key_file;

    do_resize_call_back_t resize_cb;
    struct winsize s_pre_wsz;

#ifdef ENABLE_NATIVE_NETWORK
    // network
    char *network_name;

    // network create
    char *driver;
    char *gateway;
    bool internal;
    char *subnet;

    // port command
    char *port;
#endif
};

#define LOG_OPTIONS(log) { CMD_OPT_TYPE_BOOL_FALSE, false, "debug", 'D', &(log).quiet, "Enable debug mode", NULL },

#define COMMON_OPTIONS(cmdargs)                                                                                         \
    { CMD_OPT_TYPE_STRING_DUP, false, "host", 'H', &(cmdargs).socket, "Daemon socket(s) to connect to",                 \
        command_valid_socket },                                                                                           \
    { CMD_OPT_TYPE_BOOL, false, "tls", 0, &(cmdargs).tls, "Use TLS; implied by --tlsverify", NULL },            \
    { CMD_OPT_TYPE_BOOL, false, "tlsverify", 0, &(cmdargs).tls_verify, "Use TLS and verify the remote", NULL }, \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                  \
      false,                                                                                                    \
      "tlscacert",                                                                                              \
      0,                                                                                                        \
      &(cmdargs).ca_file,                                                                                       \
      "Trust certs signed only by this CA (default \"/root/.iSulad/ca.pem\")",                                  \
      NULL },                                                                                                   \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                  \
      false,                                                                                                    \
      "tlscert",                                                                                                \
      0,                                                                                                        \
      &(cmdargs).cert_file,                                                                                     \
      "Path to TLS certificate file (default \"/root/.iSulad/cert.pem\")",                                      \
      NULL },                                                                                                   \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                  \
      false,                                                                                                    \
      "tlskey",                                                                                                 \
      0,                                                                                                        \
      &(cmdargs).key_file,                                                                                      \
      "Path to TLS key file (default \"/root/.iSulad/key.pem\")",                                               \
      NULL },                                                                                                   \
    { CMD_OPT_TYPE_BOOL, false, "help", 0, &(cmdargs).help, "Print usage", NULL },

#define VERSION_OPTIONS(cmdargs) \
    { CMD_OPT_TYPE_BOOL, false, "version", 0, NULL, "Print version information and quit", NULL },

extern void print_common_help();

extern int client_arguments_init(struct client_arguments *args);

extern void client_arguments_free(struct client_arguments *args);

extern void isulad_screen_print(uint32_t cc, uint32_t server_errono, struct client_arguments *args);

extern void client_print_error(uint32_t cc, uint32_t server_errono, const char *errmsg);

extern client_connect_config_t get_connect_config(const struct client_arguments *args);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_CLIENT_ARGUMENTS_H
