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
 * Description: provide container commands definition
 ******************************************************************************/
#ifndef CMD_ISULAD_ISULAD_COMMANDS_H
#define CMD_ISULAD_ISULAD_COMMANDS_H
#include <isula_libutils/isulad_daemon_configs.h>
#include <stdbool.h>
#include <stddef.h>

#include "daemon_arguments.h"
#include "command_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

void print_common_help(void);
void print_version(void);

// Default help command if implementation doesn't prvide one
int command_default_help(const char * const program_name, int argc, char **argv);
int command_isulad_valid_socket(command_option_t *option, const char *arg);
int parse_args(struct service_arguments *args, int argc, const char **argv);
int check_args(struct service_arguments *args);
int update_hosts(struct service_arguments *args);
int update_default_ulimit(struct service_arguments *args);
int command_default_ulimit_append(command_option_t *option, const char *arg);


#ifdef ENABLE_SUP_GROUPS
#define SUP_GROUPS_OPT(cmdargs)                                                                                   \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
      false,                                                                                                      \
      "sup-groups",                                                                                               \
      0,                                                                                                          \
      (cmdargs)->json_confs,                                                                                      \
      "Set the supplementary group IDs for isulad, can be specified multiple times",                              \
      command_append_sup_groups },                                                                                \

#else
#define SUP_GROUPS_OPT(cmdargs)
#endif

#if (defined GRPC_CONNECTOR) && (defined ENABLE_METRICS)
#define METRICS_PORT_OPT(cmdargs)                                                                                 \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
        false, "metrics-port", 0, &(cmdargs)->json_confs->metrics_port,                                           \
        "The metric service listening port (default 9090)",                                                       \
        command_convert_uint                                                                                      \
    },                                                                                                            \

#else
#define METRICS_PORT_OPT(cmdargs)
#endif

#ifdef ENABLE_USERNS_REMAP
#define USERNS_REMAP_OPT(cmdargs)                                                                                 \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
        false,                                                                                                    \
        "userns-remap",                                                                                           \
        0,                                                                                                        \
        &(cmdargs)->json_confs->userns_remap,                                                                     \
        "User/Group setting for user namespaces",                                                                 \
        NULL },                                                                                                   \

#else
#define USERNS_REMAP_OPT(cmdargs)
#endif

#ifdef ENABLE_PLUGIN
#define PLUGINS_OPT(cmdargs)                                                                                \
    { CMD_OPT_TYPE_STRING_DUP,                                                                              \
      false, "enable-plugins", 0, &(cmdargs)->json_confs->enable_plugins,                                   \
      "Enable plugins for all containers", NULL                                                             \
    }, 
#else
#define PLUGINS_OPT(cmdargs)
#endif

#ifdef ENABLE_GRPC_REMOTE_CONNECT
#define ISULAD_TLS_OPTIONS(cmdargs)                                                                               \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "authorization-plugin",                                                                                     \
      0,                                                                                                          \
      &(cmdargs)->json_confs->authorization_plugin,                                                               \
      "Use authorization plugin",                                                                                 \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_BOOL, false, "tls", 0, &(cmdargs)->json_confs->tls, "Use TLS; implied by --tlsverify", NULL }, \
    { CMD_OPT_TYPE_BOOL,                                                                                          \
      false,                                                                                                      \
      "tlsverify",                                                                                                \
      0,                                                                                                          \
      &(cmdargs)->json_confs->tls_verify,                                                                         \
      "Use TLS and verify the remote",                                                                            \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "tlscacert",                                                                                                \
      0,                                                                                                          \
      &(cmdargs)->json_confs->tls_config->ca_file,                                                                \
      "Trust certs signed only by this CA (default \"/root/.iSulad/ca.pem\")",                                    \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "tlscert",                                                                                                  \
      0,                                                                                                          \
      &(cmdargs)->json_confs->tls_config->cert_file,                                                              \
      "Path to TLS certificate file (default \"/root/.iSulad/cert.pem\")",                                        \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "tlskey",                                                                                                   \
      0,                                                                                                          \
      &(cmdargs)->json_confs->tls_config->key_file,                                                               \
      "Path to TLS key file (default \"/root/.iSulad/key.pem\")",                                                 \
      NULL },
#else
#define ISULAD_TLS_OPTIONS(cmdargs)
#endif

#define ISULAD_OPTIONS(cmdargs)                                                                                   \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
        false,                                                                                                    \
        "host",                                                                                                   \
        'H',                                                                                                      \
        &(cmdargs)->hosts,                                                                                        \
        "The socket name used to create gRPC server (default \"unix:///var/run/isulad.sock\")",                   \
        command_valid_socket_append_array },                                                                      \
    { CMD_OPT_TYPE_STRING_DUP,   false, "pidfile", 'p', &(cmdargs)->json_confs->pidfile,                          \
      "Save pid into this file (default \"/var/run/isulad.pid\")", NULL },                                        \
    { CMD_OPT_TYPE_BOOL, false, "help", 0, &(cmdargs)->help, "Show help", NULL },                                 \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "hook-spec",                                                                                                \
      0,                                                                                                          \
      &(cmdargs)->json_confs->hook_spec,                                                                          \
      "Default hook spec file applied to all containers",                                                         \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "graph",                                                                                                    \
      'g',                                                                                                        \
      &(cmdargs)->json_confs->graph,                                                                              \
      "Root directory of the iSulad runtime (default \"/var/lib/isulad\")",                                       \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "state",                                                                                                    \
      'S',                                                                                                        \
      &(cmdargs)->json_confs->state,                                                                              \
      "Root directory for execution state files (default \"/var/run/isulad\")",                                   \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "start-timeout",                                                                                            \
      0,                                                                                                          \
      &(cmdargs)->json_confs->start_timeout,                                                                      \
      "timeout duration for waiting on a container to start before it is killed",                                 \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "log-level",                                                                                                \
      'l',                                                                                                        \
      &(cmdargs)->json_confs->log_level,                                                                          \
      "Set log level, the levels can be: FATAL ALERT CRIT ERROR WARN NOTICE INFO DEBUG TRACE (default INFO)",     \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "log-driver",                                                                                               \
      0,                                                                                                          \
      &(cmdargs)->json_confs->log_driver,                                                                         \
      "Set daemon log driver, support stdout and file (default file)",                                            \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
      false,                                                                                                      \
      "log-opt",                                                                                                  \
      0,                                                                                                          \
      (cmdargs),                                                                                                  \
      "Set daemon log driver options, such as: log-path=/tmp/logs/ to set directory where to store daemon logs",  \
      server_callback_log_opt },                                                                                  \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
      false,                                                                                                      \
      "container-log-driver",                                                                                     \
      0,                                                                                                          \
      (cmdargs),                                                                                                  \
      "Set default container log driver, such as: json-file",                                                     \
      server_callback_container_log_driver },                                                                     \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
      false,                                                                                                      \
      "container-log-opts",                                                                                       \
      0,                                                                                                          \
      (cmdargs),                                                                                                  \
      "Set default container log driver options, such as: max-file=7 to set max number of container log files",   \
      server_callback_container_log },                                                                            \
    { CMD_OPT_TYPE_BOOL, false, "version", 'V', &(cmdargs)->version, "Print the version", NULL },                 \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "group",                                                                                                    \
      'G',                                                                                                        \
      &(cmdargs)->json_confs->group,                                                                              \
      "Group for the unix socket (default isula)",                                                                \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "storage-driver",                                                                                           \
      0,                                                                                                          \
      &(cmdargs)->json_confs->storage_driver,                                                                     \
      "Storage driver to use (default overlay2)",                                                                 \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
      false,                                                                                                      \
      "storage-opt",                                                                                              \
      's',                                                                                                        \
      &(cmdargs)->json_confs->storage_opts,                                                                       \
      "Storage driver options",                                                                                   \
      command_append_array },                                                                                     \
    { CMD_OPT_TYPE_BOOL, false, "systemd-cgroup", 0, &(cmdargs)->json_confs->systemd_cgroup,                      \
      "Use systemd cgroup driver(default false)", NULL },                                                         \
    SUP_GROUPS_OPT(cmdargs)                                                                                       \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
      false,                                                                                                      \
      "registry-mirrors",                                                                                         \
      0,                                                                                                          \
      &(cmdargs)->json_confs->registry_mirrors,                                                                   \
      "Registry to be prepended when pulling unqualified images, can be specified multiple times",                \
      command_append_array },                                                                                     \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
      false,                                                                                                      \
      "insecure-registry",                                                                                        \
      0,                                                                                                          \
      &(cmdargs)->json_confs->insecure_registries,                                                                \
      "Disable TLS verification for the given registry",                                                          \
      command_append_array },                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "native.umask",                                                                                             \
      0,                                                                                                          \
      &(cmdargs)->json_confs->native_umask,                                                                       \
      "Default file mode creation mask (umask) for containers",                                                   \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "cgroup-parent",                                                                                            \
      0,                                                                                                          \
      &(cmdargs)->json_confs->cgroup_parent,                                                                      \
      "Set parent cgroup for all containers",                                                                     \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "pod-sandbox-image",                                                                                        \
      0,                                                                                                          \
      &(cmdargs)->json_confs->pod_sandbox_image,                                                                  \
      "The image whose network/ipc namespaces containers in each pod will use (default \"pause-${machine}:3.0\")",\
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "network-plugin",                                                                                           \
      0,                                                                                                          \
      &(cmdargs)->json_confs->network_plugin,                                                                     \
      "Set network plugin, suppport null and cni (default null)",                                                 \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "cni-bin-dir",                                                                                              \
      0,                                                                                                          \
      &(cmdargs)->json_confs->cni_bin_dir,                                                                        \
      "The full path of the directory in which to search for CNI plugin binaries (default \"/opt/cni/bin\")",     \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false,                                                                                                      \
      "cni-conf-dir",                                                                                             \
      0,                                                                                                          \
      &(cmdargs)->json_confs->cni_conf_dir,                                                                       \
      "The full path of the directory in which to search for CNI config files (default \"/etc/cni/net.d\")",      \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_BOOL,                                                                                          \
      false,                                                                                                      \
      "image-layer-check",                                                                                        \
      0,                                                                                                          \
      &(cmdargs)->json_confs->image_layer_check,                                                                  \
      "Check layer intergrity when needed",                                                                       \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_BOOL,                                                                                          \
      false,                                                                                                      \
      "insecure-skip-verify-enforce",                                                                             \
      0,                                                                                                          \
      &(cmdargs)->json_confs->insecure_skip_verify_enforce,                                                       \
      "Force to skip the insecure verify (default false)",                                                        \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_BOOL,                                                                                          \
      false,                                                                                                      \
      "use-decrypted-key",                                                                                        \
      0,                                                                                                          \
      (cmdargs)->json_confs->use_decrypted_key,                                                                   \
      "Use decrypted private key by default (default true)",                                                      \
      NULL },                                                                                                     \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
      false,                                                                                                      \
      "default-ulimit",                                                                                           \
      0,                                                                                                          \
      &(cmdargs)->default_ulimit,                                                                                 \
      "Default ulimits for containers (default [])",                                                              \
      command_default_ulimit_append },                                                                            \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
      false,                                                                                                      \
      "websocket-server-listening-port",                                                                          \
      0,                                                                                                          \
      &(cmdargs)->json_confs->websocket_server_listening_port,                                                    \
      "CRI websocket streaming service listening port (default 10350)",                                           \
      command_convert_uint },                                                                                     \
    METRICS_PORT_OPT(cmdargs)                                                                                     \
    USERNS_REMAP_OPT(cmdargs)                                                                                     \
    { CMD_OPT_TYPE_BOOL,                                                                                          \
        false, "selinux-enabled", 0, &(cmdargs)->json_confs->selinux_enabled,                                     \
        "Enable selinux support", NULL                                                                            \
    },                                                                                                            \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                    \
      false, "default-runtime", 0, &(cmdargs)->json_confs->default_runtime,                                       \
      "Default container runtime (default runc)", NULL                                                             \
    },                                                                                                            \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
      false, "cpu-rt-period", 0, &(cmdargs)->json_confs->cpu_rt_period,                                           \
      "Limit CPU real-time period in microseconds for all containers", command_convert_llong                      \
    },                                                                                                            \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
      false, "cpu-rt-runtime", 0, &(cmdargs)->json_confs->cpu_rt_runtime,                                         \
      "Limit CPU real-time runtime in microseconds for all containers", command_convert_llong                     \
    },                                                                                                            \
    PLUGINS_OPT(cmdargs)                                                                                          \
    { CMD_OPT_TYPE_CALLBACK,                                                                                      \
      false, "cri-runtime", 0, (cmdargs),                                                                         \
      "CRI runtime class transform", server_callback_cri_runtime                                                  \
    },                                                                                                            \

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULAD_ISULAD_COMMANDS_H
