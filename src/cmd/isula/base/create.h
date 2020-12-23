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
 * Description: provide container create definition
 ******************************************************************************/
#ifndef CMD_ISULA_BASE_CREATE_H
#define CMD_ISULA_BASE_CREATE_H

#include <stdbool.h>
#include <stddef.h>

#include "client_arguments.h"
#include "command_parser.h"
#include "namespace.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CREATE_OPTIONS(cmdargs)                                                                                                                                   \
    {                                                                                                                                                             \
        CMD_OPT_TYPE_BOOL,                                                                                                                                        \
        false,                                                                                                                                                    \
        "read-only",                                                                                                                                              \
        0,                                                                                                                                                        \
        &(cmdargs).custom_conf.readonly,                                                                                                                          \
        "Make container rootfs readonly",                                                                                                                         \
        NULL                                                                                                                                                      \
    },                                                                                                                                                            \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "cap-add",                                                                                                                                          \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.cap_adds,                                                                                                                    \
      "Add Linux capabilities ('ALL' to add all capabilities)",                                                                                           \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "cap-drop",                                                                                                                                         \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.cap_drops,                                                                                                                   \
      "Drop Linux capabilities ('ALL' to drop all capabilities)",                                                                                         \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK, false, "cpu-shares", 0, &(cmdargs).cr.cpu_shares, "CPU shares (relative weight)",                                            \
      command_convert_llong },                                                                                                                            \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "cpu-period",                                                                                                                                       \
      0,                                                                                                                                                  \
      &(cmdargs).cr.cpu_period,                                                                                                                           \
      "Limit CPU CFS (Completely Fair Scheduler) period",                                                                                                 \
      command_convert_llong },                                                                                                                            \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "cpu-quota",                                                                                                                                        \
      0,                                                                                                                                                  \
      &(cmdargs).cr.cpu_quota,                                                                                                                            \
      "Limit CPU CFS (Completely Fair Scheduler) quota",                                                                                                  \
      command_convert_llong },                                                                                                                            \
    { CMD_OPT_TYPE_STRING,                                                                                                                                \
      false,                                                                                                                                              \
      "cpuset-cpus",                                                                                                                                      \
      0,                                                                                                                                                  \
      &(cmdargs).cr.cpuset_cpus,                                                                                                                          \
      "CPUs in which to allow execution (e.g. 0-3, 0,1)",                                                                                                 \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING,                                                                                                                                \
      false,                                                                                                                                              \
      "cpuset-mems",                                                                                                                                      \
      0,                                                                                                                                                  \
      &(cmdargs).cr.cpuset_mems,                                                                                                                          \
      "MEMs in which to allow execution (0-3, 0,1)",                                                                                                      \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "device-read-bps",                                                                                                                                  \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.blkio_throttle_read_bps_device,                                                                                              \
      "Limit read rate (bytes per second) from a device (default []),format: <device-path>:<number>[<unit>], Number is a positive integer",               \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "device-write-bps",                                                                                                                                 \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.blkio_throttle_write_bps_device,                                                                                             \
      "Limit write rate (bytes per second) to a device (default []),format: <device-path>:<number>[<unit>], Number is a positive integer",                \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "oom-score-adj",                                                                                                                                    \
      0,                                                                                                                                                  \
      &(cmdargs).cr.oom_score_adj,                                                                                                                        \
      "Tune host's OOM preferences (-1000 to 1000)",                                                                                                      \
      command_convert_llong },                                                                                                                            \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "device",                                                                                                                                           \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.devices,                                                                                                                     \
      "Add a host device to the container",                                                                                                               \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK, false, "env", 'e', &(cmdargs).custom_conf.env, "Set environment variables",                                                  \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "env-file",                                                                                                                                         \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.env_file,                                                                                                                    \
      "Read in a file of environment variables",                                                                                                          \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "label",                                                                                                                                            \
      'l',                                                                                                                                                \
      &(cmdargs).custom_conf.label,                                                                                                                       \
      "Set metadata on container (default [])",                                                                                                           \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "label-file",                                                                                                                                       \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.label_file,                                                                                                                  \
      "Read in a line delimited file of labels (default [])",                                                                                             \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                                                            \
      false,                                                                                                                                              \
      "entrypoint",                                                                                                                                       \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.entrypoint,                                                                                                                  \
      "Entrypoint to run when starting the container",                                                                                                    \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING,                                                                                                                                \
      false,                                                                                                                                              \
      "external-rootfs",                                                                                                                                  \
      0,                                                                                                                                                  \
      &(cmdargs).external_rootfs,                                                                                                                         \
      "Specify the custom rootfs that is not managed by isulad for the container, directory or block device",                                             \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "files-limit",                                                                                                                                      \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.files_limit,                                                                                                                 \
      "Tune container files limit (set -1 for unlimited)",                                                                                                \
      command_convert_llong },                                                                                                                            \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                                                            \
      false,                                                                                                                                              \
      "hook-spec",                                                                                                                                        \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.hook_spec,                                                                                                                   \
      "File containing hook definition(prestart, poststart, poststop)",                                                                                   \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP, false, "hostname", 'h', &(cmdargs).custom_conf.hostname,                                                                   \
      "Container host name",   NULL },                                                                                                                    \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "add-host",                                                                                                                                         \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.extra_hosts,                                                                                                                 \
      "Add a custom host-to-IP mapping (host:ip)",                                                                                                        \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK, false, "dns", 0, &(cmdargs).custom_conf.dns, "Set custom DNS servers",                                                       \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK, false, "dns-opt", 0, &(cmdargs).custom_conf.dns_options, "Set DNS options",                                                  \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "dns-search",                                                                                                                                       \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.dns_search,                                                                                                                  \
      "Set custom DNS search domains",                                                                                                                    \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_STRING,                                                                                                                                \
      false,                                                                                                                                              \
      "user-remap",                                                                                                                                       \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.user_remap,                                                                                                                  \
      "Set user remap for container",                                                                                                                     \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP, false, "ipc", 0, &(cmdargs).custom_conf.share_ns[NAMESPACE_IPC],                                                           \
      "IPC namespace to use",  NULL },                                                                                                                    \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "shm-size",                                                                                                                                         \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.shm_size,                                                                                                                    \
      "Size of /dev/shm, default value is 64MB",                                                                                                          \
      command_convert_membytes },                                                                                                                         \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "kernel-memory",                                                                                                                                    \
      0,                                                                                                                                                  \
      &(cmdargs).cr.kernel_memory_limit,                                                                                                                  \
      "Kernel memory limit",                                                                                                                              \
      command_convert_membytes },                                                                                                                         \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "hugetlb-limit",                                                                                                                                    \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.hugepage_limits,                                                                                                             \
      "Huge page limit (format: [size:]<limit>, e.g. --hugetlb-limit 2MB:32MB)",                                                                          \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "log-driver",                                                                                                                                       \
      0,                                                                                                                                                  \
      &(cmdargs),                                                                                                                                         \
      "Container log driver, support syslog and json-file",                                                                                               \
      callback_log_driver },                                                                                                                              \
    { CMD_OPT_TYPE_CALLBACK, false, "log-opt", 0, &(cmdargs), "Container log options, value formate: key=value",                                          \
      callback_log_opt },                                                                                                                                 \
    { CMD_OPT_TYPE_CALLBACK,   false, "memory", 'm', &(cmdargs).cr.memory_limit, "Memory limit",                                                          \
      command_convert_membytes },                                                                                                                         \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "memory-reservation",                                                                                                                               \
      0,                                                                                                                                                  \
      &(cmdargs).cr.memory_reservation,                                                                                                                   \
      "Memory soft limit",                                                                                                                                \
      command_convert_membytes },                                                                                                                         \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "memory-swap",                                                                                                                                      \
      0,                                                                                                                                                  \
      &(cmdargs).cr.memory_swap,                                                                                                                          \
      "Swap limit equal to memory plus swap: '-1' to enable unlimited swap",                                                                              \
      command_convert_memswapbytes },                                                                                                                     \
    { CMD_OPT_TYPE_CALLBACK,     false,                                                                                                                   \
      "memory-swappiness",       0,                                                                                                                       \
      &(cmdargs).cr.swappiness,  "Tune container memory swappiness (0 to 100) (default -1)",                                                              \
      command_convert_swappiness },                                                                                                                       \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "mount",                                                                                                                                            \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.mounts,                                                                                                                      \
      "Attach a filesystem mount to the service",                                                                                                         \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "group-add",                                                                                                                                        \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.group_add,                                                                                                                   \
      "Add additional groups to join",                                                                                                                    \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP, false, "name", 'n', &(cmdargs).name, "Name of the container", NULL },                                                      \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                                                            \
      false,                                                                                                                                              \
      "net",                                                                                                                                              \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.share_ns[NAMESPACE_NET],                                                                                                     \
      "Connect a container to a network",                                                                                                                 \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                                                            \
      false,                                                                                                                                              \
      "network",                                                                                                                                          \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.share_ns[NAMESPACE_NET],                                                                                                     \
      "Connect a container to a network",                                                                                                                 \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                                                            \
      false,                                                                                                                                              \
      "ip",                                                                                                                                               \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.ip,                                                                                                                          \
      "Specify a static IP address for container (e.g. 192.168.21.9)",                                                                                    \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                                                            \
      false,                                                                                                                                              \
      "mac-address",                                                                                                                                      \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.mac_address,                                                                                                                 \
      "Specify a MAC address for container (e.g. 9e:c7:76:04:9a:42)",                                                                                     \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP, false, "pid", 0, &(cmdargs).custom_conf.share_ns[NAMESPACE_PID],                                                           \
      "PID namespace to use",  NULL },                                                                                                                    \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "pids-limit",                                                                                                                                       \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.pids_limit,                                                                                                                  \
      "Tune container pids limit (set -1 for unlimited)",                                                                                                 \
      command_convert_llong },                                                                                                                            \
    { CMD_OPT_TYPE_BOOL,                                                                                                                                  \
      false,                                                                                                                                              \
      "privileged",                                                                                                                                       \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.privileged,                                                                                                                  \
      "Give extended privileges to this container",                                                                                                       \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING,                                                                                                                                \
      false,                                                                                                                                              \
      "pull",                                                                                                                                             \
      0,                                                                                                                                                  \
      &(cmdargs).pull,                                                                                                                                    \
      "Pull image before running (\"always\"|\"missing\"|\"never\") (default \"missing\")",                                                               \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK, false, "tmpfs", 0, &(cmdargs).custom_conf.tmpfs, "Mount a tmpfs directory",                                                 \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_BOOL, false, "tty", 't', &(cmdargs).custom_conf.tty, "Allocate a pseudo-TTY", NULL },                                                  \
    { CMD_OPT_TYPE_STRING,                                                                                                                                \
      false,                                                                                                                                              \
      "restart",                                                                                                                                          \
      0,                                                                                                                                                  \
      &(cmdargs).restart,                                                                                                                                 \
      "Restart policy to apply when a container exits(no, always, on-reboot, on-failure[:max-retries])",                                                  \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING,                                                                                                                                \
      false,                                                                                                                                              \
      "host-channel",                                                                                                                                     \
      0,                                                                                                                                                  \
      &(cmdargs).host_channel,                                                                                                                            \
      "Create share memory between host and container",                                                                                                   \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING,                                                                                                                                \
      false,                                                                                                                                              \
      "runtime",                                                                                                                                          \
      'R',                                                                                                                                                \
      &(cmdargs).runtime,                                                                                                                                 \
      "Runtime to use for containers(default: lcr)",                                                                                                      \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                                                            \
      false,                                                                                                                                              \
      "user",                                                                                                                                             \
      'u',                                                                                                                                                \
      &(cmdargs).custom_conf.user,                                                                                                                        \
      "Username or UID (format: <name|uid>[:<group|gid>])",                                                                                               \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP, false, "uts", 0, &(cmdargs).custom_conf.share_ns[NAMESPACE_UTS],                                                           \
      "UTS namespace to use",  NULL },                                                                                                                    \
    { CMD_OPT_TYPE_CALLBACK, false, "volume", 'v', &(cmdargs).custom_conf.volumes, "Bind mount a volume",                                                 \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "volumes-from",                                                                                                                                     \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.volumes_from,                                                                                                                \
      "Mount volumes from the specified container(s)",                                                                                                    \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK, false, "annotation", 0, &(cmdargs), "Set annotations on a container",                                                        \
      callback_annotation },                                                                                                                              \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                                                            \
      false,                                                                                                                                              \
      "workdir",                                                                                                                                          \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.workdir,                                                                                                                     \
      "Working directory inside the container",                                                                                                           \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_BOOL,                                                                                                                                  \
      false,                                                                                                                                              \
      "system-container",                                                                                                                                 \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.system_container,                                                                                                            \
      "Extend some features only needed by running system container",                                                                                     \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_BOOL,    false, "oom-kill-disable", 0, &(cmdargs).custom_conf.oom_kill_disable,                                                        \
      "Disable OOM Killer", NULL },                                                                                                                       \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "security-opt",                                                                                                                                     \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.security,                                                                                                                    \
      "Security Options (default [])",                                                                                                                    \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "storage-opt",                                                                                                                                      \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.storage_opts,                                                                                                                \
      "Storage driver options for the container",                                                                                                         \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP,          false, "health-cmd", 0, &(cmdargs).custom_conf.health_cmd,                                                        \
      "Command to run to check health", NULL },                                                                                                           \
    { CMD_OPT_TYPE_CALLBACK, false, "sysctl", 0, &(cmdargs).custom_conf.sysctls, "Sysctl options",                                                        \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                                                            \
      false,                                                                                                                                              \
      "env-target-file",                                                                                                                                  \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.env_target_file,                                                                                                             \
      "Export env to target file path in rootfs",                                                                                                         \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                                                            \
      false,                                                                                                                                              \
      "cgroup-parent",                                                                                                                                    \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.cgroup_parent,                                                                                                               \
      "Optional parent cgroup for the container",                                                                                                         \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "health-interval",                                                                                                                                  \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.health_interval,                                                                                                             \
      "Time between running the check (ms|s|m|h) (default 30s)",                                                                                          \
      command_convert_nanoseconds },                                                                                                                      \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "health-retries",                                                                                                                                   \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.health_retries,                                                                                                              \
      "Consecutive failures needed to report unhealthy (default 3)",                                                                                      \
      command_convert_int },                                                                                                                              \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "health-timeout",                                                                                                                                   \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.health_timeout,                                                                                                              \
      "Maximum time to allow one check to run (ms|s|m|h) (default 30s)",                                                                                  \
      command_convert_nanoseconds },                                                                                                                      \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "health-start-period",                                                                                                                              \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.health_start_period,                                                                                                         \
      "Start period for the container to initialize before starting health-retries countdown (ms|s|m|h) "                                                 \
      "(default 0s)",                                                                                                                                     \
      command_convert_nanoseconds },                                                                                                                      \
    { CMD_OPT_TYPE_BOOL,                                                                                                                                  \
      false,                                                                                                                                              \
      "no-healthcheck",                                                                                                                                   \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.no_healthcheck,                                                                                                              \
      "Disable any container-specified HEALTHCHECK",                                                                                                      \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_BOOL,                                                                                                                                  \
      false,                                                                                                                                              \
      "health-exit-on-unhealthy",                                                                                                                         \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.exit_on_unhealthy,                                                                                                           \
      "Kill the container when it is detected to be unhealthy",                                                                                           \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING,                                                                                                                                \
      false,                                                                                                                                              \
      "ns-change-opt",                                                                                                                                    \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.ns_change_opt,                                                                                                               \
      "Namespaced kernel param options for system container (default [])",                                                                                \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK, false, "ulimit", 0, &(cmdargs).custom_conf.ulimits, "Ulimit options (default [])",                                           \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "blkio-weight",                                                                                                                                     \
      0,                                                                                                                                                  \
      &(cmdargs).cr.blkio_weight,                                                                                                                         \
      "Block IO (relative weight), between 10 and 1000, or 0 to disable (default 0)",                                                                     \
      command_convert_u16 },                                                                                                                              \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "blkio-weight-device",                                                                                                                              \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.weight_devices,                                                                                                              \
      "Block IO weight (relative device weight) (default []), format: DEVICE_NAME:WEIGHT, weight value between 10 and 1000, or 0 to disable (default 0)", \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "device-read-iops",                                                                                                                                 \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.blkio_throttle_read_iops_device,                                                                                             \
      "Limit read rate (IO per second) from a device (format: <device-path>:<number>),number is unsigned 64 bytes integer",                               \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "device-write-iops",                                                                                                                                \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.blkio_throttle_write_iops_device,                                                                                            \
      "Limit write rate (IO per second) to a device (format: <device-path>:<number>),number is unsigned 64 bytes integer.",                               \
      command_append_array },                                                                                                                             \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "cpu-rt-period",                                                                                                                                    \
      0,                                                                                                                                                  \
      &((cmdargs).cr).cpu_rt_period,                                                                                                                      \
      "Limit CPU real-time period in microseconds.",                                                                                                      \
      command_convert_llong },                                                                                                                            \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "cpu-rt-runtime",                                                                                                                                   \
      0,                                                                                                                                                  \
      &((cmdargs).cr).cpu_rt_runtime,                                                                                                                     \
      "Limit CPU real-time runtime in microseconds.",                                                                                                     \
      command_convert_llong },                                                                                                                            \
    { CMD_OPT_TYPE_CALLBACK,   false, "cpus", 0, &((cmdargs).cr).nano_cpus, "Number of CPUs.",                                                            \
      command_convert_nanocpus },                                                                                                                         \
    { CMD_OPT_TYPE_CALLBACK,                                                                                                                              \
      false,                                                                                                                                              \
      "device-cgroup-rule",                                                                                                                               \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.device_cgroup_rules,                                                                                                         \
      "Add a rule to the cgroup allowed devices list.",                                                                                                   \
      command_convert_device_cgroup_rules },                                                                                                              \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                                                            \
      false,                                                                                                                                              \
      "stop-signal",                                                                                                                                      \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.stop_signal,                                                                                                                 \
      "Signal to stop a container (default \"SIGTERM\")",                                                                                                 \
      NULL },                                                                                                                                             \
    { CMD_OPT_TYPE_STRING_DUP,                                                                                                                            \
      false,                                                                                                                                              \
      "userns",                                                                                                                                           \
      0,                                                                                                                                                  \
      &(cmdargs).custom_conf.share_ns[NAMESPACE_USER],                                                                                                    \
      "Set the usernamespace mode for the container when `userns-remap` option is enabled.",                                                              \
      NULL },

#define CREATE_EXTEND_OPTIONS(cmdargs)        \
    { CMD_OPT_TYPE_BOOL,                      \
        false,                                  \
        "interactive",                          \
        'i',                                    \
        &(cmdargs).custom_conf.open_stdin,      \
        "Keep STDIN open even if not attached", \
        NULL },

extern const char g_cmd_create_desc[];
extern const char g_cmd_create_usage[];
extern struct client_arguments g_cmd_create_args;

int create_parser(struct client_arguments *args, int c, char *arg);

int create_checker(struct client_arguments *args);

int client_create(struct client_arguments *args);

int callback_log_driver(command_option_t *option, const char *value);

int callback_log_opt(command_option_t *option, const char *value);

int callback_annotation(command_option_t *option, const char *value);

int cmd_create_main(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_BASE_CREATE_H
