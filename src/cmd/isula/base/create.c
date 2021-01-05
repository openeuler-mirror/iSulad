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
 * Description: provide container create functions
 ******************************************************************************/
#include "create.h"
#include <stdio_ext.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <isula_libutils/json_common.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "namespace.h"
#include "error.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_string.h"
#include "isula_connect.h"
#include "path.h"
#include "pull.h"
#include "constants.h"
#include "connect.h"
#include "opt_log.h"

#include "utils_array.h"
#include "utils_convert.h"
#include "utils_file.h"
#include "utils_verify.h"
#include "isula_container_spec.h"
#include "isula_host_spec.h"
#include "utils_mount_spec.h"
#include "utils_network.h"
#include "utils_port.h"

const char g_cmd_create_desc[] = "Create a new container";
const char g_cmd_create_usage[] = "create [OPTIONS] --external-rootfs=PATH|IMAGE [COMMAND] [ARG...]";

struct client_arguments g_cmd_create_args = {
    .runtime = "",
    .restart = "no",
    .cr.oom_score_adj = 0,
    .custom_conf.health_interval = 0,
    .custom_conf.health_timeout = 0,
    .custom_conf.health_start_period = 0,
    .custom_conf.health_retries = 0,
    .pull = "missing"
};

static void request_pack_host_config_limit(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* pids limit */
    if (args->custom_conf.pids_limit != 0) {
        hostconfig->cr->pids_limit = args->custom_conf.pids_limit;
    }
    /* files limit */
    if (args->custom_conf.files_limit != 0) {
        hostconfig->cr->files_limit = args->custom_conf.files_limit;
    }
}

static int request_pack_host_config_storage_opts(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    size_t i = 0;
    size_t len = 0;

    if (args->custom_conf.storage_opts == NULL) {
        return 0;
    }

    hostconfig->storage_opts = util_common_calloc_s(sizeof(json_map_string_string));
    if (hostconfig->storage_opts == NULL) {
        COMMAND_ERROR("Out of memory");
        return -1;
    }

    len = util_array_len((const char **)(args->custom_conf.storage_opts));
    for (i = 0; i < len; i++) {
        char *p = NULL;
        p = strchr(args->custom_conf.storage_opts[i], '=');
        if (p != NULL) {
            *p = '\0';
            if (append_json_map_string_string(hostconfig->storage_opts, args->custom_conf.storage_opts[i], p + 1)) {
                COMMAND_ERROR("Failed to append map");
                *p = '=';
                return -1;
            }
            *p = '=';
        } else {
            COMMAND_ERROR("Invalid storage option '%s'", args->custom_conf.storage_opts[i]);
            return -1;
        }
    }
    return 0;
}

static int request_pack_host_config_sysctls(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    size_t i = 0;
    size_t len = 0;

    if (args->custom_conf.sysctls == NULL) {
        return 0;
    }

    hostconfig->sysctls = util_common_calloc_s(sizeof(json_map_string_string));
    if (hostconfig->sysctls == NULL) {
        COMMAND_ERROR("Out of memory");
        return -1;
    }

    len = util_array_len((const char **)(args->custom_conf.sysctls));
    for (i = 0; i < len; i++) {
        char *p = NULL;
        p = strchr(args->custom_conf.sysctls[i], '=');
        if (p != NULL) {
            *p = '\0';
            if (append_json_map_string_string(hostconfig->sysctls, args->custom_conf.sysctls[i], p + 1)) {
                COMMAND_ERROR("Failed to append map");
                *p = '=';
                return -1;
            }
            *p = '=';
        }
    }
    return 0;
}

static int request_pack_host_config_cgroup(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    if (args == NULL) {
        return -1;
    }

    hostconfig->cr = util_common_calloc_s(sizeof(container_cgroup_resources_t));
    if (hostconfig->cr == NULL) {
        COMMAND_ERROR("Memory out");
        return -1;
    }

    /* blkio weight */
    hostconfig->cr->blkio_weight = args->cr.blkio_weight;

    /* nano cpus */
    hostconfig->cr->nano_cpus = args->cr.nano_cpus;

    /* cpu shares */
    hostconfig->cr->cpu_shares = args->cr.cpu_shares;

    /* cpu period */
    hostconfig->cr->cpu_period = args->cr.cpu_period;

    /* cpu quota */
    hostconfig->cr->cpu_quota = args->cr.cpu_quota;

    /* cpu realtime period */
    hostconfig->cr->cpu_realtime_period = args->cr.cpu_rt_period;

    /* cpu realtime runtime */
    hostconfig->cr->cpu_realtime_runtime = args->cr.cpu_rt_runtime;

    /* cpuset-cpus */
    hostconfig->cr->cpuset_cpus = util_strdup_s(args->cr.cpuset_cpus);

    /* cpuset memory */
    hostconfig->cr->cpuset_mems = util_strdup_s(args->cr.cpuset_mems);

    /* oom_score_adj */
    hostconfig->cr->oom_score_adj = args->cr.oom_score_adj;

    /* Memory limit */
    hostconfig->cr->memory = args->cr.memory_limit;

    /* memory swap */
    hostconfig->cr->memory_swap = args->cr.memory_swap;

    /* memory reservation */
    hostconfig->cr->memory_reservation = args->cr.memory_reservation;

    /* kernel memory limit */
    hostconfig->cr->kernel_memory = args->cr.kernel_memory_limit;

    hostconfig->cr->swappiness = args->cr.swappiness;

    request_pack_host_config_limit(args, hostconfig);

    return 0;
}

static int request_pack_custom_env(const struct client_arguments *args, isula_container_config_t *conf)
{
    int ret = 0;
    char *pe = NULL;
    char *new_env = NULL;

    if (args->custom_conf.env != NULL) {
        size_t i;
        for (i = 0; i < util_array_len((const char **)(args->custom_conf.env)); i++) {
            if (util_valid_env(args->custom_conf.env[i], &new_env) != 0) {
                COMMAND_ERROR("Invalid environment %s", args->custom_conf.env[i]);
                ret = -1;
                goto out;
            }
            if (new_env == NULL) {
                continue;
            }
            if (util_array_append(&conf->env, new_env) != 0) {
                COMMAND_ERROR("Failed to append custom config env list %s", new_env);
                ret = -1;
                goto out;
            }
            free(new_env);
            new_env = NULL;
        }
        conf->env_len = util_array_len((const char **)(conf->env));
    }

out:
    free(pe);
    free(new_env);
    return ret;
}

static int read_env_from_file(const char *path, size_t file_size, isula_container_config_t *conf)
{
    int ret = 0;
    FILE *fp = NULL;
    char *buf = NULL;
    char *new_env = NULL;

    if (file_size == 0) {
        return 0;
    }
    fp = util_fopen(path, "r");
    if (fp == NULL) {
        ERROR("Failed to open '%s'", path);
        return -1;
    }
    buf = (char *)util_common_calloc_s(file_size + 1);
    if (buf == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    while (fgets(buf, (int)file_size + 1, fp) != NULL) {
        size_t len = strlen(buf);
        if (len == 1) {
            continue;
        }
        buf[len - 1] = '\0';
        if (util_valid_env(buf, &new_env) != 0) {
            ret = -1;
            goto out;
        }
        if (new_env == NULL) {
            continue;
        }
        if (util_array_append(&conf->env, new_env) != 0) {
            ERROR("Failed to append environment variable");
            ret = -1;
            goto out;
        }
        free(new_env);
        new_env = NULL;
    }

out:
    fclose(fp);
    free(buf);
    free(new_env);
    return ret;
}

static int append_env_variables_to_conf(const char *env_file, isula_container_config_t *conf)
{
    int ret = 0;
    size_t file_size;

    if (!util_file_exists(env_file)) {
        COMMAND_ERROR("env file not exists: %s", env_file);
        ret = -1;
        goto out;
    }
    file_size = util_file_size(env_file);
    if (file_size > REGULAR_FILE_SIZE) {
        COMMAND_ERROR("env file '%s', size exceed limit: %lld", env_file, REGULAR_FILE_SIZE);
        ret = -1;
        goto out;
    }

    if (read_env_from_file(env_file, file_size, conf) != 0) {
        COMMAND_ERROR("failed to read env from file: %s", env_file);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int request_pack_custom_env_file(const struct client_arguments *args, isula_container_config_t *conf)
{
    int ret = 0;
    size_t i;
    char **env_files = args->custom_conf.env_file;
    size_t env_files_size = util_array_len((const char **)env_files);
    if (env_files_size == 0) {
        return 0;
    }

    for (i = 0; i < env_files_size; i++) {
        if (append_env_variables_to_conf(env_files[i], conf) != 0) {
            ret = -1;
            goto out;
        }
    }
    conf->env_len = util_array_len((const char **)(conf->env));

out:
    return ret;
}

static bool validate_label(const char *label)
{
    bool ret = true;
    char **arr = util_string_split_n(label, '=', 2);
    if (arr == NULL) {
        ERROR("Failed to split label string");
        ret = false;
        goto out;
    }

    if (strlen(arr[0]) == 0) {
        ERROR("Invalid label: %s, empty name", label);
        ret = false;
        goto out;
    }

out:
    util_free_array(arr);
    return ret;
}

static int request_pack_custom_label(const struct client_arguments *args, isula_container_config_t *conf)
{
    int ret = 0;
    size_t i;

    if (args->custom_conf.label == NULL) {
        return 0;
    }

    for (i = 0; i < util_array_len((const char **)(args->custom_conf.label)); i++) {
        if (!validate_label(args->custom_conf.label[i])) {
            COMMAND_ERROR("Invalid label '%s': empty name", args->custom_conf.label[i]);
            ret = -1;
            goto out;
        }
        if (util_array_append(&conf->label, args->custom_conf.label[i]) != 0) {
            COMMAND_ERROR("Failed to append custom config label list");
            ret = -1;
            goto out;
        }
    }
    conf->label_len = util_array_len((const char **)(conf->label));

out:
    return ret;
}

static int read_label_from_file(const char *path, size_t file_size, isula_container_config_t *conf)
{
    int ret = 0;
    FILE *fp = NULL;
    char *buf = NULL;
    size_t len;

    if (file_size == 0) {
        return 0;
    }
    fp = fopen(path, "re");
    if (fp == NULL) {
        ERROR("Failed to open '%s'", path);
        return -1;
    }
    __fsetlocking(fp, FSETLOCKING_BYCALLER);
    while (getline(&buf, &len, fp) != -1) {
        if (strlen(util_trim_space(buf)) == 0) {
            continue;
        }
        if (!validate_label(buf)) {
            COMMAND_ERROR("Invalid label '%s': empty name", buf);
            ret = -1;
            goto out;
        }
        if (util_array_append(&conf->label, buf) != 0) {
            ERROR("Failed to append label");
            ret = -1;
            goto out;
        }
    }

out:
    free(buf);
    fclose(fp);
    return ret;
}

static int append_labels_to_conf(const char *label_file, isula_container_config_t *conf)
{
    int ret = 0;
    size_t file_size;

    if (!util_file_exists(label_file)) {
        COMMAND_ERROR("label file not exists: %s", label_file);
        ret = -1;
        goto out;
    }
    file_size = util_file_size(label_file);
    if (file_size > REGULAR_FILE_SIZE) {
        COMMAND_ERROR("label file '%s', size exceed limit: %lld", label_file, REGULAR_FILE_SIZE);
        ret = -1;
        goto out;
    }

    if (read_label_from_file(label_file, file_size, conf) != 0) {
        COMMAND_ERROR("failed to read label from file: %s", label_file);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int request_pack_custom_label_file(const struct client_arguments *args, isula_container_config_t *conf)
{
    int ret = 0;
    size_t i;
    char **label_files = args->custom_conf.label_file;
    size_t label_files_size = util_array_len((const char **)label_files);
    if (label_files_size == 0) {
        return 0;
    }

    for (i = 0; i < label_files_size; i++) {
        if (append_labels_to_conf(label_files[i], conf) != 0) {
            ret = -1;
            goto out;
        }
    }
    conf->label_len = util_array_len((const char **)(conf->label));

out:
    return ret;
}

static void request_pack_custom_user(const struct client_arguments *args, isula_container_config_t *conf)
{
    if (args->custom_conf.user != NULL) {
        conf->user = util_strdup_s(args->custom_conf.user);
    }

    return;
}

static void request_pack_custom_hostname(const struct client_arguments *args, isula_container_config_t *conf)
{
    if (args->custom_conf.hostname != NULL) {
        conf->hostname = util_strdup_s(args->custom_conf.hostname);
    }

    return;
}

static void request_pack_custom_all_devices(const struct client_arguments *args, isula_container_config_t *conf)
{
    /* alldevices */
    if (args->custom_conf.all_devices) {
        conf->all_devices = true;
    }
    return;
}

static void request_pack_custom_system_container(const struct client_arguments *args, isula_container_config_t *conf)
{
    if (args->custom_conf.system_container) {
        conf->system_container = true;
    }

    /* ns change opt */
    if (!args->custom_conf.privileged) {
        if (args->custom_conf.ns_change_opt != NULL) {
            conf->ns_change_opt = util_strdup_s(args->custom_conf.ns_change_opt);
        }
    }

    return;
}

static void request_pack_custom_entrypoint(const struct client_arguments *args, isula_container_config_t *conf)
{
    if (args->custom_conf.entrypoint != NULL) {
        conf->entrypoint = util_strdup_s(args->custom_conf.entrypoint);
    }

    return;
}

static int request_pack_custom_args(const struct client_arguments *args, isula_container_config_t *conf)
{
    if (args->argc == 0) {
        return 0;
    }

    if (util_dup_array_of_strings((const char **)args->argv, args->argc, &conf->cmd, &conf->cmd_len) != 0) {
        COMMAND_ERROR("Failed to dup command");
        return -1;
    }

    return 0;
}

static void request_pack_custom_log_options(const struct client_arguments *args, isula_container_config_t *conf)
{
    conf->log_driver = util_strdup_s(args->log_driver);
}

static void request_pack_custom_work_dir(const struct client_arguments *args, isula_container_config_t *conf)
{
    /* work dir in container */
    if (args->custom_conf.workdir != NULL) {
        conf->workdir = util_strdup_s(args->custom_conf.workdir);
    }

    return;
}

static void request_pack_custom_tty(const struct client_arguments *args, isula_container_config_t *conf)
{
    conf->tty = args->custom_conf.tty;
    conf->open_stdin = args->custom_conf.open_stdin;
    conf->attach_stdin = args->custom_conf.attach_stdin;
    conf->attach_stdout = args->custom_conf.attach_stdout;
    conf->attach_stderr = args->custom_conf.attach_stderr;

    return;
}

static void request_pack_custom_health_check(const struct client_arguments *args, isula_container_config_t *conf)
{
    if (args->custom_conf.health_cmd != NULL) {
        conf->health_cmd = util_strdup_s(args->custom_conf.health_cmd);
    }
    /* health check */
    conf->health_interval = args->custom_conf.health_interval;
    conf->health_timeout = args->custom_conf.health_timeout;
    conf->health_start_period = args->custom_conf.health_start_period;
    conf->health_retries = args->custom_conf.health_retries;
    conf->no_healthcheck = args->custom_conf.no_healthcheck;
    conf->exit_on_unhealthy = args->custom_conf.exit_on_unhealthy;

    return;
}

static int request_pack_custom_annotations(const struct client_arguments *args, isula_container_config_t *conf)
{
    if (args->annotations == NULL) {
        return 0;
    }

    conf->annotations = util_common_calloc_s(sizeof(json_map_string_string));
    if (conf->annotations == NULL) {
        COMMAND_ERROR("Out of memory");
        return -1;
    }

    if (dup_json_map_string_string(args->annotations, conf->annotations) != 0) {
        COMMAND_ERROR("Failed to dup map");
        return -1;
    }

    return 0;
}

static void request_pack_custom_stop_signal(const struct client_arguments *args, isula_container_config_t *conf)
{
    if (args->custom_conf.stop_signal != NULL) {
        conf->stop_signal = util_strdup_s(args->custom_conf.stop_signal);
    }

    return;
}

static isula_container_config_t *request_pack_custom_conf(const struct client_arguments *args)
{
    isula_container_config_t *conf = NULL;

    if (args == NULL) {
        return NULL;
    }

    conf = util_common_calloc_s(sizeof(isula_container_config_t));
    if (conf == NULL) {
        return NULL;
    }

    /* append environment variables from env file */
    if (request_pack_custom_env_file(args, conf) != 0) {
        goto error_out;
    }

    /* make sure --env has higher priority than --env-file */
    if (request_pack_custom_env(args, conf) != 0) {
        goto error_out;
    }

    /* append labels from label file */
    if (request_pack_custom_label_file(args, conf) != 0) {
        goto error_out;
    }

    /* make sure --label has higher priority than --label-file */
    if (request_pack_custom_label(args, conf) != 0) {
        goto error_out;
    }

    /* user and group */
    request_pack_custom_user(args, conf);

    request_pack_custom_hostname(args, conf);

    /* all devices */
    request_pack_custom_all_devices(args, conf);

    /* system container */
    request_pack_custom_system_container(args, conf);

    /* entrypoint */
    request_pack_custom_entrypoint(args, conf);

    /* command args */
    if (request_pack_custom_args(args, conf) != 0) {
        goto error_out;
    }

    /* console log options */
    request_pack_custom_log_options(args, conf);

    if (request_pack_custom_annotations(args, conf) != 0) {
        goto error_out;
    }

    /* work dir in container */
    request_pack_custom_work_dir(args, conf);

    request_pack_custom_tty(args, conf);

    request_pack_custom_health_check(args, conf);

    request_pack_custom_stop_signal(args, conf);

    return conf;

error_out:
    isula_container_config_free(conf);
    return NULL;
}

static int request_pack_host_ns_change_files(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    int ret = 0;
    size_t i = 0;
    size_t files_len = 0;
    char **files = NULL;
    char *net_files[] = { "/proc/sys/net" };
    char *ipc_files[] = { "/proc/sys/kernel/shmmax",          "/proc/sys/kernel/shmmni", "/proc/sys/kernel/shmall",
                          "/proc/sys/kernel/shm_rmid_forced", "/proc/sys/kernel/msgmax", "/proc/sys/kernel/msgmni",
                          "/proc/sys/kernel/msgmnb",          "/proc/sys/kernel/sem",    "/proc/sys/fs/mqueue"
                        };
    char *net_ipc_files[] = { "/proc/sys/net",           "/proc/sys/kernel/shmmax",          "/proc/sys/kernel/shmmni",
                              "/proc/sys/kernel/shmall", "/proc/sys/kernel/shm_rmid_forced", "/proc/sys/kernel/msgmax",
                              "/proc/sys/kernel/msgmni", "/proc/sys/kernel/msgmnb",          "/proc/sys/kernel/sem",
                              "/proc/sys/fs/mqueue"
                            };

    if (args->custom_conf.ns_change_opt == NULL) {
        return 0;
    }

    if (args->custom_conf.privileged) {
        return 0;
    }

    if (strcmp(args->custom_conf.ns_change_opt, "net") == 0) {
        files = net_files;
        files_len = sizeof(net_files) / sizeof(net_files[0]);
    } else if (strcmp(args->custom_conf.ns_change_opt, "ipc") == 0) {
        files = ipc_files;
        files_len = sizeof(ipc_files) / sizeof(ipc_files[0]);
    } else {
        files = net_ipc_files;
        files_len = sizeof(net_ipc_files) / sizeof(net_ipc_files[0]);
    }
    if (files_len > (SIZE_MAX / sizeof(char *)) - 1) {
        ERROR("Too many files");
        return -1;
    }
    hostconfig->ns_change_files = util_common_calloc_s((files_len + 1) * sizeof(char *));
    if (hostconfig->ns_change_files == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < files_len; i++) {
        hostconfig->ns_change_files[hostconfig->ns_change_files_len++] = util_strdup_s(files[i]);
    }

    return ret;
}

static int request_pack_host_caps(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* cap add */
    if (args->custom_conf.cap_adds != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.cap_adds),
                                      util_array_len((const char **)(args->custom_conf.cap_adds)), &hostconfig->cap_add,
                                      &hostconfig->cap_add_len) != 0) {
            COMMAND_ERROR("Failed to dup cap adds");
            return -1;
        }
    }
    /* cap drop */
    if (args->custom_conf.cap_drops != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.cap_drops),
                                      util_array_len((const char **)(args->custom_conf.cap_drops)),
                                      &hostconfig->cap_drop, &hostconfig->cap_drop_len) != 0) {
            COMMAND_ERROR("Failed to dup cap drops");
            return -1;
        }
    }

    return 0;
}

static int request_pack_host_group_add(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* group add */
    if (args->custom_conf.group_add != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.group_add),
                                      util_array_len((const char **)(args->custom_conf.group_add)),
                                      &hostconfig->group_add, &hostconfig->group_add_len) != 0) {
            COMMAND_ERROR("Failed to dup group adds");
            return -1;
        }
    }

    return 0;
}

static int request_pack_host_extra_hosts(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* extra hosts */
    if (args->custom_conf.extra_hosts != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.extra_hosts),
                                      util_array_len((const char **)(args->custom_conf.extra_hosts)),
                                      &hostconfig->extra_hosts, &hostconfig->extra_hosts_len) != 0) {
            COMMAND_ERROR("Failed to dup extra hosts");
            return -1;
        }
    }

    return 0;
}

static int request_pack_host_dns(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* dns */
    if (args->custom_conf.dns != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.dns),
                                      util_array_len((const char **)(args->custom_conf.dns)), &hostconfig->dns,
                                      &hostconfig->dns_len) != 0) {
            COMMAND_ERROR("Failed to dup dns");
            return -1;
        }
    }

    /* dns options */
    if (args->custom_conf.dns_options != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.dns_options),
                                      util_array_len((const char **)(args->custom_conf.dns_options)),
                                      &hostconfig->dns_options, &hostconfig->dns_options_len) != 0) {
            COMMAND_ERROR("Failed to dup dns options");
            return -1;
        }
    }

    /* dns search */
    if (args->custom_conf.dns_search != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.dns_search),
                                      util_array_len((const char **)(args->custom_conf.dns_search)),
                                      &hostconfig->dns_search, &hostconfig->dns_search_len) != 0) {
            COMMAND_ERROR("Failed to dup dns search");
            return -1;
        }
    }

    return 0;
}

inline static int request_pack_host_ulimit(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* ulimit options */
    if (args->custom_conf.ulimits != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.ulimits),
                                      util_array_len((const char **)(args->custom_conf.ulimits)), &hostconfig->ulimits,
                                      &hostconfig->ulimits_len) != 0) {
            COMMAND_ERROR("Failed to dup ulimits");
            return -1;
        }
    }

    return 0;
}

inline static int request_pack_host_weight_devices(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* blkio weight devices */
    if (args->custom_conf.weight_devices != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.weight_devices),
                                      util_array_len((const char **)(args->custom_conf.weight_devices)),
                                      &hostconfig->blkio_weight_device, &hostconfig->blkio_weight_device_len) != 0) {
            COMMAND_ERROR("Failed to dup weight devices");
            return -1;
        }
    }

    return 0;
}

inline static int request_pack_host_device_read_bps(const struct client_arguments *args,
                                                    isula_host_config_t *hostconfig)
{
    if (args->custom_conf.blkio_throttle_read_bps_device != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.blkio_throttle_read_bps_device),
                                      util_array_len((const char **)(args->custom_conf.blkio_throttle_read_bps_device)),
                                      &hostconfig->blkio_throttle_read_bps_device,
                                      &hostconfig->blkio_throttle_read_bps_device_len) != 0) {
            COMMAND_ERROR("Failed to dup blkio_throttle_read_bps_device");
            return -1;
        }
    }

    return 0;
}

inline static int request_pack_host_device_write_bps(const struct client_arguments *args,
                                                     isula_host_config_t *hostconfig)
{
    if (args->custom_conf.blkio_throttle_write_bps_device != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.blkio_throttle_write_bps_device),
                                      util_array_len((const char **)(args->custom_conf.blkio_throttle_write_bps_device)),
                                      &hostconfig->blkio_throttle_write_bps_device,
                                      &hostconfig->blkio_throttle_write_bps_device_len) != 0) {
            COMMAND_ERROR("Failed to dup blkio_throttle_write_bps_device");
            return -1;
        }
    }

    return 0;
}

inline static int request_pack_host_device_read_iops(const struct client_arguments *args,
                                                     isula_host_config_t *hostconfig)
{
    if (args->custom_conf.blkio_throttle_read_iops_device != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.blkio_throttle_read_iops_device),
                                      util_array_len((const char **)(args->custom_conf.blkio_throttle_read_iops_device)),
                                      &hostconfig->blkio_throttle_read_iops_device,
                                      &hostconfig->blkio_throttle_read_iops_device_len) != 0) {
            COMMAND_ERROR("Failed to dup blkio_throttle_read_iops_device");
            return -1;
        }
    }

    return 0;
}

inline static int request_pack_host_device_write_iops(const struct client_arguments *args,
                                                      isula_host_config_t *hostconfig)
{
    if (args->custom_conf.blkio_throttle_write_iops_device != NULL) {
        if (util_dup_array_of_strings(
                (const char **)(args->custom_conf.blkio_throttle_write_iops_device),
                util_array_len((const char **)(args->custom_conf.blkio_throttle_write_iops_device)),
                &hostconfig->blkio_throttle_write_iops_device,
                &hostconfig->blkio_throttle_write_iops_device_len) != 0) {
            COMMAND_ERROR("Failed to dup blkio_throttle_write_iops_device");
            return -1;
        }
    }

    return 0;
}

inline static int request_pack_host_device_cgroup_rules(const struct client_arguments *args,
                                                        isula_host_config_t *hostconfig)
{
    if (args->custom_conf.device_cgroup_rules != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.device_cgroup_rules),
                                      util_array_len((const char **)(args->custom_conf.device_cgroup_rules)),
                                      &hostconfig->device_cgroup_rules, &hostconfig->device_cgroup_rules_len) != 0) {
            COMMAND_ERROR("Failed to dup device_cgroup_rules");
            return -1;
        }
    }

    return 0;
}

inline static int request_pack_host_blockio(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    return (request_pack_host_weight_devices(args, hostconfig) || request_pack_host_device_read_bps(args, hostconfig) ||
            request_pack_host_device_write_bps(args, hostconfig) ||
            request_pack_host_device_read_iops(args, hostconfig) ||
            request_pack_host_device_write_iops(args, hostconfig));
}

inline static int request_pack_host_devices(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* devices */
    if (args->custom_conf.devices != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.devices),
                                      util_array_len((const char **)(args->custom_conf.devices)), &hostconfig->devices,
                                      &hostconfig->devices_len) != 0) {
            COMMAND_ERROR("Failed to dup devices");
            return -1;
        }
    }

    return 0;
}

inline static int request_pack_host_hugepage_limits(const struct client_arguments *args,
                                                    isula_host_config_t *hostconfig)
{
    /* hugepage limits */
    if (args->custom_conf.hugepage_limits != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.hugepage_limits),
                                      util_array_len((const char **)(args->custom_conf.hugepage_limits)),
                                      &hostconfig->hugetlbs, &hostconfig->hugetlbs_len) != 0) {
            COMMAND_ERROR("Failed to dup hugepage_limits");
            return -1;
        }
    }

    return 0;
}

inline static int request_pack_host_binds(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* volumes to binds */
    if (args->custom_conf.volumes != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.volumes),
                                      util_array_len((const char **)(args->custom_conf.volumes)), &hostconfig->binds,
                                      &hostconfig->binds_len) != 0) {
            COMMAND_ERROR("Failed to dup volumes");
            return -1;
        }
    }

    return 0;
}

inline static int request_pack_host_volumes_from(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* volumes-from */
    if (args->custom_conf.volumes_from != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.volumes_from),
                                      util_array_len((const char **)(args->custom_conf.volumes_from)),
                                      &hostconfig->volumes_from, &hostconfig->volumes_from_len) != 0) {
            COMMAND_ERROR("Failed to dup volumes-from");
            return -1;
        }
    }

    return 0;
}

static int request_pack_host_mounts(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    size_t size = 0;
    size_t i = 0;
    mount_spec *mount = NULL;
    char *errmsg = NULL;

    if (args->custom_conf.mounts == NULL) {
        return 0;
    }

    size = (size_t)util_array_len((const char **)(args->custom_conf.mounts));
    hostconfig->mounts = util_common_calloc_s(sizeof(mount_spec *) * size);
    if (hostconfig->mounts == NULL) {
        COMMAND_ERROR("out of memory");
        return -1;
    }

    for (i = 0; i < size; i++) {
        if (util_parse_mount_spec(args->custom_conf.mounts[i], &mount, &errmsg) != 0) {
            COMMAND_ERROR("%s", errmsg);
            free(errmsg);
            return -1;
        }
        hostconfig->mounts[hostconfig->mounts_len++] = mount;
    }

    return 0;
}

static int request_pack_host_tmpfs(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    size_t i = 0;
    size_t len = 0;

    if (args->custom_conf.tmpfs == NULL) {
        return 0;
    }

    hostconfig->tmpfs = util_common_calloc_s(sizeof(json_map_string_string));
    if (hostconfig->tmpfs == NULL) {
        COMMAND_ERROR("Out of memory");
        return -1;
    }

    len = util_array_len((const char **)(args->custom_conf.tmpfs));
    for (i = 0; i < len; i++) {
        if (append_json_map_string_string(hostconfig->tmpfs, args->custom_conf.tmpfs[i], "")) {
            COMMAND_ERROR("Failed to append map");
            return -1;
        }
    }
    return 0;
}

inline static void request_pack_host_hook_spec(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* hook-spec file */
    hostconfig->hook_spec = util_strdup_s(args->custom_conf.hook_spec);
}

inline static void request_pack_host_restart_policy(const struct client_arguments *args,
                                                    isula_host_config_t *hostconfig)
{
    hostconfig->restart_policy = util_strdup_s(args->restart);
}

static bool bridge_network_mode(const char *net_mode)
{
    if (namespace_is_host(net_mode) || namespace_is_container(net_mode) || namespace_is_none(net_mode)) {
        return false;
    }

    return true;
}

static void request_pack_host_namespaces(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    hostconfig->ipc_mode = util_strdup_s(args->custom_conf.share_ns[NAMESPACE_IPC]);

    hostconfig->userns_mode = util_strdup_s(args->custom_conf.share_ns[NAMESPACE_USER]);

    hostconfig->uts_mode = util_strdup_s(args->custom_conf.share_ns[NAMESPACE_UTS]);

    hostconfig->pid_mode = util_strdup_s(args->custom_conf.share_ns[NAMESPACE_PID]);

    if (args->custom_conf.share_ns[NAMESPACE_NET] == NULL) {
        return;
    }

    if (!bridge_network_mode(args->custom_conf.share_ns[NAMESPACE_NET])) {
        hostconfig->network_mode = util_strdup_s(args->custom_conf.share_ns[NAMESPACE_NET]);
    } else {
        hostconfig->network_mode = util_strdup_s(SHARE_NAMESPACE_BRIDGE);
    }
}

inline static int request_pack_host_security(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* security opt */
    if (args->custom_conf.security != NULL) {
        if (util_dup_array_of_strings((const char **)(args->custom_conf.security),
                                      util_array_len((const char **)(args->custom_conf.security)),
                                      &hostconfig->security, &hostconfig->security_len) != 0) {
            COMMAND_ERROR("Failed to dup security");
            return -1;
        }
    }

    return 0;
}

static int request_pack_host_network(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    int ret = 0;
    size_t bridge_network_len = 0;
    char **bridge_network = NULL;
    const char *net_mode = args->custom_conf.share_ns[NAMESPACE_NET];

    hostconfig->ip = util_strdup_s(args->custom_conf.ip);

    hostconfig->mac_address = util_strdup_s(args->custom_conf.mac_address);

    if (net_mode == NULL || !bridge_network_mode(net_mode)) {
        return 0;
    }

    bridge_network = util_string_split(net_mode, ',');
    if (bridge_network == NULL) {
        COMMAND_ERROR("Failed to pack hostconfig bridge");
        return -1;
    }
    bridge_network_len = util_array_len((const char **)bridge_network);

    if (util_string_array_unique((const char **)bridge_network, bridge_network_len,
                                 &hostconfig->bridge_network, &hostconfig->bridge_network_len) != 0) {
        ERROR("Failed to unique bridge networks");
        ret = -1;
    }

    util_free_array_by_len(bridge_network, bridge_network_len);
    return ret;
}

static isula_host_config_t *request_pack_host_config(const struct client_arguments *args)
{
    isula_host_config_t *hostconfig = NULL;

    if (args == NULL) {
        return NULL;
    }

    hostconfig = util_common_calloc_s(sizeof(isula_host_config_t));
    if (hostconfig == NULL) {
        return NULL;
    }

    /* privileged */
    hostconfig->privileged = args->custom_conf.privileged;

    /* system container */
    hostconfig->system_container = args->custom_conf.system_container;

    /* oom kill disable */
    hostconfig->oom_kill_disable = args->custom_conf.oom_kill_disable;

    /* shm size */
    hostconfig->shm_size = args->custom_conf.shm_size;

    /* user remap */
    hostconfig->user_remap = util_strdup_s(args->custom_conf.user_remap);

    /* auto remove */
    hostconfig->auto_remove = args->custom_conf.auto_remove;

    /* readonly rootfs */
    hostconfig->readonly_rootfs = args->custom_conf.readonly;

    /* env target file */
    hostconfig->env_target_file = util_strdup_s(args->custom_conf.env_target_file);

    /* cgroup parent */
    hostconfig->cgroup_parent = util_strdup_s(args->custom_conf.cgroup_parent);

    if (request_pack_host_config_cgroup(args, hostconfig) != 0) {
        goto error_out;
    }

    /* storage options */
    if (request_pack_host_config_storage_opts(args, hostconfig) != 0) {
        goto error_out;
    }

    /* sysctls */
    if (request_pack_host_config_sysctls(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_ns_change_files(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_mounts(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_tmpfs(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_caps(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_group_add(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_extra_hosts(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_dns(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_ulimit(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_blockio(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_devices(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_hugepage_limits(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_binds(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_volumes_from(args, hostconfig) != 0) {
        goto error_out;
    }

    request_pack_host_hook_spec(args, hostconfig);

    request_pack_host_restart_policy(args, hostconfig);

    request_pack_host_namespaces(args, hostconfig);

    hostconfig->host_channel = util_strdup_s(args->host_channel);

    if (request_pack_host_security(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_device_cgroup_rules(args, hostconfig) != 0) {
        goto error_out;
    }

    if (request_pack_host_network(args, hostconfig) != 0) {
        goto error_out;
    }

    hostconfig->publish_all = args->custom_conf.publish_all;

    return hostconfig;

error_out:
    isula_host_config_free(hostconfig);
    return NULL;
}

#define IMAGE_NOT_FOUND_ERROR "No such image"

static int do_client_create(const struct client_arguments *args, const isula_connect_ops *ops,
                            const struct isula_create_request *request, struct isula_create_response *response)
{
    int ret = 0;
    client_connect_config_t config = get_connect_config(args);

    ret = ops->container.create(request, response, &config);
    if (ret != 0) {
        if (response->cc == ISULAD_ERR_INPUT) {
            ret = EINVALIDARGS;
        } else if (response->server_errono ||
                   (response->errmsg && !strcmp(response->errmsg, errno_to_error_message(ISULAD_ERR_CONNECT)))) {
            ret = ESERVERERROR;
        } else {
            ret = ECOMMON;
        }
    }
    return ret;
}

static int client_try_to_create(const struct client_arguments *args, const struct isula_create_request *request,
                                struct isula_create_response **out_response)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_create_response *response = NULL;

    response = util_common_calloc_s(sizeof(struct isula_create_response));
    if (response == NULL) {
        ERROR("Out of memory");
        ret = ECOMMON;
        goto out;
    }

    ops = get_connect_client_ops();
    if (ops == NULL || ops->container.create == NULL) {
        ERROR("Unimplemented ops");
        ret = ESERVERERROR;
        goto out;
    }

    if (strcmp(args->pull, "always") == 0) {
        ret = client_pull(args);
        if (ret != 0) {
            goto out;
        }
    }

    ret = do_client_create(args, ops, request, response);
    if (ret != 0) {
        if (response->errmsg == NULL || strstr(response->errmsg, IMAGE_NOT_FOUND_ERROR) == NULL ||
            strcmp(args->pull, "missing") != 0) {
            client_print_error(response->cc, response->server_errono, response->errmsg);
            goto out;
        }
        COMMAND_ERROR("Unable to find image '%s' locally", request->image);
        ret = client_pull(args);
        if (ret != 0) {
            goto out;
        }

        /* retry create */
        isula_create_response_free(response);
        response = util_common_calloc_s(sizeof(struct isula_create_response));
        if (response == NULL) {
            ERROR("Out of memory");
            ret = ECOMMON;
            goto out;
        }
        ret = do_client_create(args, ops, request, response);
        if (ret != 0) {
            client_print_error(response->cc, response->server_errono, response->errmsg);
            goto out;
        }
    }
out:
    *out_response = response;
    return ret;
}

static bool valid_pull_option(const char *pull)
{
    if (strcmp(pull, "always") == 0 || strcmp(pull, "missing") == 0 || strcmp(pull, "never") == 0) {
        return true;
    }
    return false;
}

static int pack_custom_network_expose(isula_container_config_t *container_spec, const map_t *expose_m)
{
    int ret = 0;
    size_t len = 0;
    size_t i = 0;
    map_itor *itor = NULL;
    defs_map_string_object *expose = NULL;

    len = map_size(expose_m);
    if (len == 0) {
        DEBUG("Expose port list empty, no need to pack");
        return 0;
    }

    itor = map_itor_new(expose_m);
    if (itor == NULL) {
        ERROR("Out of memory, create new map itor failed");
        ret = -1;
        goto out;
    }

    expose = util_common_calloc_s(sizeof(defs_map_string_object));
    if (expose == NULL) {
        ERROR("Out of memory, allocate expose failed");
        ret = -1;
        goto out;
    }

    expose->keys = util_common_calloc_s(sizeof(char *) * len);
    if (expose->keys == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    expose->values = util_common_calloc_s(len * sizeof(defs_map_string_object_element*));
    if (expose->values == NULL) {
        free(expose->keys);
        expose->keys = NULL;
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (; map_itor_valid(itor) && i < len; map_itor_next(itor), i++) {
        void *key = map_itor_key(itor);
        if (key == NULL) {
            continue;
        }
        expose->keys[i] = util_strdup_s(key);
        expose->len++;
    }
    container_spec->expose = expose;
    expose = NULL;

out:
    free_defs_map_string_object(expose);
    map_itor_free(itor);
    return ret;
}

static int pack_custom_network_publish(isula_host_config_t *host_spec, const map_t *port_binding_m)
{
    if (map_size(port_binding_m) == 0) {
        return 0;
    }

    return util_copy_port_binding_from_custom_map(&(host_spec->port_bindings), port_binding_m);
}

/*
 * Create a create request message and call RPC
 */
int client_create(struct client_arguments *args)
{
    int ret = 0;
    struct isula_create_request *request = NULL;
    struct isula_create_response *response = NULL;
    isula_container_config_t *container_spec = NULL;
    isula_host_config_t *host_spec = NULL;
    map_t *expose_m = NULL;
    map_t *port_binding_m = NULL;

    request = util_common_calloc_s(sizeof(struct isula_create_request));
    if (request == NULL) {
        COMMAND_ERROR("Memery out");
        ret = -1;
        goto out;
    }

    request->name = util_strdup_s(args->name);
    request->rootfs = util_strdup_s(args->create_rootfs);
    request->runtime = util_strdup_s(args->runtime);
    request->image = util_strdup_s(args->image_name);

    // parse --publish param to custom map
    if (args->custom_conf.publish != NULL) {
        ret = util_parse_port_specs((const char **)args->custom_conf.publish, &expose_m, &port_binding_m);
        if (ret != 0) {
            COMMAND_ERROR("Invalid --publish or -p params value");
            ret = EINVALIDARGS;
            goto out;
        }
    }
    // parse --expose param to custom map
    if (args->custom_conf.expose != NULL && args->custom_conf.publish_all) {
        if (util_parse_expose_ports((const char **)args->custom_conf.expose, &expose_m) != 0) {
            COMMAND_ERROR("Invalid --expose params value");
            ret = EINVALIDARGS;
            goto out;
        }
    }

    container_spec = request_pack_custom_conf(args);
    if (container_spec == NULL) {
        ret = EINVALIDARGS;
        goto out;
    }

    if (pack_custom_network_expose(container_spec, expose_m) != 0) {
        ret = EINVALIDARGS;
        goto out;
    }

    if (generate_container_config(container_spec, &request->container_spec_json) != 0) {
        ret = EINVALIDARGS;
        goto out;
    }

    host_spec = request_pack_host_config(args);
    if (host_spec == NULL) {
        ret = EINVALIDARGS;
        goto out;
    }

    if (pack_custom_network_publish(host_spec, port_binding_m) != 0) {
        ret = EINVALIDARGS;
        goto out;
    }

    host_spec->publish_all = args->custom_conf.publish_all;

    if (generate_hostconfig(host_spec, &request->host_spec_json) != 0) {
        ret = EINVALIDARGS;
        goto out;
    }

    ret = client_try_to_create(args, request, &response);
    if (ret != 0) {
        goto out;
    }

    if (response->id != NULL) {
        free(args->name);
        args->name = util_strdup_s(response->id);
    } else {
        ERROR("Container id create failed.");
        ret = ESERVERERROR;
        goto out;
    }

out:
    isula_host_config_free(host_spec);
    isula_container_config_free(container_spec);
    isula_create_response_free(response);
    isula_create_request_free(request);
    map_free(expose_m);
    map_free(port_binding_m);
    return ret;
}

static int add_new_annotation(const char *key, const char *value, struct client_arguments *args)
{
    if (key == NULL || value == NULL) {
        return -1;
    }

    if (args->annotations == NULL) {
        args->annotations = util_common_calloc_s(sizeof(json_map_string_string));
        if (args->annotations == NULL) {
            COMMAND_ERROR("Out Memory");
            return -1;
        }
    }

    if (append_json_map_string_string(args->annotations, key, value)) {
        COMMAND_ERROR("Failed to append annotation key:%s, value:%s", key, value);
        return -1;
    }

    return 0;
}

int log_opt_parser(struct client_arguments *args, const char *option)
{
    int ret = -1;
    char *optkey = NULL;
    char *value = NULL;
    char *tmp = NULL;
    size_t len;
    size_t total_len;

    if (option == NULL || args == NULL) {
        goto out;
    }

    tmp = util_strdup_s(option);

    // log option format: key=value
    total_len = strlen(tmp);
    if (total_len <= 2) {
        goto out;
    }

    optkey = tmp;
    value = strchr(tmp, '=');
    // option do not contain '='
    if (value == NULL) {
        goto out;
    }

    len = (size_t)(value - optkey);
    // if option is 'optkey='
    if (total_len == len + 1) {
        goto out;
    }

    // if option is '=optkey'
    if (len == 0) {
        goto out;
    }

    tmp[len] = '\0';
    value += 1;

    if (args->annotations == NULL) {
        args->annotations = util_common_calloc_s(sizeof(json_map_string_string));
        if (args->annotations == NULL) {
            COMMAND_ERROR("Out of Memory");
            goto out;
        }
    }

    if (!parse_container_log_opt(optkey, value, args->annotations)) {
        ret = -1;
        goto out;
    }

    ret = 0;
out:
    if (ret != 0) {
        COMMAND_ERROR("Invalid option: %s", option);
    }
    free(tmp);

    return ret;
}

int callback_log_opt(command_option_t *option, const char *value)
{
    struct client_arguments *args = (struct client_arguments *)option->data;
    return log_opt_parser(args, value);
}

int callback_log_driver(command_option_t *option, const char *value)
{
    struct client_arguments *args = (struct client_arguments *)option->data;

    if (value == NULL) {
        COMMAND_ERROR("log driver is NULL");
        return -1;
    }

    if (!check_opt_container_log_driver(value)) {
        COMMAND_ERROR("Unsupported log driver: %s", value);
        return -1;
    }

    free(args->log_driver);
    args->log_driver = util_strdup_s(value);

    return 0;
}

static int annotation_parser(struct client_arguments *args, const char *option)
{
    int ret = -1;
    char *optkey = NULL;
    char *value = NULL;
    char *tmp = NULL;

    if (args == NULL || option == NULL) {
        goto out;
    }

    // annotation format: key[=][value]
    tmp = util_strdup_s(option);

    optkey = tmp;
    value = strchr(tmp, '=');

    if (value != NULL) {
        *value = '\0';
        value++;
    } else {
        value = "";
    }

    if (optkey[0] == '\0') {
        goto out;
    }

    ret = add_new_annotation(optkey, value, args);

out:
    if (ret < 0) {
        COMMAND_ERROR("Invalid option: '%s'", option);
    }
    free(tmp);

    return ret;
}

int callback_annotation(command_option_t *option, const char *value)
{
    struct client_arguments *args = (struct client_arguments *)option->data;
    return annotation_parser(args, value);
}

int cmd_create_main(int argc, const char **argv)
{
    int nret = 0;
    int ret = 0;
    command_t cmd = { 0 };
    struct isula_libutils_log_config lconf = { 0 };

    if (client_arguments_init(&g_cmd_create_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_create_args.progname = argv[0];
    g_cmd_create_args.subcommand = argv[1];
    struct command_option options[] = { LOG_OPTIONS(lconf) CREATE_OPTIONS(g_cmd_create_args) CREATE_EXTEND_OPTIONS(
            g_cmd_create_args) COMMON_OPTIONS(g_cmd_create_args)
    };

    isula_libutils_default_log_config(argv[0], &lconf);
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_create_desc,
                 g_cmd_create_usage);
    if (command_parse_args(&cmd, &g_cmd_create_args.argc, &g_cmd_create_args.argv) ||
        create_checker(&g_cmd_create_args)) {
        nret = EINVALIDARGS;
        goto out;
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        exit(ECOMMON);
    }

    ret = client_create(&g_cmd_create_args);
    if (ret != 0) {
        ERROR("Container \"%s\" create failed", g_cmd_create_args.name);
        nret = ECOMMON;
        goto out;
    }
    printf("%s\n", g_cmd_create_args.name);
    nret = EXIT_SUCCESS;
out:
    exit(nret);
}

static int check_parsed_devices(const char *devices, const char *cgroup_permissions, const char *path_in_container)
{
    int ret = 0;
    int nret = 0;

    /* check valid device mode */
    if (!util_valid_device_mode(cgroup_permissions)) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --device: bad mode specified: %s", devices, cgroup_permissions);
        ret = -1;
        goto out;
    }

    /* check valid path in container */
    nret = util_validate_absolute_path(path_in_container);
    if (nret != 0) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --device: %s is not an absolute path", devices, path_in_container);
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static bool check_devices_conf_valid(const char *devices)
{
    bool ret = true;
    size_t tmp_str_len = 0;
    char **tmp_str = NULL;
    char *cgroup_permissions = NULL;
    char *path_in_container = NULL;

    if (devices == NULL || !strcmp(devices, "")) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --device", devices ? devices : "null");
        return false;
    }

    tmp_str = util_string_split(devices, ':');
    if (tmp_str == NULL) {
        ERROR("Out of memory");
        ret = false;
        goto out;
    }
    tmp_str_len = util_array_len((const char **)tmp_str);

    // device format: x:x:x or x:x or x
    switch (tmp_str_len) {
        case 3:
            path_in_container = tmp_str[1];
            cgroup_permissions = tmp_str[2];
            break;
        case 2:
            if (util_valid_device_mode(tmp_str[1])) {
                path_in_container = tmp_str[0];
                cgroup_permissions = tmp_str[1];
            } else {
                path_in_container = tmp_str[1];
                cgroup_permissions = "rwm";
            }
            break;
        case 1:
            path_in_container = tmp_str[0];
            cgroup_permissions = "rwm";
            break;
        default:
            COMMAND_ERROR("Invalid value \"%s\" for flag --device\n", devices);
            ret = false;
            break;
    }
    if (!ret) {
        goto out;
    }

    /* check valid device */
    if (check_parsed_devices(devices, cgroup_permissions, path_in_container) != 0) {
        ret = false;
        goto out;
    }

out:
    util_free_array(tmp_str);
    return ret;
}

static bool check_volumes_valid(const char *volume)
{
    bool ret = true;
    size_t alen = 0;
    char **array = NULL;
    char **modes = NULL;

    // split volume to src:dest:mode
    array = util_string_split(volume, ':');
    if (array == NULL) {
        COMMAND_ERROR("Out of memory");
        ret = false;
        goto free_out;
    }
    alen = util_array_len((const char **)array);

    // volume format: src:dst:mode
    switch (alen) {
        case 1:
#ifdef ENABLE_OCI_IMAGE
            // anonymous volume, do nothing
#else
            COMMAND_ERROR("Not supported volume format '%s'", volume);
            ret = false;
#endif
            goto free_out;
        case 2:
            if (util_valid_mount_mode(array[1])) {
                // Destination + Mode is not a valid volume - volumes
                // cannot include a mode. eg /foo:rw
                COMMAND_ERROR("Invalid volume specification '%s',Invalid mode:%s", volume, array[1]);
                ret = false;
                goto free_out;
            }
            break;
        case 3:
            if (!util_valid_mount_mode(array[2])) {
                COMMAND_ERROR("Invalid volume specification '%s'.Invalid mode:%s", volume, array[2]);
                ret = false;
                goto free_out;
            }
            modes = util_string_split(array[2], ',');
            if (modes == NULL) {
                ERROR("Out of memory");
                ret = false;
                goto free_out;
            }
            break;
        default:
            COMMAND_ERROR("Invalid volume specification '%s'", volume);
            ret = false;
            goto free_out;
    }

#ifdef ENABLE_OCI_IMAGE
    if (array[1][0] != '/' || strcmp(array[1], "/") == 0) {
#else
    if (array[0][0] != '/' || array[1][0] != '/' || strcmp(array[1], "/") == 0) {
#endif
        COMMAND_ERROR("Invalid volume: path must be absolute, and destination can't be '/'");
        ret = false;
        goto free_out;
    }

free_out:
    util_free_array(array);
    util_free_array(modes);
    return ret;
}

static bool check_volumes_conf_valid(const char *volume)
{
    if (volume == NULL || !strcmp(volume, "")) {
        COMMAND_ERROR("Volume can't be empty");
        return false;
    }

    if (volume[0] == ':' || volume[strlen(volume) - 1] == ':') {
        COMMAND_ERROR("Delimiter ':' can't be the first or the last character");
        return false;
    }

    return check_volumes_valid(volume);
}

static int check_hook_spec_file(const char *hook_spec)
{
    struct stat hookstat = { 0 };

    if (hook_spec == NULL) {
        return 0;
    }
    if (util_validate_absolute_path(hook_spec)) {
        COMMAND_ERROR("Hook path \"%s\" must be an absolute path", hook_spec);
        return -1;
    }
    if (stat(hook_spec, &hookstat)) {
        COMMAND_ERROR("Stat hook spec file failed: %s", strerror(errno));
        return -1;
    }
    if ((hookstat.st_mode & S_IFMT) != S_IFREG) {
        COMMAND_ERROR("Hook spec file must be a regular text file");
        return -1;
    }

    if (hookstat.st_size > REGULAR_FILE_SIZE) {
        COMMAND_ERROR("Hook spec file size %llu exceed limit: %dM", (unsigned long long)hookstat.st_size,
                      (int)(REGULAR_FILE_SIZE / SIZE_MB));
        return -1;
    }

    return 0;
}

static int create_check_rootfs(struct client_arguments *args)
{
    int ret = 0;

    if (args->external_rootfs != NULL) {
        args->create_rootfs = util_strdup_s(args->external_rootfs);
    } else {
        if (strcmp(args->argv[0], "none:latest") == 0 || strcmp(args->argv[0], "none") == 0) {
            char *rootfs = getenv("IMAGE_NONE_PATH");
            if (rootfs != NULL) {
                args->create_rootfs = util_strdup_s(rootfs);
            } else {
                args->create_rootfs = util_strdup_s(DEFAULT_ROOTFS_PATH);
            }
        }
    }

    args->image_name = args->argv[0];

    args->argc--;
    args->argv++;

    if (args->create_rootfs != NULL) {
        char real_path[PATH_MAX] = { 0 };
        if (realpath(args->create_rootfs, real_path) == NULL) {
            COMMAND_ERROR("Failed to get rootfs '%s': %s", args->create_rootfs, strerror(errno));
            ret = -1;
            goto out;
        }
        free(args->create_rootfs);
        args->create_rootfs = util_strdup_s(real_path);
    }
out:
    return ret;
}

static int create_check_hugetlbs(const struct client_arguments *args)
{
    int ret = 0;
    size_t len, i;

    len = util_array_len((const char **)(args->custom_conf.hugepage_limits));
    for (i = 0; i < len; i++) {
        char *limit = NULL;
        int64_t limitvalue;
        char *dup = NULL;
        char *p = NULL;
        char *pdot2 = NULL;

        dup = util_strdup_s(args->custom_conf.hugepage_limits[i]);

        p = dup;
        p = strchr(p, ':');
        if (p == NULL) {
            limit = dup;
        } else {
            *p = '\0';
            p++;
            pdot2 = strchr(p, ':');
            if (pdot2 != NULL) {
                COMMAND_ERROR("Invalid arguments \"%s\" for flag --hugetlb-limit: too many colons",
                              args->custom_conf.hugepage_limits[i]);
                free(dup);
                ret = -1;
                goto out;
            }
            limit = p;
        }
        ret = util_parse_byte_size_string(limit, &limitvalue);
        if (ret != 0) {
            COMMAND_ERROR("Invalid hugetlb limit:%s:%s", limit, strerror(-ret));
            free(dup);
            ret = -1;
            goto out;
        }
        free(dup);
    }
out:
    return ret;
}

static int create_check_network(const struct client_arguments *args)
{
    size_t len, i;
    const char *net_mode = args->custom_conf.share_ns[NAMESPACE_NET];

    len = util_array_len((const char **)(args->custom_conf.extra_hosts));
    for (i = 0; i < len; i++) {
        char **items = NULL;
        items = util_string_split(args->custom_conf.extra_hosts[i], ':');
        if (items == NULL) {
            COMMAND_ERROR("split extra hosts '%s' failed.", args->custom_conf.extra_hosts[i]);
            return -1;
        }
        if (util_array_len((const char **)items) != 2) {
            util_free_array(items);
            COMMAND_ERROR("Invalid extra hosts specification '%s'. unsupported format",
                          args->custom_conf.extra_hosts[i]);
            return EINVALIDARGS;
        }
        if (!util_validate_ipv4_address(items[1])) {
            COMMAND_ERROR("Invalid host ip address '%s'.", items[1]);
            util_free_array(items);
            return EINVALIDARGS;
        }
        util_free_array(items);
    }
    len = util_array_len((const char **)(args->custom_conf.dns));
    for (i = 0; i < len; i++) {
        if (!util_validate_ipv4_address(args->custom_conf.dns[i])) {
            COMMAND_ERROR("Invalid dns ip address '%s'.", args->custom_conf.dns[i]);
            return EINVALIDARGS;
        }
    }

    // check static IP and MAC address
    if (args->custom_conf.ip != NULL || args->custom_conf.mac_address != NULL) {
        if (net_mode == NULL || !bridge_network_mode(net_mode)) {
            COMMAND_ERROR("Cannot set static IP or MAC address if not set a bridge network");
            return EINVALIDARGS;
        }
        if (util_strings_contains_any(net_mode, ",")) {
            COMMAND_ERROR("Cannot set static IP or MAC address if set more than one bridge network");
            return EINVALIDARGS;
        }
    }

    if (args->custom_conf.ip != NULL && !util_validate_ip_address(args->custom_conf.ip)) {
        COMMAND_ERROR("Invalid ip address '%s'", args->custom_conf.ip);
        return EINVALIDARGS;
    }

    if (args->custom_conf.mac_address != NULL && !util_validate_mac_address(args->custom_conf.mac_address)) {
        COMMAND_ERROR("Invalid MAC address '%s'", args->custom_conf.mac_address);
        return EINVALIDARGS;
    }

    return 0;
}

static int create_hostname_checker(const struct client_arguments *args)
{
    int ret = 0;

    if (args->custom_conf.hostname != NULL) {
        if (!util_valid_host_name(args->custom_conf.hostname)) {
            COMMAND_ERROR("Invalid container hostname (%s), only %s and less than 64 bytes are allowed.",
                          args->custom_conf.hostname, HOST_NAME_REGEXP);
            ret = -1;
            goto out;
        }
    }
out:
    return ret;
}

static int create_name_checker(const struct client_arguments *args)
{
    int ret = 0;

    if (args->name != NULL && !util_valid_container_name(args->name)) {
        COMMAND_ERROR("Invalid container name (%s), only [a-zA-Z0-9][a-zA-Z0-9_.-] are allowed.", args->name);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static bool check_mounts_conf_valid(const char *mount_str)
{
    char *errmsg = NULL;

    if (!util_valid_mount_spec(mount_str, &errmsg)) {
        COMMAND_ERROR("%s", errmsg);
        free(errmsg);
        return false;
    }
    return true;
}

static int create_devices_volumes_checker(const struct client_arguments *args)
{
    int ret = 0;
    size_t i;
    size_t len = 0;

    len = util_array_len((const char **)(args->custom_conf.devices));
    for (i = 0; i < len; i++) {
        if (!check_devices_conf_valid(args->custom_conf.devices[i])) {
            ret = -1;
            goto out;
        }
    }
    len = util_array_len((const char **)(args->custom_conf.volumes));
    for (i = 0; i < len; i++) {
        if (!check_volumes_conf_valid(args->custom_conf.volumes[i])) {
            ret = -1;
            goto out;
        }
    }
    len = util_array_len((const char **)(args->custom_conf.mounts));
    for (i = 0; i < len; i++) {
        if (!check_mounts_conf_valid(args->custom_conf.mounts[i])) {
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int create_namespaces_checker(const struct client_arguments *args)
{
#define MAX_FILES 200
    int ret = 0;
    int max_bridge_len = 0;
    const char *net_mode = args->custom_conf.share_ns[NAMESPACE_NET];
    const char *user_mode = args->custom_conf.share_ns[NAMESPACE_USER];

    if (net_mode == NULL || !bridge_network_mode(net_mode)) {
        return 0;
    }

    if (args->custom_conf.share_ns[NAMESPACE_USER]) {
        if (!namespace_is_host(user_mode) && !namespace_is_none(user_mode)) {
            COMMAND_ERROR("Unsupported user mode %s", user_mode);
            ret = -1;
            goto out;
        }
    }

    max_bridge_len = (MAX_NETWORK_NAME_LEN + 1) * MAX_FILES - 1;
    if (strnlen(net_mode, max_bridge_len + 1) > max_bridge_len) {
        COMMAND_ERROR("Network mode \"%s\" is too long", net_mode);
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static int create_check_user_remap(const struct client_arguments *args)
{
    char *user_remap = args->custom_conf.user_remap;
    unsigned int host_uid = 0;
    unsigned int host_gid = 0;
    unsigned int size = 0;

    if (user_remap == NULL) {
        return 0;
    }
    if (args->custom_conf.privileged || !args->custom_conf.system_container || args->external_rootfs == NULL) {
        COMMAND_ERROR("--user-remap only available for system container");
        return -1;
    }
    return util_parse_user_remap(user_remap, &host_uid, &host_gid, &size);
}

static int create_check_nschangeopt(const struct client_arguments *args)
{
    size_t array_str_len;
    size_t i;
    char **array_str = NULL;

    if (args->custom_conf.ns_change_opt == NULL) {
        return 0;
    }

    if (!args->custom_conf.system_container) {
        COMMAND_ERROR("Unsupported ns-change-opt param in normal container");
        return EINVALIDARGS;
    }

    array_str = util_string_split(args->custom_conf.ns_change_opt, ',');
    if (array_str == NULL) {
        ERROR("Out of memory");
        return EINVALIDARGS;
    }
    array_str_len = util_array_len((const char **)array_str);
    if (array_str_len != 1 && array_str_len != 2) {
        COMMAND_ERROR("invalid ns-change-opt pararm:%s\n", args->custom_conf.ns_change_opt);
        util_free_array(array_str);
        return EINVALIDARGS;
    }

    for (i = 0; i < array_str_len; i++) {
        if ((strcmp(array_str[i], "net") != 0) && (strcmp(array_str[i], "ipc") != 0)) {
            COMMAND_ERROR("invalid ns-change-opt pararm:%s\n", args->custom_conf.ns_change_opt);
            util_free_array(array_str);
            return EINVALIDARGS;
        }
    }

    util_free_array(array_str);
    return 0;
}

static int create_check_oomkilldisable(const struct client_arguments *args)
{
    if (args->custom_conf.oom_kill_disable && args->cr.memory_limit == 0) {
        COMMAND_ERROR("WARNING: Disabling the OOM killer on containers without "
                      "setting a '-m/--memory' limit may be dangerous.");
    }

    return 0;
}

static void restore_to_equate(char *p)
{
    *p = '=';
}

static bool do_create_check_sysctl(const char *sysctl)
{
    char *p = NULL;

    p = strchr(sysctl, '=');
    if (p != NULL) {
        *p = '\0';
        if (strcmp("kernel.pid_max", sysctl) == 0) {
            if (!util_check_pid_max_kernel_namespaced()) {
                COMMAND_ERROR("Sysctl '%s' is not kernel namespaced, it cannot be changed", sysctl);
                restore_to_equate(p);
                return false;
            } else {
                restore_to_equate(p);
                return true;
            }
        }
        if (!util_valid_sysctl(sysctl)) {
            restore_to_equate(p);
            COMMAND_ERROR("Sysctl '%s' is not whitelist", sysctl);
            return false;
        }
        restore_to_equate(p);
    } else {
        COMMAND_ERROR("Invalid sysctl option '%s'", sysctl);
        return false;
    }
    return true;
}

static int create_check_sysctl(const struct client_arguments *args)
{
    size_t i = 0;
    size_t len = 0;

    if (args->custom_conf.sysctls == NULL) {
        return 0;
    }

    len = util_array_len((const char **)(args->custom_conf.sysctls));
    for (i = 0; i < len; i++) {
        if (!do_create_check_sysctl((const char *)args->custom_conf.sysctls[i])) {
            return -1;
        }
    }
    return 0;
}

static int create_check_env_target_file(const struct client_arguments *args)
{
    int ret = 0;
    int64_t file_size = 0;
    char *env_path = NULL;
    char *env_target_file = args->custom_conf.env_target_file;

    if (env_target_file == NULL) {
        return 0;
    }
    if (env_target_file[0] != '/') {
        COMMAND_ERROR("env target file path must be absolute path");
        return -1;
    }
    if (args->external_rootfs == NULL) {
        COMMAND_ERROR("external rootfs not specified");
        return 0;
    }
    if (util_realpath_in_scope(args->external_rootfs, env_target_file, &env_path) < 0) {
        COMMAND_ERROR("env target file '%s' real path must be under '%s'", env_target_file, args->external_rootfs);
        ret = -1;
        goto out;
    }
    if (!util_file_exists(env_path)) {
        goto out;
    }
    file_size = util_file_size(env_path);
    if (file_size > REGULAR_FILE_SIZE) {
        COMMAND_ERROR("env target file '%s', size exceed limit: %lld", env_path, REGULAR_FILE_SIZE);
        ret = -1;
        goto out;
    }

out:
    free(env_path);
    return ret;
}

int create_checker(struct client_arguments *args)
{
    int ret = 0;

    if (args == NULL) {
        return -1;
    }

    args->custom_conf.attach_stdin = args->custom_conf.open_stdin;

    if (create_hostname_checker(args) != 0) {
        ret = -1;
        goto out;
    }

    if (create_name_checker(args) != 0) {
        ret = -1;
        goto out;
    }

    if (create_devices_volumes_checker(args) != 0) {
        ret = -1;
        goto out;
    }

    if (args->argc < 1) {
        COMMAND_ERROR("\"%s\" requires a minimum of 1 argument.", args->subcommand);
        ret = -1;
        goto out;
    }

    if (!valid_pull_option(args->pull)) {
        COMMAND_ERROR("invalid --pull option, only \"always\"|\"missing\"|\"never\" is allowed");
        ret = -1;
        goto out;
    }

    if (create_check_rootfs(args)) {
        ret = -1;
        goto out;
    }

    if (create_check_network(args)) {
        ret = -1;
        goto out;
    }

    if (create_check_user_remap(args)) {
        ret = -1;
        goto out;
    }

    if (check_hook_spec_file(args->custom_conf.hook_spec)) {
        ret = -1;
        goto out;
    }

    if (create_check_hugetlbs(args)) {
        ret = -1;
        goto out;
    }

    if (create_namespaces_checker(args) != 0) {
        ret = -1;
        goto out;
    }

    if (create_check_nschangeopt(args)) {
        ret = -1;
        goto out;
    }

    if (create_check_oomkilldisable(args)) {
        ret = -1;
        goto out;
    }

    if (create_check_sysctl(args)) {
        ret = -1;
        goto out;
    }

    if (create_check_env_target_file(args)) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}
