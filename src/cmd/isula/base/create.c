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
#include <unistd.h>
#include <stdio_ext.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <arpa/inet.h>

#include "namespace.h"
#include "error.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_string.h"
#include "console.h"
#include "create.h"
#include "isula_commands.h"
#include "isula_connect.h"
#include "path.h"
#include "pull.h"
#include "libisulad.h"

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

    /* blkio weight */
    hostconfig->cr->blkio_weight = args->cr.blkio_weight;

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
    hostconfig->cr->cpuset_cpus = args->cr.cpuset_cpus;

    /* cpuset memory */
    hostconfig->cr->cpuset_mems = args->cr.cpuset_mems;

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

static int util_env_set_isulad_enable_plugins(char ***penv, const size_t *penv_len, const char *names)
{
    size_t env_len;
    size_t len = 0;
    char *val = NULL;
    char *kv = NULL;
    char **env = NULL;
    const char *arr[10] = { NULL };

    if (penv == NULL || penv_len == NULL || names == NULL) {
        return -1;
    }

    env = *penv;
    env_len = *penv_len;

    arr[0] = ISULAD_ENABLE_PLUGINS;
    arr[1] = "=";
    arr[2] = names;
    len = 3;

    val = util_env_get_val(env, env_len, ISULAD_ENABLE_PLUGINS, strlen(ISULAD_ENABLE_PLUGINS));
    if (val != NULL && strlen(val) != 0) {
        arr[3] = ISULAD_ENABLE_PLUGINS_SEPERATOR;
        arr[4] = val;
        len = 5;
    }

    kv = util_string_join("", arr, len);
    if (kv == NULL) {
        goto failed;
    }

    if (util_env_set_val(penv, penv_len, ISULAD_ENABLE_PLUGINS, strlen(ISULAD_ENABLE_PLUGINS), kv)) {
        goto failed;
    }

    free(val);
    free(kv);
    return 0;

failed:
    free(val);
    free(kv);
    return -1;
}

static int request_pack_custom_env(struct client_arguments *args, isula_container_config_t *conf)
{
    int ret = 0;
    char *pe = NULL;
    char *new_env = NULL;

    if (args->custom_conf.env != NULL) {
        size_t i;
        for (i = 0; i < util_array_len((const char **)(args->custom_conf.env)); i++) {
            if (util_validate_env(args->custom_conf.env[i], &new_env) != 0) {
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

    if (args->custom_conf.accel != NULL) {
        pe = util_env_get_val(conf->env, conf->env_len, ISULAD_ENABLE_PLUGINS, strlen(ISULAD_ENABLE_PLUGINS));
        if (pe == NULL) {
            if (util_array_append(&conf->env, ISULAD_ENABLE_PLUGINS "=")) {
                COMMAND_ERROR("init env ISULAD_ENABLE_PLUGINS failed");
                ret = -1;
                goto out;
            }
        }
        conf->env_len = util_array_len((const char **)(conf->env));
        conf->accel = args->custom_conf.accel;
        conf->accel_len = util_array_len((const char **)(args->custom_conf.accel));
        if (util_env_set_isulad_enable_plugins(&conf->env, &conf->env_len, ISULAD_ISULA_ADAPTER)) {
            COMMAND_ERROR("init accel env failed");
            ret = -1;
            goto out;
        }
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
        if (util_validate_env(buf, &new_env) != 0) {
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

static int request_pack_custom_label(struct client_arguments *args, isula_container_config_t *conf)
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
    util_free_array(args->custom_conf.label);
    args->custom_conf.label = conf->label; /* make sure args->custom_conf.label point to valid memory. */
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
        conf->user = args->custom_conf.user;
    }

    return;
}

static void request_pack_custom_hostname(const struct client_arguments *args, isula_container_config_t *conf)
{
    if (args->custom_conf.hostname != NULL) {
        conf->hostname = args->custom_conf.hostname;
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
            conf->ns_change_opt = args->custom_conf.ns_change_opt;
        }
    }

    return;
}

static void request_pack_custom_mounts(const struct client_arguments *args, isula_container_config_t *conf)
{
    if (args->custom_conf.mounts != NULL) {
        conf->mounts_len = util_array_len((const char **)(args->custom_conf.mounts));
        conf->mounts = args->custom_conf.mounts;
    }
    return;
}

static void request_pack_custom_entrypoint(const struct client_arguments *args, isula_container_config_t *conf)
{
    if (args->custom_conf.entrypoint != NULL) {
        conf->entrypoint = args->custom_conf.entrypoint;
    }

    return;
}

static void request_pack_custom_args(const struct client_arguments *args, isula_container_config_t *conf)
{
    if (args->argc != 0 && args->argv != NULL) {
        conf->cmd_len = (size_t)(args->argc);
        conf->cmd = (char **)args->argv;
    }

    return;
}

static void request_pack_custom_log_options(const struct client_arguments *args, isula_container_config_t *conf)
{
    conf->log_driver = util_strdup_s(args->log_driver);
}

static int request_pack_custom_log_accel(struct client_arguments *args, isula_container_config_t *conf)
{
    int ret = 0;
    char *accargs = NULL;

    if (conf->accel != NULL) {
        accargs = util_string_join(ISULAD_ISULA_ACCEL_ARGS_SEPERATOR, (const char **)conf->accel, conf->accel_len);

        if (conf->annotations == NULL) {
            conf->annotations = util_common_calloc_s(sizeof(json_map_string_string));
            if (conf->annotations == NULL) {
                COMMAND_ERROR("alloc annotations failed for accel");
                ret = -1;
                goto out;
            }
        }

        ret = append_json_map_string_string(conf->annotations, ISULAD_ISULA_ACCEL_ARGS, accargs);
        if (ret != 0) {
            COMMAND_ERROR("init accel annotations failed accel=%s", accargs);
            ret = -1;
            goto out;
        }
        UTIL_FREE_AND_SET_NULL(accargs);
    }

out:
    free(accargs);
    return ret;
}

static void request_pack_custom_work_dir(const struct client_arguments *args, isula_container_config_t *conf)
{
    /* work dir in container */
    if (args->custom_conf.workdir != NULL) {
        conf->workdir = args->custom_conf.workdir;
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
        conf->health_cmd = args->custom_conf.health_cmd;
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

static int request_pack_custom_conf(struct client_arguments *args, isula_container_config_t *conf)
{
    if (args == NULL) {
        return -1;
    }

    /* append environment variables from env file */
    if (request_pack_custom_env_file(args, conf) != 0) {
        return -1;
    }

    /* make sure --env has higher priority than --env-file */
    if (request_pack_custom_env(args, conf) != 0) {
        return -1;
    }

    /* append labels from label file */
    if (request_pack_custom_label_file(args, conf) != 0) {
        return -1;
    }

    /* make sure --label has higher priority than --label-file */
    if (request_pack_custom_label(args, conf) != 0) {
        return -1;
    }

    /* user and group */
    request_pack_custom_user(args, conf);

    request_pack_custom_hostname(args, conf);

    /* all devices */
    request_pack_custom_all_devices(args, conf);

    /* system container */
    request_pack_custom_system_container(args, conf);

    /* mounts to mount filesystem */
    request_pack_custom_mounts(args, conf);

    /* entrypoint */
    request_pack_custom_entrypoint(args, conf);

    /* command args */
    request_pack_custom_args(args, conf);

    /* console log options */
    request_pack_custom_log_options(args, conf);

    conf->annotations = args->annotations;
    args->annotations = NULL;

    if (request_pack_custom_log_accel(args, conf) != 0) {
        return -1;
    }

    /* work dir in container */
    request_pack_custom_work_dir(args, conf);

    request_pack_custom_tty(args, conf);

    request_pack_custom_health_check(args, conf);

    return 0;
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
                          "/proc/sys/kernel/msgmnb",          "/proc/sys/kernel/sem",    "/proc/sys/fs/mqueue" };
    char *net_ipc_files[] = { "/proc/sys/net",           "/proc/sys/kernel/shmmax",          "/proc/sys/kernel/shmmni",
                              "/proc/sys/kernel/shmall", "/proc/sys/kernel/shm_rmid_forced", "/proc/sys/kernel/msgmax",
                              "/proc/sys/kernel/msgmni", "/proc/sys/kernel/msgmnb",          "/proc/sys/kernel/sem",
                              "/proc/sys/fs/mqueue" };

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

static void request_pack_host_caps(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* cap add */
    if (args->custom_conf.cap_adds != NULL) {
        hostconfig->cap_add_len = util_array_len((const char **)(args->custom_conf.cap_adds));
        hostconfig->cap_add = args->custom_conf.cap_adds;
    }
    /* cap drop */
    if (args->custom_conf.cap_drops != NULL) {
        hostconfig->cap_drop_len = util_array_len((const char **)(args->custom_conf.cap_drops));
        hostconfig->cap_drop = args->custom_conf.cap_drops;
    }
}

static void request_pack_host_group_add(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* group add */
    if (args->custom_conf.group_add != NULL) {
        hostconfig->group_add_len = util_array_len((const char **)(args->custom_conf.group_add));
        hostconfig->group_add = args->custom_conf.group_add;
    }
}

static void request_pack_host_extra_hosts(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* extra hosts */
    if (args->custom_conf.extra_hosts != NULL) {
        hostconfig->extra_hosts_len = util_array_len((const char **)(args->custom_conf.extra_hosts));
        hostconfig->extra_hosts = args->custom_conf.extra_hosts;
    }
}

static void request_pack_host_dns(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* dns */
    if (args->custom_conf.dns != NULL) {
        hostconfig->dns_len = util_array_len((const char **)(args->custom_conf.dns));
        hostconfig->dns = args->custom_conf.dns;
    }

    /* dns options */
    if (args->custom_conf.dns_options != NULL) {
        hostconfig->dns_options_len = util_array_len((const char **)(args->custom_conf.dns_options));
        hostconfig->dns_options = args->custom_conf.dns_options;
    }

    /* dns search */
    if (args->custom_conf.dns_search != NULL) {
        hostconfig->dns_search_len = util_array_len((const char **)(args->custom_conf.dns_search));
        hostconfig->dns_search = args->custom_conf.dns_search;
    }
}

static void request_pack_host_ulimit(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* ulimit options */
    if (args->custom_conf.ulimits != NULL) {
        hostconfig->ulimits_len = util_array_len((const char **)(args->custom_conf.ulimits));
        hostconfig->ulimits = args->custom_conf.ulimits;
    }
}

static void request_pack_host_weight_devices(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* blkio weight devices */
    if (args->custom_conf.weight_devices != NULL) {
        hostconfig->blkio_weight_device_len = util_array_len((const char **)(args->custom_conf.weight_devices));
        hostconfig->blkio_weight_device = args->custom_conf.weight_devices;
    }
}

static void request_pack_host_device_read_bps(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    if (args->custom_conf.blkio_throttle_read_bps_device != NULL) {
        hostconfig->blkio_throttle_read_bps_device_len =
                util_array_len((const char **)(args->custom_conf.blkio_throttle_read_bps_device));
        hostconfig->blkio_throttle_read_bps_device = args->custom_conf.blkio_throttle_read_bps_device;
    }
}

static void request_pack_host_device_write_bps(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    if (args->custom_conf.blkio_throttle_write_bps_device != NULL) {
        hostconfig->blkio_throttle_write_bps_device_len =
                util_array_len((const char **)(args->custom_conf.blkio_throttle_write_bps_device));
        hostconfig->blkio_throttle_write_bps_device = args->custom_conf.blkio_throttle_write_bps_device;
    }
}

static void request_pack_host_blockio(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    request_pack_host_weight_devices(args, hostconfig);
    request_pack_host_device_read_bps(args, hostconfig);
    request_pack_host_device_write_bps(args, hostconfig);
}

static void request_pack_host_devices(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* devices */
    if (args->custom_conf.devices != NULL) {
        hostconfig->devices_len = util_array_len((const char **)(args->custom_conf.devices));
        hostconfig->devices = args->custom_conf.devices;
    }
}

static void request_pack_host_hugepage_limits(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* hugepage limits */
    if (args->custom_conf.hugepage_limits != NULL) {
        hostconfig->hugetlbs_len = util_array_len((const char **)(args->custom_conf.hugepage_limits));
        hostconfig->hugetlbs = args->custom_conf.hugepage_limits;
    }
}

static void request_pack_host_binds(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* volumes to binds */
    if (args->custom_conf.volumes != NULL) {
        hostconfig->binds_len = (size_t)util_array_len((const char **)(args->custom_conf.volumes));
        hostconfig->binds = args->custom_conf.volumes;
    }
}

static void request_pack_host_hook_spec(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* hook-spec file */
    if (args->custom_conf.hook_spec != NULL) {
        hostconfig->hook_spec = args->custom_conf.hook_spec;
    }
}

static void request_pack_host_restart_policy(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    if (args->restart != NULL) {
        hostconfig->restart_policy = args->restart;
    }
}

static void request_pack_host_namespaces(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    if (args->host_channel != NULL) {
        hostconfig->host_channel = args->host_channel;
    }

    if (args->custom_conf.share_ns[NAMESPACE_NET] != NULL) {
        hostconfig->network_mode = args->custom_conf.share_ns[NAMESPACE_NET];
    }
    if (args->custom_conf.share_ns[NAMESPACE_IPC] != NULL) {
        hostconfig->ipc_mode = args->custom_conf.share_ns[NAMESPACE_IPC];
    }
    if (args->custom_conf.share_ns[NAMESPACE_USER] != NULL) {
        hostconfig->userns_mode = args->custom_conf.share_ns[NAMESPACE_USER];
    }
    if (args->custom_conf.share_ns[NAMESPACE_UTS] != NULL) {
        hostconfig->uts_mode = args->custom_conf.share_ns[NAMESPACE_UTS];
    }
    if (args->custom_conf.share_ns[NAMESPACE_PID] != NULL) {
        hostconfig->pid_mode = args->custom_conf.share_ns[NAMESPACE_PID];
    }
}

static void request_pack_host_security(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    /* security opt */
    if (args->custom_conf.security != NULL) {
        hostconfig->security_len = util_array_len((const char **)(args->custom_conf.security));
        hostconfig->security = args->custom_conf.security;
    }
}

static int request_pack_host_config(const struct client_arguments *args, isula_host_config_t *hostconfig)
{
    int ret = 0;

    if (args == NULL) {
        return -1;
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
    hostconfig->user_remap = args->custom_conf.user_remap;

    /* auto remove */
    hostconfig->auto_remove = args->custom_conf.auto_remove;

    /* readonly rootfs */
    hostconfig->readonly_rootfs = args->custom_conf.readonly;

    /* env target file */
    hostconfig->env_target_file = args->custom_conf.env_target_file;

    /* cgroup parent */
    hostconfig->cgroup_parent = args->custom_conf.cgroup_parent;

    ret = request_pack_host_config_cgroup(args, hostconfig);
    if (ret != 0) {
        return ret;
    }

    /* storage options */
    ret = request_pack_host_config_storage_opts(args, hostconfig);
    if (ret != 0) {
        return ret;
    }

    /* sysctls */
    ret = request_pack_host_config_sysctls(args, hostconfig);
    if (ret != 0) {
        return ret;
    }

    ret = request_pack_host_ns_change_files(args, hostconfig);
    if (ret != 0) {
        return ret;
    }

    request_pack_host_caps(args, hostconfig);

    request_pack_host_group_add(args, hostconfig);

    request_pack_host_extra_hosts(args, hostconfig);

    request_pack_host_dns(args, hostconfig);

    request_pack_host_ulimit(args, hostconfig);

    request_pack_host_blockio(args, hostconfig);

    request_pack_host_devices(args, hostconfig);

    request_pack_host_hugepage_limits(args, hostconfig);

    request_pack_host_binds(args, hostconfig);

    request_pack_host_hook_spec(args, hostconfig);

    request_pack_host_restart_policy(args, hostconfig);

    request_pack_host_namespaces(args, hostconfig);

    request_pack_host_security(args, hostconfig);

    return ret;
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

    ret = do_client_create(args, ops, request, response);
    if (ret != 0) {
        if (response->errmsg == NULL || strstr(response->errmsg, IMAGE_NOT_FOUND_ERROR) == NULL) {
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

static void free_alloced_memory_in_host_config(isula_host_config_t *hostconfig)
{
    isula_ns_change_files_free(hostconfig);
    isula_host_config_storage_opts_free(hostconfig);
    isula_host_config_sysctl_free(hostconfig);
}

static void free_alloced_memory_in_config(isula_container_config_t *custom_conf)
{
    if (custom_conf == NULL) {
        return;
    }

    free_json_map_string_string(custom_conf->annotations);
    custom_conf->annotations = NULL;
}

/*
 * Create a create request message and call RPC
 */
int client_create(struct client_arguments *args)
{
    int ret = 0;
    struct isula_create_request request = { 0 };
    struct isula_create_response *response = NULL;
    isula_container_config_t custom_conf = { 0 };
    isula_host_config_t host_config = { 0 };
    container_cgroup_resources_t cr = { 0 };

    request.name = args->name;
    request.rootfs = args->create_rootfs;
    request.runtime = args->runtime;
    request.image = args->image_name;
    request.hostconfig = &host_config;
    request.config = &custom_conf;
    host_config.cr = &cr;

    ret = request_pack_custom_conf(args, request.config);
    if (ret != 0) {
        goto out;
    }

    ret = request_pack_host_config(args, request.hostconfig);
    if (ret != 0) {
        goto out;
    }

    ret = client_try_to_create(args, &request, &response);
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
    free_alloced_memory_in_host_config(request.hostconfig);
    free_alloced_memory_in_config(request.config);
    isula_create_response_free(response);
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

typedef int (*log_opt_callback_t)(const char *key, const char *value, struct client_arguments *args);

typedef struct log_opt_parse {
    const char *key;
    const char *anno_key;
    log_opt_callback_t cb;
} log_opt_parse_t;

static int log_opt_common_cb(const char *key, const char *value, struct client_arguments *args)
{
    return add_new_annotation(key, value, args);
}

static int log_opt_max_file_cb(const char *key, const char *value, struct client_arguments *args)
{
    unsigned int ptr = 0;
    int ret = -1;

    if (util_safe_uint(value, &ptr)) {
        return ret;
    }
    if (ptr == 0) {
        COMMAND_ERROR("Invalid option 'max-file', value:%s", value);
        return ret;
    }

    return add_new_annotation(key, value, args);
}

static int log_opt_syslog_facility(const char *key, const char *value, struct client_arguments *args)
{
#define FACILITIES_LEN 20
    const char *facility_keys[FACILITIES_LEN] = { "kern",     "user",   "mail",   "daemon", "auth",
                                                  "syslog",   "lpr",    "news",   "uucp",   "cron",
                                                  "authpriv", "ftp",    "local0", "local1", "local2",
                                                  "local3",   "local4", "local5", "local6", "local7" };
    int i;

    for (i = 0; i < FACILITIES_LEN; i++) {
        if (strcmp(facility_keys[i], value) == 0) {
            break;
        }
    }

    if (i == FACILITIES_LEN) {
        return -1;
    }

    return add_new_annotation(key, value, args);
}

static int log_opt_disable_log_cb(const char *key, const char *value, struct client_arguments *args)
{
    int ret = -1;

    if (strcmp(value, "true") == 0) {
        ret = add_new_annotation(key, "none", args);
    } else if (strcmp(value, "false") == 0) {
        ret = 0;
    } else {
        COMMAND_ERROR("Invalid option 'disable-log', value:%s", value);
    }

    return ret;
}

static int log_opt_parse_options(struct client_arguments *args, const char *optkey, const char *value)
{
#define OPTIONS_MAX 5
    log_opt_parse_t log_opts[OPTIONS_MAX] = {
        {
                .key = "max-size",
                .anno_key = CONTAINER_LOG_CONFIG_KEY_SIZE,
                .cb = &log_opt_common_cb,
        },
        {
                .key = "max-file",
                .anno_key = CONTAINER_LOG_CONFIG_KEY_ROTATE,
                .cb = &log_opt_max_file_cb,
        },
        {
                .key = "disable-log",
                .anno_key = CONTAINER_LOG_CONFIG_KEY_FILE,
                .cb = &log_opt_disable_log_cb,
        },
        {
                .key = "syslog-tag",
                .anno_key = CONTAINER_LOG_CONFIG_KEY_SYSLOG_TAG,
                .cb = &log_opt_common_cb,
        },
        {
                .key = "syslog-facility",
                .anno_key = CONTAINER_LOG_CONFIG_KEY_SYSLOG_FACILITY,
                .cb = &log_opt_syslog_facility,
        },
    };
    int ret = -1;
    int i;

    for (i = 0; i < OPTIONS_MAX; i++) {
        if (strcmp(optkey, log_opts[i].key) == 0) {
            ret = log_opts[i].cb(log_opts[i].anno_key, value, args);
            break;
        }
    }

    if (i == OPTIONS_MAX) {
        COMMAND_ERROR("Unsupported log opt: %s", optkey);
    }

    return ret;
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

    ret = log_opt_parse_options(args, optkey, value);

out:
    if (ret < 0) {
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
#define DRIVER_MAX 2
    const char *drivers[] = { CONTAINER_LOG_CONFIG_JSON_FILE_DRIVER, CONTAINER_LOG_CONFIG_SYSLOG_DRIVER };
    int i = 0;
    struct client_arguments *args = (struct client_arguments *)option->data;

    if (value == NULL) {
        return -1;
    }

    for (; i < DRIVER_MAX; i++) {
        if (strcmp(value, drivers[i]) == 0) {
            break;
        }
    }
    if (i == DRIVER_MAX) {
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
    struct command_option options[] = { LOG_OPTIONS(lconf), CREATE_OPTIONS(g_cmd_create_args),
                                        CREATE_EXTEND_OPTIONS(g_cmd_create_args), COMMON_OPTIONS(g_cmd_create_args) };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_create_desc,
                 g_cmd_create_usage);
    if (command_parse_args(&cmd, &g_cmd_create_args.argc, &g_cmd_create_args.argv) ||
        create_checker(&g_cmd_create_args)) {
        nret = EINVALIDARGS;
        goto out;
    }
    isula_libutils_default_log_config(argv[0], &lconf);
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
            COMMAND_ERROR("Not supported volume format '%s'", volume);
            ret = false;
            goto free_out;
        /* fall-through */
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

    if (array[0][0] != '/' || array[1][0] != '/' || strcmp(array[1], "/") == 0) {
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

struct valid_mounts_state {
    char *mount;
    bool has_type;
    bool has_src;
    bool has_dst;
    bool type_squashfs;
    char *source;
};

#define MOUNT_STATE_CHECK_SUCCESS 0
#define MOUNT_STATE_CHECK_IGNORE 1
#define MOUNT_STATE_CHECK_INVALID_ARG 2

static int parse_mount_item_type(const char *value, struct valid_mounts_state *state)
{
    /* If value of type is NULL, ignore it */
    if (value == NULL) {
        return MOUNT_STATE_CHECK_IGNORE;
    }

    if (state->has_type) {
        COMMAND_ERROR("Invalid mount specification '%s'.More than one type found", state->mount);
        return MOUNT_STATE_CHECK_INVALID_ARG;
    }

    if (strcmp(value, "squashfs") && strcmp(value, "bind")) {
        COMMAND_ERROR("Invalid mount specification '%s'.Type must be squashfs or bind", state->mount);
        return MOUNT_STATE_CHECK_INVALID_ARG;
    }

    if (strcmp(value, "squashfs") == 0) {
        state->type_squashfs = true;
    }

    state->has_type = true;
    return MOUNT_STATE_CHECK_SUCCESS;
}

static int parse_mount_item_src(const char *value, struct valid_mounts_state *state)
{
    /* If value of source is NULL, ignore it */
    if (value == NULL) {
        return MOUNT_STATE_CHECK_IGNORE;
    }

    if (state->has_src) {
        COMMAND_ERROR("Invalid mount specification '%s'.More than one source found", state->mount);
        return MOUNT_STATE_CHECK_INVALID_ARG;
    }

    if (value[0] != '/') {
        COMMAND_ERROR("Invalid mount specification '%s'.Source must be absolute path", state->mount);
        return MOUNT_STATE_CHECK_INVALID_ARG;
    }

    free(state->source);
    state->source = util_strdup_s(value);

    state->has_src = true;
    return MOUNT_STATE_CHECK_SUCCESS;
}

static int parse_mount_item_dst(const char *value, struct valid_mounts_state *state)
{
    char dstpath[PATH_MAX] = { 0 };

    /* If value of destination is NULL, ignore it */
    if (value == NULL) {
        return MOUNT_STATE_CHECK_IGNORE;
    }

    if (state->has_dst) {
        COMMAND_ERROR("Invalid mount specification '%s'.More than one destination found", state->mount);
        return MOUNT_STATE_CHECK_INVALID_ARG;
    }

    if (value[0] != '/') {
        COMMAND_ERROR("Invalid mount specification '%s'.Destination must be absolute path", state->mount);
        return MOUNT_STATE_CHECK_INVALID_ARG;
    }

    if (strcmp(value, "/") == 0) {
        COMMAND_ERROR("Invalid mount specification '%s'.Destination can't be '/'", state->mount);
        return MOUNT_STATE_CHECK_INVALID_ARG;
    }

    if (!cleanpath(value, dstpath, sizeof(dstpath))) {
        COMMAND_ERROR("Invalid mount specification '%s'.Can't translate destination path to clean path", state->mount);
        return MOUNT_STATE_CHECK_INVALID_ARG;
    }

    state->has_dst = true;
    return MOUNT_STATE_CHECK_SUCCESS;
}

static int parse_mount_item_ro(const char *value, const struct valid_mounts_state *state)
{
    if (value != NULL) {
        if (strcmp(value, "1") && strcmp(value, "true") && strcmp(value, "0") && strcmp(value, "false")) {
            COMMAND_ERROR("Invalid mount specification '%s'.Invalid readonly mode:%s", state->mount, value);
            return MOUNT_STATE_CHECK_INVALID_ARG;
        }
    }
    return MOUNT_STATE_CHECK_SUCCESS;
}

static int parse_mount_item_propagation(const char *value, const struct valid_mounts_state *state)
{
    if (value == NULL) {
        return MOUNT_STATE_CHECK_IGNORE;
    }

    if (!util_valid_propagation_mode(value)) {
        COMMAND_ERROR("Invalid mount specification '%s'.Invalid propagation mode:%s", state->mount, value);
        return MOUNT_STATE_CHECK_INVALID_ARG;
    }
    return MOUNT_STATE_CHECK_SUCCESS;
}

static int parse_mount_item_selinux(const char *value, const struct valid_mounts_state *state)
{
    if (value == NULL) {
        return MOUNT_STATE_CHECK_IGNORE;
    }

    if (!util_valid_label_mode(value)) {
        COMMAND_ERROR("Invalid mount specification '%s'.Invalid bind selinux opts:%s", state->mount, value);
        return MOUNT_STATE_CHECK_INVALID_ARG;
    }
    return MOUNT_STATE_CHECK_SUCCESS;
}

/*
 * 0: success
 * 1: ignore this item, continue
 * 2: failed
 */
static int valid_mounts_item(const char *mntkey, const char *value, struct valid_mounts_state *state)
{
    if (strcmp(mntkey, "type") == 0) {
        return parse_mount_item_type(value, state);
    } else if (strcmp(mntkey, "src") == 0 || strcmp(mntkey, "source") == 0) {
        return parse_mount_item_src(value, state);
    } else if (strcmp(mntkey, "dst") == 0 || strcmp(mntkey, "destination") == 0) {
        return parse_mount_item_dst(value, state);
    } else if (strcmp(mntkey, "ro") == 0 || strcmp(mntkey, "readonly") == 0) {
        return parse_mount_item_ro(value, state);
    } else if (strcmp(mntkey, "bind-propagation") == 0) {
        return parse_mount_item_propagation(value, state);
    } else if (strcmp(mntkey, "bind-selinux-opts") == 0) {
        return parse_mount_item_selinux(value, state);
    } else {
        COMMAND_ERROR("Invalid mount specification '%s'.Unsupported item:%s", state->mount, mntkey);
        return MOUNT_STATE_CHECK_INVALID_ARG;
    }
}

static int parse_mounts_conf(const char *mount, struct valid_mounts_state *state)
{
    int ret = 0;
    size_t i = 0;
    size_t items_len = 0;
    char **items = NULL;
    char **key_val = NULL;

    items = util_string_split(mount, ',');
    if (items == NULL) {
        ret = EINVALIDARGS;
        COMMAND_ERROR("Invalid mount specification '%s'. unsupported format", mount);
        goto out;
    }

    items_len = util_array_len((const char **)items);

    for (i = 0; i < items_len; i++) {
        key_val = util_string_split(items[i], '=');
        if (key_val == NULL) {
            continue;
        }

        ret = valid_mounts_item(key_val[0], key_val[1], state);
        if (ret == MOUNT_STATE_CHECK_IGNORE) { /* ignore this item */
            ret = 0;
            util_free_array(key_val);
            key_val = NULL;
            continue;
        } else if (ret == MOUNT_STATE_CHECK_INVALID_ARG) { /* invalid args */
            ret = EINVALIDARGS;
            goto out;
        }
        util_free_array(key_val);
        key_val = NULL;
    }

out:
    util_free_array(key_val);
    util_free_array(items);
    return ret;
}

static int check_parsed_mounts_conf(const char *mount, const struct valid_mounts_state *state)
{
    int ret = 0;
    char real_path[PATH_MAX] = { 0 }; /* Init to zero every time loop enter here. */

    if (!state->has_type) {
        ret = EINVALIDARGS;
        COMMAND_ERROR("Invalid mount specification '%s'.Missing type", mount);
        goto out;
    }

    if (!state->has_src) {
        ret = EINVALIDARGS;
        COMMAND_ERROR("Invalid mount specification '%s'.Missing source", mount);
        goto out;
    }

    if (!state->has_dst) {
        ret = EINVALIDARGS;
        COMMAND_ERROR("Invalid mount specification '%s'.Missing destination", mount);
        goto out;
    }

    if (state->type_squashfs) {
        if (strlen(state->source) > PATH_MAX || realpath(state->source, real_path) == NULL) {
            ret = EINVALIDARGS;
            COMMAND_ERROR("Invalid mount specification '%s'.Source %s not exist", mount, state->source);
            goto out;
        }

        /* Make sure it's a regular file */
        if (!util_valid_file(real_path, S_IFREG)) {
            ret = EINVALIDARGS;
            COMMAND_ERROR("Invalid mount specification '%s'.Source %s is not a squashfs file", mount, state->source);
            goto out;
        }
    }
out:
    return ret;
}

static bool check_mounts_conf_valid(const char *mount)
{
    int ret = 0;
    struct valid_mounts_state state = { (char *)mount, false, false, false, NULL };

    if (mount == NULL) {
        COMMAND_ERROR("Invalid mount specification: can't be empty");
        return false;
    }
    if (!mount[0]) {
        COMMAND_ERROR("Invalid mount specification: can't be empty");
        return false;
    }

    ret = parse_mounts_conf(mount, &state);
    if (ret != 0) {
        goto out;
    }

    ret = check_parsed_mounts_conf(mount, &state);
    if (ret != 0) {
        goto out;
    }

out:
    free(state.source);
    return ret ? false : true;
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
    struct sockaddr_in sa;

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
        if (!inet_pton(AF_INET, items[1], &sa.sin_addr)) {
            COMMAND_ERROR("Invalid host ip address '%s'.", items[1]);
            util_free_array(items);
            return EINVALIDARGS;
        }
        util_free_array(items);
    }
    len = util_array_len((const char **)(args->custom_conf.dns));
    for (i = 0; i < len; i++) {
        if (!inet_pton(AF_INET, args->custom_conf.dns[i], &sa.sin_addr)) {
            COMMAND_ERROR("Invalid dns ip address '%s'.", args->custom_conf.dns[i]);
            return EINVALIDARGS;
        }
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
    int ret = 0;
    const char *net_mode = args->custom_conf.share_ns[NAMESPACE_NET];

    if (args->custom_conf.share_ns[NAMESPACE_NET]) {
        if (!is_host(net_mode) && !is_container(net_mode) && !is_none(net_mode)) {
            COMMAND_ERROR("Unsupported network mode %s", net_mode);
            ret = -1;
            goto out;
        }
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
            if (!pid_max_kernel_namespaced()) {
                COMMAND_ERROR("Sysctl '%s' is not kernel namespaced, it cannot be changed", sysctl);
                restore_to_equate(p);
                return false;
            } else {
                restore_to_equate(p);
                return true;
            }
        }
        if (!check_sysctl_valid(sysctl)) {
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
    if (realpath_in_scope(args->external_rootfs, env_target_file, &env_path) < 0) {
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
