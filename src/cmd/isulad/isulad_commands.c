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
 * Description: provide container commands functions
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "isulad_commands.h"
#include "config.h"
#include "isula_libutils/log.h"
#include "path.h"
#include "libisulad.h"
#include "daemon_arguments.h"

#include "utils.h"
#include "constants.h"
#include "isula_libutils/isulad_daemon_configs.h"

const char isulad_desc[] = "GLOBAL OPTIONS:";
const char isulad_usage[] = "[global options]";

void print_version()
{
    printf("Version %s, commit %s\n", VERSION, ISULAD_GIT_COMMIT);
}

static int check_default_ulimit_input(const char *val)
{
    int ret = 0;
    if (val == NULL || strcmp(val, "") == 0) {
        COMMAND_ERROR("ulimit argument can't be empty");
        ret = -1;
        goto out;
    }

    if (val[0] == '=' || val[strlen(val) - 1] == '=') {
        COMMAND_ERROR("Invalid ulimit argument: \"%s\", delimiter '=' can't"
                      " be the first or the last character",
                      val);
        ret = -1;
    }

out:
    return ret;
}

static void get_default_ulimit_split_parts(const char *val, char ***parts, size_t *parts_len, char deli)
{
    *parts = util_string_split_multi(val, deli);
    if (*parts == NULL) {
        ERROR("Out of memory");
        return;
    }
    *parts_len = util_array_len((const char **)(*parts));
}

static int parse_soft_hard_default_ulimit(const char *val, char **limitvals, size_t limitvals_len, int64_t *soft,
                                          int64_t *hard)
{
    int ret = 0;
    // parse soft
    ret = util_safe_llong(limitvals[0], (long long *)soft);
    if (ret < 0) {
        COMMAND_ERROR("Invalid ulimit soft value: \"%s\", parse int64 failed: %s", val, strerror(-ret));
        ret = -1;
        goto out;
    }

    // parse hard if exists
    if (limitvals_len > 1) {
        ret = util_safe_llong(limitvals[1], (long long *)hard);
        if (ret < 0) {
            COMMAND_ERROR("Invalid ulimit hard value: \"%s\", parse int64 failed: %s", val, strerror(-ret));
            ret = -1;
            goto out;
        }

        if (*soft > *hard) {
            COMMAND_ERROR("Ulimit soft limit must be less than or equal to hard limit: %lld > %lld",
                          (long long int)(*soft), (long long int)(*hard));
            ret = -1;
            goto out;
        }
    } else {
        *hard = *soft; // default to soft in case no hard was set
    }
out:
    return ret;
}

int check_default_ulimit_type(const char *type)
{
    int ret = 0;
    char **tmptype = NULL;
    char *ulimit_valid_type[] = {
        // "as", // Disabled since this doesn't seem usable with the way Docker inits a container.
        "core",   "cpu",   "data", "fsize",  "locks",  "memlock",    "msgqueue", "nice",
        "nofile", "nproc", "rss",  "rtprio", "rttime", "sigpending", "stack",    NULL
    };

    for (tmptype = ulimit_valid_type; *tmptype != NULL; tmptype++) {
        if (strcmp(type, *tmptype) == 0) {
            break;
        }
    }

    if (*tmptype == NULL) {
        COMMAND_ERROR("Invalid ulimit type: %s", type);
        ret = -1;
    }
    return ret;
}

static host_config_ulimits_element *parse_default_ulimit(const char *val)
{
    int ret = 0;
    int64_t soft = 0;
    int64_t hard = 0;
    size_t parts_len = 0;
    size_t limitvals_len = 0;
    char **parts = NULL;
    char **limitvals = NULL;
    host_config_ulimits_element *ulimit = NULL;

    ret = check_default_ulimit_input(val);
    if (ret != 0) {
        return NULL;
    }

    get_default_ulimit_split_parts(val, &parts, &parts_len, '=');
    if (parts == NULL) {
        ERROR("Out of memory");
        return NULL;
    } else if (parts_len != 2) {
        COMMAND_ERROR("Invalid ulimit argument: %s", val);
        ret = -1;
        goto out;
    }

    ret = check_default_ulimit_type(parts[0]);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    if (parts[1][0] == ':' || parts[1][strlen(parts[1]) - 1] == ':') {
        COMMAND_ERROR("Invalid ulimit value: \"%s\", delimiter ':' can't be the first"
                      " or the last character",
                      val);
        ret = -1;
        goto out;
    }

    // parse value
    get_default_ulimit_split_parts(parts[1], &limitvals, &limitvals_len, ':');
    if (limitvals == NULL) {
        ret = -1;
        goto out;
    }

    if (limitvals_len > 2) {
        COMMAND_ERROR("Too many limit value arguments - %s, can only have up to two, `soft[:hard]`", parts[1]);
        ret = -1;
        goto out;
    }

    ret = parse_soft_hard_default_ulimit(val, limitvals, limitvals_len, &soft, &hard);
    if (ret < 0) {
        goto out;
    }

    ulimit = util_common_calloc_s(sizeof(host_config_ulimits_element));
    if (ulimit == NULL) {
        ret = -1;
        goto out;
    }
    ulimit->name = util_strdup_s(parts[0]);
    ulimit->hard = hard;
    ulimit->soft = soft;

out:
    util_free_array(parts);
    util_free_array(limitvals);
    if (ret != 0) {
        free_host_config_ulimits_element(ulimit);
        ulimit = NULL;
    }

    return ulimit;
}

int command_default_ulimit_append(command_option_t *option, const char *arg)
{
    int ret = 0;
    size_t ulimit_len;
    host_config_ulimits_element *tmp = NULL;
    host_config_ulimits_element **pos = NULL;

    if (option == NULL) {
        ret = -1;
        goto out;
    }

    tmp = parse_default_ulimit(arg);
    if (tmp == NULL) {
        ERROR("parse default ulimit from arg failed");
        ret = -1;
        goto out;
    }

    for (pos = *(host_config_ulimits_element ***)(option->data); pos != NULL && *pos != NULL; pos++) {
        if (strcmp((*pos)->name, tmp->name) == 0) {
            break;
        }
    }
    if (pos != NULL && *pos != NULL) {
        (*pos)->hard = tmp->hard;
        (*pos)->soft = tmp->soft;
        goto out;
    }

    ulimit_len = ulimit_array_len(*(host_config_ulimits_element ***)(option->data));
    if (ulimit_array_append(option->data, tmp, ulimit_len) != 0) {
        ERROR("default ulimit append failed");
        ret = -1;
    }

out:
    free_host_config_ulimits_element(tmp);
    return ret;
}

int server_callback_log_opt(command_option_t *option, const char *value)
{
    int ret = 0;
    struct service_arguments *args = NULL;

    if (option == NULL || value == NULL) {
        COMMAND_ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    args = (struct service_arguments *)option->data;
    ret = server_log_opt_parser(args, value);
    if (ret != 0) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --%s", value, option->large);
    }

out:
    return ret;
}

static void command_init_isulad(command_t *self, command_option_t *options, int options_len, int argc,
                                const char **argv, const char *description, const char *usage)
{
    self->name = argv[0];
    self->argc = argc - 1;
    self->argv = argv + 1;
    self->usage = usage;
    self->description = description;
    self->options = options;
    self->option_count = options_len;
    self->type = "isulad";
}

// Tries to execute a command in the command list.
int parse_args(struct service_arguments *args, int argc, const char **argv)
{
    command_t cmd = { 0 };
    struct command_option options[] = { ISULAD_OPTIONS(args) };
    command_init_isulad(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, isulad_desc,
                        isulad_usage);
    if (command_parse_args(&cmd, &args->argc, &args->argv)) {
        exit(EINVALIDARGS);
    }

    if (args->argc > 0) {
        printf("unresolved arguments: %s;\t"
               "run `%s --help` or `%s -h` for help.\n",
               args->argv[0], argv[0], argv[0]);
        return -1;
    }

    if (args->version == true) {
        print_version();
        exit(0);
    }

    return 0;
}

static bool check_file_mode(unsigned int mode)
{
    unsigned int work = 0x01ff;

    if ((mode & (~work)) == 0) {
        return true;
    }
    return false;
}

static int check_args_log_conf(const struct service_arguments *args)
{
    int ret = 0;

    /* validate log-file-mode */
    if (!check_file_mode(args->log_file_mode)) {
        ERROR("Invalid log file mode: %d", args->log_file_mode);
        ret = -1;
        goto out;
    }

    /* validate max-size */
    if ((args->json_confs->log_driver && strcasecmp("file", args->json_confs->log_driver) == 0) &&
        (args->max_size < (4 * 1024))) {
        ERROR("Max-size \"%ld\" must large than 4KB.", args->max_size);
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static int check_args_hosts_conf(const char **array, size_t size)
{
    int ret = 0;
    size_t i;

    /* validate unix/tcp socket name */
    for (i = 0; i < size; i++) {
        if (!util_validate_socket(array[i])) {
            isulad_set_error_message("Invalid socket name: %s", array[i]);
            ret = -1;
            goto out;
        }
    }
out:
    return ret;
}

static int check_args_graph_path(struct service_arguments *args)
{
    int ret = 0;
    char dstpath[PATH_MAX] = { 0 };

    ret = util_validate_absolute_path(args->json_confs->graph);
    if (ret) {
        ERROR("Invalid absolute root directory path:(%s).", args->json_confs->graph);
        ret = -1;
        goto out;
    }
    if (cleanpath(args->json_confs->graph, dstpath, sizeof(dstpath)) == NULL) {
        ERROR("failed to get clean path");
        ret = -1;
        goto out;
    }
    free(args->json_confs->graph);
    args->json_confs->graph = util_strdup_s(dstpath);

out:
    return ret;
}

static int check_args_state_path(struct service_arguments *args)
{
    int ret = 0;
    char dstpath[PATH_MAX] = { 0 };

    ret = util_validate_absolute_path(args->json_confs->state);
    if (ret != 0) {
        ERROR("Invalid absolute state directory path:(%s).", args->json_confs->state);
        ret = -1;
        goto out;
    }
    if (cleanpath(args->json_confs->state, dstpath, sizeof(dstpath)) == NULL) {
        ERROR("failed to get clean path");
        ret = -1;
        goto out;
    }
    free(args->json_confs->state);
    args->json_confs->state = util_strdup_s(dstpath);

out:
    return ret;
}

static int check_args_umask(const struct service_arguments *args)
{
    int ret = 0;

    if (args->json_confs->native_umask != NULL) {
        if (strcmp(args->json_confs->native_umask, UMASK_NORMAL) != 0 &&
            strcmp(args->json_confs->native_umask, UMASK_SECURE) != 0) {
            COMMAND_ERROR("Invalid native umask: %s", args->json_confs->native_umask);
            ERROR("Invalid native umask: %s", args->json_confs->native_umask);
            ret = -1;
            goto out;
        }
    }
out:
    return ret;
}

static int check_args_auth_plugin(const struct service_arguments *args)
{
    int ret = 0;

    if (args->json_confs->authorization_plugin != NULL) {
        if (strcmp(args->json_confs->authorization_plugin, AUTH_PLUGIN)) {
            COMMAND_ERROR("Invalid authorization plugin '%s'", args->json_confs->authorization_plugin);
            ERROR("Invalid authorization plugin '%s'", args->json_confs->authorization_plugin);
            ret = -1;
            goto out;
        }
    }
out:
    return ret;
}

static int check_websocket_server_listening_port(const struct service_arguments *args)
{
#define MIN_REGISTER_PORT 1024
#define MAX_REGISTER_PORT 49151
    int ret = 0;

    if (args->json_confs->websocket_server_listening_port < MIN_REGISTER_PORT ||
        args->json_confs->websocket_server_listening_port > MAX_REGISTER_PORT) {
        COMMAND_ERROR("Invalid websocket server listening port: '%d' (range: %d-%d)",
                      args->json_confs->websocket_server_listening_port, MIN_REGISTER_PORT, MAX_REGISTER_PORT);
        ERROR("Invalid websocket server listening port: '%d' (range: %d-%d)",
              args->json_confs->websocket_server_listening_port, MIN_REGISTER_PORT, MAX_REGISTER_PORT);
        ret = -1;
        goto out;
    }
out:
    return ret;
}

int check_args(struct service_arguments *args)
{
    int ret = 0;

    if (args->json_confs == NULL) {
        ERROR("Empty json configs");
        ret = -1;
        goto out;
    }

    args->hosts_len = util_array_len((const char **)(args->hosts));
    args->json_confs->storage_opts_len = util_array_len((const char **)(args->json_confs->storage_opts));
    args->json_confs->registry_mirrors_len = util_array_len((const char **)(args->json_confs->registry_mirrors));
    args->json_confs->insecure_registries_len = util_array_len((const char **)(args->json_confs->insecure_registries));

    /* validate log-file-mode */
    if (check_args_log_conf(args) != 0) {
        ret = -1;
        goto out;
    }

    if (check_args_hosts_conf((const char **)(args->hosts), args->hosts_len) != 0) {
        ret = -1;
        goto out;
    }

    /* validate pid file format */
    if (util_validate_absolute_path(args->json_confs->pidfile) != 0) {
        ERROR("Invalid absolute pid file path:(%s).", args->json_confs->pidfile);
        ret = -1;
        goto out;
    }

    /* validate rootpath format */
    if (check_args_graph_path(args) != 0) {
        ret = -1;
        goto out;
    }

    /* validate statepath format */
    if (check_args_state_path(args) != 0) {
        ret = -1;
        goto out;
    }

    if (check_args_umask(args) != 0) {
        ret = -1;
        goto out;
    }

    if (check_args_auth_plugin(args) != 0) {
        ret = -1;
        goto out;
    }

    if (check_websocket_server_listening_port(args) != 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int do_merge_conf_hosts_into_global(struct service_arguments *args)
{
#define DEFAULT_HOSTS_LEN 2

    if (args->json_confs->hosts_len != 0) {
        args->hosts = args->json_confs->hosts;
        args->hosts_len = args->json_confs->hosts_len;
        args->json_confs->hosts = NULL;
        args->json_confs->hosts_len = 0;
        return 0;
    }

    if (args->hosts_len == 0) {
        /* set default host */
        args->hosts = (char **)util_common_calloc_s(sizeof(char *) * DEFAULT_HOSTS_LEN);
        if (args->hosts == NULL) {
            ERROR("Out of memory");
            return -1;
        }
        args->hosts[0] = util_strdup_s(DEFAULT_UNIX_SOCKET);
        args->hosts_len++;
    }

    return 0;
}

static int check_hosts_specified_conflict(const struct service_arguments *args)
{
    int ret = 0;
    char *flag_hosts = NULL;
    char *file_hosts = NULL;

    if (args->hosts_len != 0 && args->json_confs->hosts_len != 0) {
        flag_hosts = util_string_join(" ", (const char **)args->hosts, args->hosts_len);
        if (flag_hosts == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }

        file_hosts = util_string_join(" ", (const char **)args->json_confs->hosts, args->json_confs->hosts_len);
        if (file_hosts == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        COMMAND_ERROR("unable to configure the isulad with file %s: "
                      "the following directives are specified both as a flag and in the configuration file: hosts: "
                      "(from flag: [%s], from file: [%s])",
                      ISULAD_DAEMON_JSON_CONF_FILE, flag_hosts, file_hosts);

        ret = -1;
    }

out:
    free(flag_hosts);
    free(file_hosts);
    return ret;
}

static int do_merge_conf_default_ulimit_into_global(struct service_arguments *args)
{
    size_t i, j, json_default_ulimit_len;
    isulad_daemon_configs_default_ulimits_element *ptr = NULL;

    if (args->json_confs->default_ulimits == NULL) {
        return 0;
    }

    json_default_ulimit_len = args->json_confs->default_ulimits->len;
    for (i = 0; i < json_default_ulimit_len; i++) {
        ptr = args->json_confs->default_ulimits->values[i];
        for (j = 0; j < args->default_ulimit_len; j++) {
            if (strcmp(ptr->name, args->default_ulimit[j]->name) == 0) {
                break;
            }
        }

        if (j < args->default_ulimit_len) {
            args->default_ulimit[j]->soft = ptr->soft;
            args->default_ulimit[j]->hard = ptr->hard;
            continue;
        }
        if (ulimit_array_append(&args->default_ulimit, (host_config_ulimits_element *)ptr, args->default_ulimit_len) !=
            0) {
            ERROR("merge json confs default ulimit config failed");
            return -1;
        }

        args->default_ulimit_len++;
    }

    return 0;
}

static int ulimit_flag_join(char *out_msg, const size_t msg_len, const size_t default_ulimit_len,
                            host_config_ulimits_element **default_ulimit)
{
    int ret = -1;
    size_t i;
    char *tmp = NULL;

    int nret = snprintf(out_msg, msg_len, "[");
    if (nret < 0 || nret >= msg_len) {
        ERROR("Failed to print string");
        goto out;
    }

    for (i = 0; i < default_ulimit_len; i++) {
        tmp = util_strdup_s(out_msg);
        nret = snprintf(out_msg, msg_len, "%s %s=%lld:%lld", tmp, default_ulimit[i]->name,
                        (long long int)default_ulimit[i]->soft, (long long int)default_ulimit[i]->hard);
        if (nret < 0 || nret >= msg_len) {
            ERROR("Failed to print string");
            goto out;
        }
        free(tmp);
        tmp = NULL;
    }

    tmp = util_strdup_s(out_msg);
    nret = snprintf(out_msg, msg_len, "%s ]", tmp);
    if (nret < 0 || nret >= msg_len) {
        ERROR("Failed to print string");
        goto out;
    }

    ret = 0;

out:
    free(tmp);
    return ret;
}

static int ulimit_file_join(char *out_msg, const size_t msg_len,
                            isulad_daemon_configs_default_ulimits_element **default_ulimits, size_t default_ulimits_len)
{
    int ret = -1;
    size_t i;
    char *tmp = NULL;
    isulad_daemon_configs_default_ulimits_element *ptr = NULL;

    int nret = snprintf(out_msg, msg_len, "[");
    if (nret < 0 || nret >= msg_len) {
        ERROR("Failed to print string");
        goto out;
    }
    for (i = 0; i < default_ulimits_len; i++) {
        ptr = default_ulimits[i];
        tmp = util_strdup_s(out_msg);
        nret = snprintf(out_msg, msg_len, "%s %s=%lld:%lld", tmp, ptr->name, (long long int)(ptr->soft),
                        (long long int)(ptr->hard));
        if (nret < 0 || nret >= msg_len) {
            ERROR("Failed to print string");
            goto out;
        }
        free(tmp);
        tmp = NULL;
    }

    tmp = util_strdup_s(out_msg);
    nret = snprintf(out_msg, msg_len, "%s ]", tmp);
    if (nret < 0 || nret >= msg_len) {
        ERROR("Failed to print string");
        goto out;
    }

    ret = 0;
out:
    free(tmp);
    return ret;
}

static int check_conf_default_ulimit(const struct service_arguments *args)
{
#define ULIMIT_MSG_MAX 1024
    int ret = 0;
    size_t i;
    char *type = NULL;
    isulad_daemon_configs_default_ulimits_element *ptr = NULL;

    if (args->json_confs->default_ulimits == NULL) {
        ret = 0;
        goto out;
    }

    /* check json_confs default_ulimits */
    for (i = 0; i < args->json_confs->default_ulimits->len; i++) {
        type = args->json_confs->default_ulimits->keys[i];
        ptr = args->json_confs->default_ulimits->values[i];
        if (ptr->soft > ptr->hard) {
            COMMAND_ERROR("Ulimit soft limit must be less than or equal to hard limit: %lld > %lld in %s",
                          (long long int)(ptr->soft), (long long int)(ptr->hard), ISULAD_DAEMON_JSON_CONF_FILE);
            ret = -1;
            goto out;
        }
        if (strcmp(ptr->name, type) != 0) {
            COMMAND_ERROR("Ulimit Name \"%s\" must same as type \"%s\" in %s", ptr->name, type,
                          ISULAD_DAEMON_JSON_CONF_FILE);
            ret = -1;
            goto out;
        }

        ret = check_default_ulimit_type(type);
        if (ret != 0) {
            goto out;
        }
    }

    /* check conflict */
    if (args->default_ulimit_len != 0) {
        char flag_def_ulimit[ULIMIT_MSG_MAX] = { 0 };
        char file_def_ulimit[ULIMIT_MSG_MAX] = { 0 };

        if (ulimit_flag_join(flag_def_ulimit, ULIMIT_MSG_MAX, args->default_ulimit_len, args->default_ulimit) != 0) {
            ret = -1;
            goto out;
        }

        if (ulimit_file_join(file_def_ulimit, ULIMIT_MSG_MAX, args->json_confs->default_ulimits->values,
                             args->json_confs->default_ulimits->len) != 0) {
            ret = -1;
            goto out;
        }

        COMMAND_ERROR("unable to configure the isulad with file %s: "
                      "the following directives are specified both as a flag and in the configuration file: "
                      "default-ulimits: (from flag: %s, from file: %s)",
                      ISULAD_DAEMON_JSON_CONF_FILE, flag_def_ulimit, file_def_ulimit);
        ret = -1;
    }

out:
    return ret;
}

int update_hosts(struct service_arguments *args)
{
    args->hosts_len = util_array_len((const char **)(args->hosts));

    if (check_hosts_specified_conflict(args) != 0) {
        return -1;
    }

    return do_merge_conf_hosts_into_global(args);
}

int update_default_ulimit(struct service_arguments *args)
{
    args->default_ulimit_len = ulimit_array_len(args->default_ulimit);

    if (check_conf_default_ulimit(args) != 0) {
        return -1;
    }

    return do_merge_conf_default_ulimit_into_global(args);
}
