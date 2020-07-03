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
 * Description: provide container server arguments functions
 ******************************************************************************/
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include "error.h"
#include "utils.h"
#include "daemon_arguments.h"
#include "err_msg.h"
#include "constants.h"
#include "isulad_config.h"
#include "isula_libutils/log.h"

static int set_daemon_default_tls_options(struct service_arguments *args)
{
    int ret = -1;
    char *tls = NULL;
    char *tmp_path = NULL;
    char *tls_verify = NULL;
    char *cert_path = NULL;
    char *ca_file = NULL;
    char *cert_file = NULL;
    char *key_file = NULL;

    tls = getenv("ISULAD_TLS");
    args->json_confs->tls = (tls != NULL && strlen(tls) != 0 && strcmp(tls, "0") != 0);
    tls = NULL;

    tls_verify = getenv("ISULAD_TLS_VERIFY");
    args->json_confs->tls_verify = (tls_verify != NULL && strlen(tls_verify) != 0 && strcmp(tls_verify, "0") != 0);
    tls_verify = NULL;

    tmp_path = getenv("ISULAD_CERT_PATH");
    if (tmp_path == NULL || strlen(tmp_path) == 0) {
        cert_path = util_strdup_s(ISULAD_CONFIG);
    } else {
        cert_path = util_strdup_s(tmp_path);
    }
    tmp_path = NULL;

    args->json_confs->tls_config =
        (isulad_daemon_configs_tls_config *)util_common_calloc_s(sizeof(isulad_daemon_configs_tls_config));
    if (args->json_confs->tls_config == NULL) {
        goto out;
    }

    ca_file = util_path_join(cert_path, DEFAULT_CA_FILE);
    if (ca_file == NULL) {
        goto out;
    }
    free(args->json_confs->tls_config->ca_file);
    args->json_confs->tls_config->ca_file = ca_file;

    key_file = util_path_join(cert_path, DEFAULT_KEY_FILE);
    if (key_file == NULL) {
        goto out;
    }
    free(args->json_confs->tls_config->key_file);
    args->json_confs->tls_config->key_file = key_file;

    cert_file = util_path_join(cert_path, DEFAULT_CERT_FILE);
    if (cert_file == NULL) {
        goto out;
    }
    free(args->json_confs->tls_config->cert_file);
    args->json_confs->tls_config->cert_file = cert_file;

    ret = 0;

out:
    free(cert_path);
    return ret;
}

int service_arguments_init(struct service_arguments *args)
{
#define DEFAULT_LOG_OPTS_LEN 3

    int ret = -1;
    if (args == NULL) {
        return -1;
    }
    args->argc = 0;
    args->argv = NULL;

    args->progname = util_strdup_s("isulad");
    args->quiet = true;
    args->help = false;
    args->version = false;

    args->json_confs = (isulad_daemon_configs *)util_common_calloc_s(sizeof(isulad_daemon_configs));
    if (args->json_confs == NULL) {
        goto free_out;
    }
    args->json_confs->engine = util_strdup_s("lcr");
    args->json_confs->group = util_strdup_s("isulad");
    args->json_confs->graph = util_strdup_s(ISULAD_ROOT_PATH);
    args->json_confs->state = util_strdup_s(ISULAD_STATE_PATH);
    args->json_confs->log_level = util_strdup_s("INFO");
    args->json_confs->log_driver = util_strdup_s("file");
    args->json_confs->log_opts = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if (args->json_confs->log_opts == NULL) {
        goto free_out;
    }
    args->json_confs->log_opts->keys = (char **)util_common_calloc_s(sizeof(char *) * DEFAULT_LOG_OPTS_LEN);
    if (args->json_confs->log_opts->keys == NULL) {
        goto free_out;
    }
    args->json_confs->log_opts->values = (char **)util_common_calloc_s(sizeof(char *) * DEFAULT_LOG_OPTS_LEN);
    if (args->json_confs->log_opts->values == NULL) {
        goto free_out;
    }
    args->json_confs->log_opts->len = DEFAULT_LOG_OPTS_LEN;
    args->json_confs->log_opts->keys[0] = util_strdup_s("log-file-mode");
    args->json_confs->log_opts->values[0] = util_strdup_s("0600");
    args->json_confs->log_opts->keys[1] = util_strdup_s("max-file");
    args->json_confs->log_opts->values[1] = util_strdup_s("7");
    args->json_confs->log_opts->keys[2] = util_strdup_s("max-size");
    args->json_confs->log_opts->values[2] = util_strdup_s("1MB");
    args->log_file_mode = 0600;
    args->max_file = 7;
    args->max_size = 1024 * 1024;

    args->json_confs->pidfile = util_strdup_s("/var/run/isulad.pid");
    args->json_confs->storage_driver = util_strdup_s("overlay2");
    args->json_confs->native_umask = util_strdup_s(UMASK_SECURE);
    args->json_confs->image_service = true;
    args->json_confs->image_layer_check = false;
    args->json_confs->use_decrypted_key = (bool *)util_common_calloc_s(sizeof(bool));
    if (args->json_confs->use_decrypted_key == NULL) {
        goto free_out;
    }
    *(args->json_confs->use_decrypted_key) = true;
    args->json_confs->insecure_skip_verify_enforce = false;

    args->image_opt_timeout = 5 * 60; // default image operation timeout 300s
    if (set_daemon_default_tls_options(args) != 0) {
        goto free_out;
    }

    args->default_ulimit = NULL;
    args->default_ulimit_len = 0;
    args->json_confs->websocket_server_listening_port = DEFAULT_WEBSOCKET_SERVER_LISTENING_PORT;
    args->json_confs->selinux_enabled = false;

    ret = 0;

free_out:
    if (ret != 0) {
        service_arguments_free(args);
    }
    return ret;
}

/* service arguments free */
void service_arguments_free(struct service_arguments *args)
{
    if (args == NULL) {
        return;
    }
    free(args->progname);
    args->progname = NULL;

    free(args->logpath);
    args->logpath = NULL;

    util_free_array_by_len(args->hosts, args->hosts_len);
    args->hosts = NULL;
    args->hosts_len = 0;

    free_isulad_daemon_configs(args->json_confs);
    args->json_confs = NULL;

    free_oci_runtime_spec_hooks(args->hooks);
    args->hooks = NULL;

    free_default_ulimit(args->default_ulimit);
    args->default_ulimit = NULL;
    args->default_ulimit_len = 0;
}

/* server log opt parser */
int server_log_opt_parser(struct service_arguments *args, const char *option)
{
    int ret = -1;
    char *key = NULL;
    char *value = NULL;
    char *tmp = NULL;
    size_t len = 0;
    size_t total_len = 0;

    if (option == NULL || args == NULL) {
        goto out;
    }

    // option format: key=value
    total_len = strlen(option);
    if (args == NULL || total_len <= 2) {
        goto out;
    }

    tmp = util_strdup_s(option);
    key = tmp;
    value = strchr(tmp, '=');
    // option do not contain '='
    if (value == NULL) {
        goto out;
    }

    len = (size_t)(value - key);
    // if option is '=key'
    if (len == 0) {
        goto out;
    }
    // if option is 'key='
    if (total_len == len + 1) {
        goto out;
    }
    tmp[len] = '\0';
    value += 1;

    ret = parse_log_opts(args, key, value);

    if (ret == 0 && args->json_confs != NULL && args->json_confs->log_opts != NULL) {
        ret = append_json_map_string_string(args->json_confs->log_opts, key, value);
    }

out:
    free(tmp);
    return ret;
}

size_t ulimit_array_len(host_config_ulimits_element **default_ulimit)
{
    size_t len = 0;
    host_config_ulimits_element **pos = NULL;

    for (pos = default_ulimit; pos != NULL && *pos != NULL; pos++) {
        len++;
    }

    return len;
}

int ulimit_array_append(host_config_ulimits_element ***ulimit_array, const host_config_ulimits_element *element,
                        const size_t len)
{
    int ret;
    size_t old_size, new_size;
    host_config_ulimits_element *new_element = NULL;
    host_config_ulimits_element **new_ulimit_array = NULL;

    if (ulimit_array == NULL || element == NULL) {
        return -1;
    }

    // let new len to len + 2 for element and null
    if (len > SIZE_MAX / sizeof(host_config_ulimits_element *) - 2) {
        ERROR("Too many ulimit elements!");
        return -1;
    }

    new_size = (len + 2) * sizeof(host_config_ulimits_element *);
    old_size = len * sizeof(host_config_ulimits_element *);

    ret = mem_realloc((void **)(&new_ulimit_array), new_size, (void *)*ulimit_array, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for append ulimit");
        return -1;
    }
    *ulimit_array = new_ulimit_array;

    new_element = util_common_calloc_s(sizeof(host_config_ulimits_element));
    if (new_element == NULL) {
        ERROR("Out of memory");
        free_default_ulimit(*ulimit_array);
        *ulimit_array = NULL;
        return -1;
    }

    new_element->name = util_strdup_s(element->name);
    new_element->hard = element->hard;
    new_element->soft = element->soft;
    new_ulimit_array[len] = new_element;

    return 0;
}

void free_default_ulimit(host_config_ulimits_element **default_ulimit)
{
    host_config_ulimits_element **p = NULL;

    for (p = default_ulimit; p != NULL && *p != NULL; p++) {
        free_host_config_ulimits_element(*p);
    }
    free(default_ulimit);
}