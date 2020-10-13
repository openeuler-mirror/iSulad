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
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide container client arguments functions
 ******************************************************************************/
#include "client_arguments.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <isula_libutils/json_common.h>

#include "error.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "constants.h"
#include "utils_array.h"
#include "utils_file.h"

client_connect_config_t get_connect_config(const struct client_arguments *args)
{
    client_connect_config_t config = { 0 };

    config.socket = args->socket;
    // unix socket not support tls
    if (strncmp(args->socket, "tcp://", strlen("tcp://"))) {
        config.tls_verify = false;
        config.tls = false;
        config.ca_file = NULL;
        config.cert_file = NULL;
        config.key_file = NULL;
    } else {
        config.tls = args->tls;
        config.tls_verify = args->tls_verify;

        if (args->tls_verify) {
            config.tls = true;
        }
        config.ca_file = args->ca_file;
        config.cert_file = args->cert_file;
        config.key_file = args->key_file;
    }
    return config;
}

static int set_default_tls_options(struct client_arguments *args)
{
    int ret = -1;
    char *tls = NULL;
    char *tls_verify = NULL;
    char *tmp_path = NULL;
    char *cert_path = NULL;
    char *ca_file = NULL;
    char *cert_file = NULL;
    char *key_file = NULL;

    tls = getenv("ISULAD_TLS");
    args->tls = (tls != NULL && strlen(tls) != 0 && strcmp(tls, "0") != 0);
    tls = NULL;

    tls_verify = getenv("ISULAD_TLS_VERIFY");
    args->tls_verify = (tls_verify != NULL && strlen(tls_verify) != 0 && strcmp(tls_verify, "0") != 0);
    tls_verify = NULL;

    tmp_path = getenv("ISULAD_CERT_PATH");
    if (tmp_path != NULL && strlen(tmp_path) != 0) {
        cert_path = util_strdup_s(tmp_path);
        ca_file = util_path_join(cert_path, DEFAULT_CA_FILE);
        if (ca_file == NULL) {
            goto out;
        }
        free(args->ca_file);

        args->ca_file = ca_file;
        key_file = util_path_join(cert_path, DEFAULT_KEY_FILE);
        if (key_file == NULL) {
            goto out;
        }
        free(args->key_file);

        args->key_file = key_file;

        cert_file = util_path_join(cert_path, DEFAULT_CERT_FILE);
        if (cert_file == NULL) {
            goto out;
        }
        free(args->cert_file);

        args->cert_file = cert_file;
    }

    ret = 0;

out:
    free(cert_path);
    return ret;
}

/* client arguments init */
int client_arguments_init(struct client_arguments *args)
{
    char *host = NULL;

    if (args == NULL) {
        return -1;
    }
    args->name = NULL;
    args->create_rootfs = NULL;
    args->argc = 0;
    args->argv = NULL;
    host = getenv("ISULAD_HOST");
    if (host != NULL && strlen(host) != 0) {
        args->socket = util_strdup_s(host);
    } else {
        args->socket = util_strdup_s(DEFAULT_UNIX_SOCKET);
    }

    (void)memset(&args->custom_conf, 0, sizeof(struct custom_configs));
    (void)memset(&args->cr, 0, sizeof(struct args_cgroup_resources));

    if (set_default_tls_options(args) != 0) {
        return -1;
    }

    // default swappiness should be set to -1
    args->cr.swappiness = -1;

    return 0;
}

/* client arguments free */
void client_arguments_free(struct client_arguments *args)
{
    int i;
    struct custom_configs *custom_conf = NULL;

    if (args == NULL) {
        return;
    }

    util_free_sensitive_string(args->username);
    util_free_sensitive_string(args->password);

    free(args->name);
    args->name = NULL;

    free(args->socket);
    args->socket = NULL;

    util_free_array(args->filters);
    args->filters = NULL;

    custom_conf = &(args->custom_conf);
    if (custom_conf == NULL) {
        return;
    }

    util_free_array(custom_conf->env);
    custom_conf->env = NULL;

    util_free_array(custom_conf->hugepage_limits);
    custom_conf->hugepage_limits = NULL;

    free(custom_conf->hook_spec);
    custom_conf->hook_spec = NULL;

    free(custom_conf->env_target_file);
    custom_conf->env_target_file = NULL;

    free(custom_conf->cgroup_parent);
    custom_conf->cgroup_parent = NULL;

    free(custom_conf->user);
    custom_conf->user = NULL;

    free(custom_conf->hostname);
    custom_conf->hostname = NULL;

    util_free_array(custom_conf->cap_adds);
    custom_conf->cap_adds = NULL;

    util_free_array(custom_conf->cap_drops);
    custom_conf->cap_drops = NULL;

    util_free_array(custom_conf->storage_opts);
    custom_conf->storage_opts = NULL;

    util_free_array(custom_conf->sysctls);
    custom_conf->sysctls = NULL;

    util_free_array(custom_conf->volumes);
    custom_conf->volumes = NULL;

    util_free_array(custom_conf->volumes_from);
    custom_conf->volumes_from = NULL;

    util_free_array(custom_conf->mounts);
    custom_conf->mounts = NULL;

    util_free_array(custom_conf->tmpfs);
    custom_conf->tmpfs = NULL;

    free(custom_conf->entrypoint);
    custom_conf->entrypoint = NULL;

    util_free_array(custom_conf->ulimits);
    custom_conf->ulimits = NULL;

    util_free_array(custom_conf->devices);
    custom_conf->devices = NULL;

    util_free_array(custom_conf->weight_devices);
    custom_conf->weight_devices = NULL;

    for (i = 0; i < NAMESPACE_MAX; i++) {
        free(custom_conf->share_ns[i]);
        custom_conf->share_ns[i] = NULL;
    }

    free(args->create_rootfs);
    args->create_rootfs = NULL;

    free(args->log_driver);
    args->log_driver = NULL;

    free_json_map_string_string(args->annotations);
    args->annotations = NULL;

    free(custom_conf->workdir);
    custom_conf->workdir = NULL;

    util_free_array(custom_conf->security);
    custom_conf->security = NULL;

    free(args->ca_file);
    args->ca_file = NULL;

    free(args->cert_file);
    args->cert_file = NULL;

    free(args->key_file);
    args->key_file = NULL;

    util_free_array(custom_conf->blkio_throttle_read_bps_device);
    custom_conf->blkio_throttle_read_bps_device = NULL;

    util_free_array(custom_conf->blkio_throttle_write_bps_device);
    custom_conf->blkio_throttle_write_bps_device = NULL;

    util_free_array(custom_conf->blkio_throttle_read_iops_device);
    custom_conf->blkio_throttle_read_iops_device = NULL;

    util_free_array(custom_conf->blkio_throttle_write_iops_device);
    custom_conf->blkio_throttle_write_iops_device = NULL;

    util_free_array(custom_conf->device_cgroup_rules);
    custom_conf->device_cgroup_rules = NULL;

    free(custom_conf->stop_signal);
    custom_conf->stop_signal = NULL;

    free(custom_conf->driver);
    custom_conf->driver = NULL;

    free(custom_conf->gateway);
    custom_conf->gateway = NULL;

    free(custom_conf->subnet);
    custom_conf->subnet = NULL;

    free(args->network_name);
    args->network_name = NULL;
}

/* print common help */
void print_common_help()
{
    struct client_arguments cmd_common_args = {};
    struct command_option options[] = { COMMON_OPTIONS(cmd_common_args) VERSION_OPTIONS(cmd_common_args) };
    size_t len = sizeof(options) / sizeof(options[0]);
    qsort(options, len, sizeof(options[0]), compare_options);
    fprintf(stdout, "COMMON OPTIONS :\n");
    print_options((int)len, options);
}

/* client print error */
void client_print_error(uint32_t cc, uint32_t server_errono, const char *errmsg)
{
    switch (server_errono) {
        case ISULAD_SUCCESS:
            if (errmsg != NULL) {
                COMMAND_ERROR("%s", errmsg);
            }
            break;
        default:
            if (errmsg != NULL) {
                COMMAND_ERROR("Error response from daemon: %s", errmsg);
            } else {
                COMMAND_ERROR("%s", errno_to_error_message(server_errono));
            }
            break;
    }
}
