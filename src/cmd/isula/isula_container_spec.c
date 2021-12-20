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
 * Create: 2020-09-28
 * Description: provide generate container spec in client
 ******************************************************************************/
#include "isula_container_spec.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <isula_libutils/defs.h>
#include <isula_libutils/json_common.h>
#include <stdint.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "isula_libutils/container_config.h"
#include "utils_array.h"
#include "utils_string.h"
#include "utils_verify.h"

static int pack_container_custom_config_args(container_config *container_spec,
                                             const isula_container_config_t *custom_conf)
{
    int ret = 0;
    int i;

    /* entrypoint */
    if (util_valid_str(custom_conf->entrypoint)) {
        container_spec->entrypoint = util_common_calloc_s(sizeof(char *));
        if (container_spec->entrypoint == NULL) {
            ret = -1;
            goto out;
        }
        container_spec->entrypoint[0] = util_strdup_s(custom_conf->entrypoint);
        container_spec->entrypoint_len++;
    }

    /* commands */
    if ((custom_conf->cmd_len != 0 && custom_conf->cmd)) {
        if (custom_conf->cmd_len > SIZE_MAX / sizeof(char *)) {
            COMMAND_ERROR("The length of cmd is too long!");
            ret = -1;
            goto out;
        }
        container_spec->cmd = util_common_calloc_s(custom_conf->cmd_len * sizeof(char *));
        if (container_spec->cmd == NULL) {
            ret = -1;
            goto out;
        }
        for (i = 0; i < (int)custom_conf->cmd_len; i++) {
            container_spec->cmd[container_spec->cmd_len] = util_strdup_s(custom_conf->cmd[i]);
            container_spec->cmd_len++;
        }
    }

out:
    return ret;
}

static int pack_container_custom_config_array(container_config *container_spec,
                                              const isula_container_config_t *custom_conf)
{
    int ret = 0;
    int i = 0;

    /* environment variables */
    if (custom_conf->env_len != 0 && custom_conf->env) {
        if (custom_conf->env_len > SIZE_MAX / sizeof(char *)) {
            COMMAND_ERROR("Too many environment variables");
            return -1;
        }
        container_spec->env = util_common_calloc_s(custom_conf->env_len * sizeof(char *));
        if (container_spec->env == NULL) {
            ret = -1;
            goto out;
        }
        for (i = 0; i < (int)custom_conf->env_len; i++) {
            container_spec->env[container_spec->env_len] = util_strdup_s(custom_conf->env[i]);
            container_spec->env_len++;
        }
    }

out:
    return ret;
}

static int get_label_key_value(const char *label, char **key, char **value)
{
    int ret = 0;
    char **arr = util_string_split_n(label, '=', 2);
    if (arr == NULL) {
        ERROR("Failed to split input label");
        ret = -1;
        goto out;
    }

    *key = util_strdup_s(arr[0]);
    if (util_array_len((const char **)arr) == 1) {
        *value = util_strdup_s("");
    } else {
        *value = util_strdup_s(arr[1]);
    }

out:
    util_free_array(arr);
    return ret;
}

static int pack_container_custom_config_labels(container_config *container_spec,
                                               const isula_container_config_t *custom_conf)
{
    int ret = 0;
    int i;
    char *key = NULL;
    char *value = NULL;

    if (custom_conf->label_len == 0 || custom_conf->label == NULL) {
        return 0;
    }

    /* labels */
    container_spec->labels = util_common_calloc_s(sizeof(json_map_string_string));
    if (container_spec->labels == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < custom_conf->label_len; i++) {
        if (get_label_key_value(custom_conf->label[i], &key, &value) != 0) {
            ERROR("Failed to get key and value of label");
            ret = -1;
            goto out;
        }

        if (append_json_map_string_string(container_spec->labels, key, value)) {
            ERROR("Append map failed");
            ret = -1;
            goto out;
        }
        free(key);
        key = NULL;
        free(value);
        value = NULL;
    }

out:
    free(key);
    free(value);
    return ret;
}

static bool have_health_check(const isula_container_config_t *custom_conf)
{
    bool have_health_settings = false;

    if ((custom_conf->health_cmd != NULL && strlen(custom_conf->health_cmd) != 0) ||
        custom_conf->health_interval != 0 || custom_conf->health_timeout != 0 ||
        custom_conf->health_start_period != 0 || custom_conf->health_retries != 0) {
        have_health_settings = true;
    }

    return have_health_settings;
}

static int pack_custom_no_health_check(container_config *container_spec, bool have_health_settings,
                                       defs_health_check *health_config)
{
    int ret = 0;

    if (have_health_settings) {
        COMMAND_ERROR("--no-healthcheck conflicts with --health-* options");
        ret = -1;
        goto out;
    }
    health_config->test = util_common_calloc_s(sizeof(char *));
    if (health_config->test == NULL) {
        ret = -1;
        goto out;
    }
    health_config->test[health_config->test_len++] = util_strdup_s("NONE");
    container_spec->healthcheck = health_config;

out:
    return ret;
}

static int pack_custom_with_health_check(container_config *container_spec, const isula_container_config_t *custom_conf,
                                         bool have_health_settings, defs_health_check *health_config)
{
    int ret = 0;

    if (custom_conf->health_cmd != NULL && strlen(custom_conf->health_cmd) != 0) {
        health_config->test = util_common_calloc_s(2 * sizeof(char *));
        if (health_config->test == NULL) {
            ret = -1;
            goto out;
        }
        health_config->test[health_config->test_len++] = util_strdup_s("CMD-SHELL");
        health_config->test[health_config->test_len++] = util_strdup_s(custom_conf->health_cmd);
    } else {
        COMMAND_ERROR("--health-cmd required!");
        ret = -1;
        goto out;
    }
    health_config->interval = custom_conf->health_interval;
    health_config->timeout = custom_conf->health_timeout;
    health_config->start_period = custom_conf->health_start_period;
    health_config->retries = custom_conf->health_retries;
    health_config->exit_on_unhealthy = custom_conf->exit_on_unhealthy;
    if (container_spec->healthcheck != NULL) {
        free_defs_health_check(container_spec->healthcheck);
    }
    container_spec->healthcheck = health_config;

out:
    return ret;
}

static int pack_container_custom_config_health(container_config *container_spec,
                                               const isula_container_config_t *custom_conf)
{
    int ret = 0;
    bool have_health_settings = false;
    defs_health_check *health_config = NULL;

    if (container_spec == NULL || custom_conf == NULL) {
        return 0;
    }

    have_health_settings = have_health_check(custom_conf);

    health_config = util_common_calloc_s(sizeof(defs_health_check));
    if (health_config == NULL) {
        ret = -1;
        goto out;
    }

    if (custom_conf->no_healthcheck) {
        ret = pack_custom_no_health_check(container_spec, have_health_settings, health_config);
        if (ret != 0) {
            goto out;
        }
    } else if (have_health_settings) {
        ret = pack_custom_with_health_check(container_spec, custom_conf, have_health_settings, health_config);
        if (ret != 0) {
            goto out;
        }
    } else {
        goto out;
    }

    return ret;

out:
    free_defs_health_check(health_config);
    return ret;
}

static int pack_container_custom_config_annotation(container_config *container_spec,
                                                   const isula_container_config_t *custom_conf)
{
    int ret = 0;
    size_t j;

    container_spec->annotations = util_common_calloc_s(sizeof(json_map_string_string));
    if (container_spec->annotations == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    if (custom_conf->annotations != NULL) {
        for (j = 0; j < custom_conf->annotations->len; j++) {
            if (append_json_map_string_string(container_spec->annotations, custom_conf->annotations->keys[j],
                                              custom_conf->annotations->values[j])) {
                ERROR("Append map failed");
                ret = -1;
                goto out;
            }
        }
    }
out:
    return ret;
}

static int pack_container_custom_config_pre(container_config *container_spec,
                                            const isula_container_config_t *custom_conf)
{
    int ret = 0;

    ret = pack_container_custom_config_args(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }

    ret = pack_container_custom_config_array(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }

    ret = pack_container_custom_config_labels(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }

    ret = pack_container_custom_config_health(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }

out:
    return ret;
}

/* translate create_custom_config to container_config */
static int pack_container_custom_config(container_config *container_spec, const isula_container_config_t *custom_conf)
{
    int ret = -1;

    if (container_spec == NULL || custom_conf == NULL) {
        return ret;
    }

    ret = pack_container_custom_config_pre(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }

    if (custom_conf->hostname != NULL) {
        container_spec->hostname = util_strdup_s(custom_conf->hostname);
    }
    container_spec->log_driver = util_strdup_s(custom_conf->log_driver);

    /* console config */
    container_spec->tty = custom_conf->tty;
    container_spec->open_stdin = custom_conf->open_stdin;
    container_spec->attach_stdin = custom_conf->attach_stdin;
    container_spec->attach_stdout = custom_conf->attach_stdout;
    container_spec->attach_stderr = custom_conf->attach_stderr;

    /* user and group */
    if (custom_conf->user != NULL) {
        container_spec->user = util_strdup_s(custom_conf->user);
    }

    /* settings for system container */
    if (custom_conf->system_container) {
        container_spec->system_container = custom_conf->system_container;
    }

    if (custom_conf->ns_change_opt != NULL) {
        container_spec->ns_change_opt = util_strdup_s(custom_conf->ns_change_opt);
    }

    ret = pack_container_custom_config_annotation(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }

    if (custom_conf->workdir != NULL) {
        container_spec->working_dir = util_strdup_s(custom_conf->workdir);
    }

    if (custom_conf->stop_signal != NULL) {
        container_spec->stop_signal = util_strdup_s(custom_conf->stop_signal);
    }

#ifdef ENABLE_NATIVE_NETWORK
    if (custom_conf->expose != NULL && custom_conf->expose->len != 0) {
        container_spec->exposed_ports = util_common_calloc_s(sizeof(defs_map_string_object));
        if (container_spec->exposed_ports == NULL) {
            ret = -1;
            goto out;
        }
        container_spec->exposed_ports->keys = util_common_calloc_s(custom_conf->expose->len * sizeof(char*));
        if (container_spec->exposed_ports->keys == NULL) {
            ret = -1;
            goto out;
        }
        container_spec->exposed_ports->values = util_common_calloc_s(custom_conf->expose->len * sizeof(
                                                                         defs_map_string_object_element*));
        if (container_spec->exposed_ports->values == NULL) {
            free(container_spec->exposed_ports->keys);
            container_spec->exposed_ports->keys = NULL;
            ret = -1;
            goto out;
        }
        for (size_t i = 0; i < custom_conf->expose->len; i++) {
            container_spec->exposed_ports->keys[i] = util_strdup_s(custom_conf->expose->keys[i]);
        }
        container_spec->exposed_ports->len = custom_conf->expose->len;
    }
#endif

out:
    return ret;
}

int generate_container_config(const isula_container_config_t *custom_conf, char **container_config_str)
{
    int ret = 0;
    container_config *container_spec = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;

    /* step 1: malloc the container config */
    container_spec = util_common_calloc_s(sizeof(container_config));
    if (container_spec == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    /* step 2: pack the container custom config */
    ret = pack_container_custom_config(container_spec, custom_conf);
    if (ret != 0) {
        ERROR("Failed to pack the container custom config");
        ret = -1;
        goto out;
    }

    /* step 3: generate the config string */
    *container_config_str = container_config_generate_json(container_spec, &ctx, &err);
    if (*container_config_str == NULL) {
        ERROR("Failed to generate OCI specification json string");
        ret = -1;
        goto out;
    }

out:
    free_container_config(container_spec);
    free(err);

    return ret;
}

/* isula container config free */
void isula_container_config_free(isula_container_config_t *config)
{
    if (config == NULL) {
        return;
    }

    util_free_array_by_len(config->env, config->env_len);
    config->env = NULL;
    config->env_len = 0;

    free(config->hostname);
    config->hostname = NULL;

    free(config->user);
    config->user = NULL;

    util_free_array_by_len(config->cmd, config->cmd_len);
    config->cmd = NULL;
    config->cmd_len = 0;

    free(config->entrypoint);
    config->entrypoint = NULL;

    free(config->log_driver);
    config->log_driver = NULL;

    free_json_map_string_string(config->annotations);
    config->annotations = NULL;

    free(config->workdir);
    config->workdir = NULL;

    free(config->stop_signal);
    config->stop_signal = NULL;

#ifdef ENABLE_NATIVE_NETWORK
    free_defs_map_string_object(config->expose);
    config->expose = NULL;
#endif

    free(config);
}
