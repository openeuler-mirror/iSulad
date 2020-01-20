/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2017-11-22
 * Description: provide container unix functions
 ******************************************************************************/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>

#include "constants.h"
#include "container_unix.h"
#include "log.h"
#include "utils.h"
#include "container_custom_config.h"
#include "container_start_generate_config.h"

static int parse_container_log_configs(container_t *cont);

static int init_container_mutex(container_t *cont)
{
    int ret = 0;

    ret = pthread_mutex_init(&(cont->mutex), NULL);
    if (ret != 0) {
        ERROR("Failed to init mutex of container");
        ret = -1;
        goto out;
    }
    cont->init_mutex = true;

    ret = pthread_cond_init(&(cont->wait_stop_con), NULL);
    if (ret != 0) {
        ERROR("Failed to init wait stop condition of container");
        ret = -1;
        goto out;
    }
    cont->init_wait_stop_con = true;

    ret = pthread_cond_init(&(cont->wait_rm_con), NULL);
    if (ret != 0) {
        ERROR("Failed to init wait remove condition of container");
        ret = -1;
        goto out;
    }
    cont->init_wait_rm_con = true;

out:
    return ret;
}

/* notes: hostconfig and common_config will be free in this function on error */
container_t *container_new(const char *runtime, const char *rootpath, const char *statepath, const char *image_id,
                           host_config **hostconfig, container_config_v2_common_config **common_config)
{
    int ret = 0;
    container_t *cont = NULL;
    host_config *tmp_host_config = NULL;
    container_config_v2_common_config *tmp_common_config = NULL;

    if (common_config == NULL || *common_config == NULL || rootpath == NULL || statepath == NULL ||
        hostconfig == NULL || *hostconfig == NULL || runtime == NULL) {
        return NULL;
    }

    tmp_host_config = *hostconfig;
    tmp_common_config = *common_config;

    *hostconfig = NULL;
    *common_config = NULL;

    cont = util_common_calloc_s(sizeof(container_t));
    if (cont == NULL) {
        free_container_config_v2_common_config(tmp_common_config);
        free_host_config(tmp_host_config);
        ERROR("Out of memory");
        return NULL;
    }

    atomic_int_set(&cont->refcnt, 1);
    cont->common_config = tmp_common_config;
    cont->hostconfig = tmp_host_config;

    ret = init_container_mutex(cont);
    if (ret != 0) {
        goto error_out;
    }

    ret = parse_container_log_configs(cont);
    if (ret != 0) {
        goto error_out;
    }

    cont->runtime = util_strdup_s(runtime);
    cont->root_path = util_strdup_s(rootpath);
    cont->state_path = util_strdup_s(statepath);
    cont->image_id = image_id != NULL ? util_strdup_s(image_id) : NULL;
    cont->state = container_state_new();
    if (cont->state == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }

    cont->rm = restart_manager_new(tmp_host_config->restart_policy,
                                   tmp_common_config->restart_count);
    if (cont->rm == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }

    cont->handler = events_handler_new();
    if (cont->handler == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }

    return cont;

error_out:
    container_unref(cont);
    return NULL;
}

/* container free */
void container_free(container_t *container)
{
    if (container == NULL) {
        return;
    }

    free_container_config_v2_common_config(container->common_config);
    container->common_config = NULL;

    container_state_free(container->state);
    container->state = NULL;

    free(container->runtime);
    container->runtime = NULL;
    free(container->root_path);
    container->root_path = NULL;
    free(container->state_path);
    container->state_path = NULL;
    free(container->image_id);
    container->image_id = NULL;

    free(container->log_path);
    container->log_path = NULL;

    free_host_config(container->hostconfig);

    restart_manager_unref(container->rm);

    events_handler_free(container->handler);

    health_check_manager_free(container->health_check);

    if (container->init_wait_stop_con) {
        pthread_cond_destroy(&container->wait_stop_con);
    }

    if (container->init_wait_rm_con) {
        pthread_cond_destroy(&container->wait_rm_con);
    }

    if (container->init_mutex) {
        pthread_mutex_destroy(&container->mutex);
    }

    free(container);
}

/* container refinc */
void container_refinc(container_t *cont)
{
    if (cont == NULL) {
        return;
    }
    atomic_int_inc(&cont->refcnt);
}

/* container unref */
void container_unref(container_t *cont)
{
    bool is_zero = false;

    if (cont == NULL) {
        return;
    }

    is_zero = atomic_int_dec_test(&cont->refcnt);
    if (!is_zero) {
        return;
    }

    container_free(cont);
}

/* container lock */
void container_lock(container_t *cont)
{
    if (cont == NULL) {
        ERROR("Invalid input arguments");
        return;
    }

    if (pthread_mutex_lock(&cont->mutex) != 0) {
        ERROR("Failed to lock container '%s'", cont->common_config->id);
    }
}

/* container timedlock */
int container_timedlock(container_t *cont, int timeout)
{
    struct timespec ts;

    if (cont == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    if (timeout <= 0) {
        return pthread_mutex_lock(&cont->mutex);
    } else {
        if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
            ERROR("Failed to get real time");
            return -1;
        }
        ts.tv_sec += timeout;

        return pthread_mutex_timedlock(&cont->mutex, &ts);
    }
}


/* container unlock */
void container_unlock(container_t *cont)
{
    if (cont == NULL) {
        ERROR("Invalid input arguments");
        return;
    }

    if (pthread_mutex_unlock(&cont->mutex) != 0) {
        ERROR("Failed to unlock container '%s'", cont->common_config->id);
    }
}

/* container wait stop cond broadcast */
void container_wait_stop_cond_broadcast(container_t *cont)
{
    if (cont == NULL) {
        ERROR("Invalid input arguments");
        return;
    }
    if (pthread_cond_broadcast(&cont->wait_stop_con) != 0) {
        ERROR("Failed to broadcast wait stop condition container '%s'", cont->common_config->id);
    }
}

/* container wait stop cond wait */
static int container_wait_stop_cond_wait(container_t *cont, int timeout)
{
    struct timespec ts;

    if (timeout < 0) {
        return pthread_cond_wait(&cont->wait_stop_con, &cont->mutex);
    }

    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        ERROR("Failed to get real time");
        return -1;
    }
    ts.tv_sec += timeout;

    return pthread_cond_timedwait(&cont->wait_stop_con, &cont->mutex, &ts);
}

/* container wait remove cond broadcast */
void container_wait_rm_cond_broadcast(container_t *cont)
{
    if (cont == NULL) {
        ERROR("Invalid input arguments");
        return;
    }
    if (pthread_cond_broadcast(&cont->wait_rm_con)) {
        ERROR("Failed to broadcast wait remove condition container '%s'", cont->common_config->id);
    }
}

/* container wait remove cond wait */
static int container_wait_rm_cond_wait(container_t *cont, int timeout)
{
    struct timespec ts;

    if (timeout < 0) {
        return pthread_cond_wait(&cont->wait_rm_con, &cont->mutex);
    }

    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        ERROR("Failed to get real time");
        return -1;
    }
    ts.tv_sec += timeout;

    return pthread_cond_timedwait(&cont->wait_rm_con, &cont->mutex, &ts);
}

/* container wait remove with locking */
int container_wait_rm_locking(container_t *cont, int timeout)
{
    int ret = 0;

    if (cont == NULL) {
        return -1;
    }

    container_lock(cont);

    ret = container_wait_rm_cond_wait(cont, timeout);

    container_unlock(cont);

    return ret;
}

static int pack_container_config_annotations_from_oci_spec(const oci_runtime_spec *oci_spec,
                                                           container_config_v2_common_config *v2_spec)
{
    int ret = 0;
    size_t i = 0;

    if (oci_spec->annotations != NULL && oci_spec->annotations->len) {
        if (v2_spec->config == NULL) {
            v2_spec->config = util_common_calloc_s(sizeof(container_config));
            if (v2_spec->config == NULL) {
                ERROR("Out of memory");
                ret = -1;
                goto out;
            }
        }
        v2_spec->config->annotations = util_common_calloc_s(sizeof(json_map_string_string));
        if (v2_spec->config->annotations == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        if (oci_spec->annotations->len > SIZE_MAX / sizeof(char *)) {
            ERROR("Annotations list is too long!");
            ret = -1;
            goto out;
        }
        v2_spec->config->annotations->keys =
            util_common_calloc_s(sizeof(char *) * oci_spec->annotations->len);
        if (v2_spec->config->annotations->keys == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        v2_spec->config->annotations->values =
            util_common_calloc_s(sizeof(char *) * oci_spec->annotations->len);
        if (v2_spec->config->annotations->values == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }

        for (i = 0; i < oci_spec->annotations->len; i++) {
            v2_spec->config->annotations->keys[i] = util_strdup_s(oci_spec->annotations->keys[i]);
            v2_spec->config->annotations->values[i] = util_strdup_s(oci_spec->annotations->values[i]);
            v2_spec->config->annotations->len++;
        }
    }

out:
    return ret;
}

static int pack_container_config_labels(container_config_v2_common_config *config,
                                        const container_custom_config *custom_spec)
{
    int ret = 0;
    size_t i = 0;

    if (custom_spec->labels != NULL && custom_spec->labels->len) {
        if (config->config == NULL) {
            config->config = util_common_calloc_s(sizeof(container_config));
            if (config->config == NULL) {
                ERROR("Out of memory");
                ret = -1;
                goto out;
            }
        }
        config->config->labels = util_common_calloc_s(sizeof(json_map_string_string));
        if (config->config->labels == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        if (custom_spec->labels->len > LIST_SIZE_MAX) {
            ERROR("Labels list is too long, the limit is %d", LIST_SIZE_MAX);
            isulad_set_error_message("Labels list is too long, the limit is %d", LIST_SIZE_MAX);
            ret = -1;
            goto out;
        }
        config->config->labels->keys = util_common_calloc_s(sizeof(char *) * custom_spec->labels->len);
        if (config->config->labels->keys == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        config->config->labels->values = util_common_calloc_s(sizeof(char *) * custom_spec->labels->len);
        if (config->config->labels->values == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }

        for (i = 0; i < custom_spec->labels->len; i++) {
            config->config->labels->keys[i] = util_strdup_s(custom_spec->labels->keys[i]);
            config->config->labels->values[i] = util_strdup_s(custom_spec->labels->values[i]);
            config->config->labels->len++;
        }
    }

out:
    return ret;
}

static int pack_container_config_health_check(container_config_v2_common_config *config,
                                              const container_custom_config *custom_spec)
{
    int ret = 0;
    size_t i = 0;

    if (custom_spec != NULL && custom_spec->health_check != NULL) {
        if (config->config == NULL) {
            config->config = util_common_calloc_s(sizeof(container_config));
            if (config->config == NULL) {
                ERROR("Out of memory");
                ret = -1;
                goto out;
            }
        }
        config->config->health_check = util_common_calloc_s(sizeof(defs_health_check));
        if (config->config->health_check == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }

        if (custom_spec->health_check->test != NULL && custom_spec->health_check->test_len != 0) {
            if (custom_spec->health_check->test_len > SIZE_MAX / sizeof(char *)) {
                ERROR("test list is too long!");
                ret = -1;
                goto out;
            }
            config->config->health_check->test =
                util_common_calloc_s(sizeof(char *) * custom_spec->health_check->test_len);
            if (config->config->health_check->test == NULL) {
                ERROR("Out of memory");
                ret = -1;
                goto out;
            }
            for (i = 0; i < custom_spec->health_check->test_len; i++) {
                config->config->health_check->test[i] = util_strdup_s(custom_spec->health_check->test[i]);
                config->config->health_check->test_len++;
            }

            config->config->health_check->interval = custom_spec->health_check->interval;
            config->config->health_check->timeout = custom_spec->health_check->timeout;
            config->config->health_check->start_period = custom_spec->health_check->start_period;
            config->config->health_check->retries = custom_spec->health_check->retries;
            config->config->health_check->exit_on_unhealthy = custom_spec->health_check->exit_on_unhealthy;
        }
    }
out:
    return ret;
}

static inline void add_to_config_v2_args(const char *str, char **args, size_t *args_len)
{
    args[*args_len] = str ? util_strdup_s(str) : NULL;
    (*args_len)++;
}

static int pack_path_and_args_from_custom_spec(const container_custom_config *custom_spec,
                                               container_config_v2_common_config *v2_spec)
{
    int ret = 0;
    size_t i, total;

    if (custom_spec->entrypoint != NULL && custom_spec->entrypoint_len > 0) {
        v2_spec->path = util_strdup_s(custom_spec->entrypoint[0]);
        total = custom_spec->entrypoint_len + custom_spec->cmd_len - 1;

        if (total > SIZE_MAX / sizeof(char *)) {
            ERROR("Container oci spec process args elements is too much!");
            ret = -1;
            goto out;
        }
        if (total == 0) {
            goto out;
        }

        v2_spec->args = util_common_calloc_s(total * sizeof(char *));
        if (v2_spec->args == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        for (i = 1; i < custom_spec->entrypoint_len; i++) {
            add_to_config_v2_args(custom_spec->entrypoint[i], v2_spec->args, &(v2_spec->args_len));
        }
        for (i = 0; i < custom_spec->cmd_len; i++) {
            add_to_config_v2_args(custom_spec->cmd[i], v2_spec->args, &(v2_spec->args_len));
        }
        goto out;
    }

    if (custom_spec->cmd != NULL && custom_spec->cmd_len > 0) {
        v2_spec->path = util_strdup_s(custom_spec->cmd[0]);
        total = custom_spec->cmd_len - 1;

        if (total > SIZE_MAX / sizeof(char *)) {
            ERROR("Container oci spec process args elements is too much!");
            ret = -1;
            goto out;
        }
        if (total == 0) {
            goto out;
        }

        v2_spec->args = util_common_calloc_s(total * sizeof(char *));
        if (v2_spec->args == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        for (i = 1; i < custom_spec->cmd_len; i++) {
            add_to_config_v2_args(custom_spec->cmd[i], v2_spec->args, &(v2_spec->args_len));
        }
    }

out:
    return ret;
}

/* container make basic v2 spec info */
int v2_spec_make_basic_info(const char *id, const char *name, const char *image_name, const char *image_type,
                            container_config_v2_common_config *v2_spec)
{
    char timebuffer[TIME_STR_SIZE] = { 0 };

    if (v2_spec == NULL) {
        return -1;
    }

    v2_spec->id = id ? util_strdup_s(id) : NULL;
    v2_spec->name = name ? util_strdup_s(name) : NULL;
    v2_spec->image = image_name ? util_strdup_s(image_name) : util_strdup_s("none");
    v2_spec->image_type = image_type ? util_strdup_s(image_type) : NULL;
    (void)get_now_time_buffer(timebuffer, sizeof(timebuffer));
    free(v2_spec->created);
    v2_spec->created = util_strdup_s(timebuffer);

    return 0;
}

/* container merge basic v2 spec info */
int v2_spec_merge_custom_spec(const container_custom_config *custom_spec, container_config_v2_common_config *v2_spec)
{
    int ret = 0;

    if (v2_spec == NULL || custom_spec == NULL) {
        return -1;
    }

    if (custom_spec->log_config != NULL && custom_spec->log_config->log_file != NULL) {
        v2_spec->log_path = util_strdup_s(custom_spec->log_config->log_file);
    }

    if (v2_spec->config == NULL) {
        v2_spec->config = util_common_calloc_s(sizeof(container_config));
        if (v2_spec->config == NULL) {
            ERROR("Failed to malloc container_config_v2_common_config_config");
            ret = -1;
            goto out;
        }
    }

    v2_spec->config->attach_stdin = custom_spec->attach_stdin;
    v2_spec->config->attach_stdout = custom_spec->attach_stdout;
    v2_spec->config->attach_stderr = custom_spec->attach_stderr;
    v2_spec->config->tty = custom_spec->tty;
    v2_spec->config->open_stdin = custom_spec->open_stdin;

    if (custom_spec->user != NULL) {
        v2_spec->config->user = util_strdup_s(custom_spec->user);
    }

    if (pack_path_and_args_from_custom_spec(custom_spec, v2_spec) != 0) {
        ret = -1;
        goto out;
    }


    ret = dup_array_of_strings((const char **)(custom_spec->cmd), custom_spec->cmd_len,
                               &(v2_spec->config->cmd), &(v2_spec->config->cmd_len));
    if (ret != 0) {
        goto out;
    }

    ret = dup_array_of_strings((const char **)(custom_spec->entrypoint), custom_spec->entrypoint_len,
                               &(v2_spec->config->entrypoint), &(v2_spec->config->entrypoint_len));
    if (ret != 0) {
        goto out;
    }

    ret = pack_container_config_labels(v2_spec, custom_spec);
    if (ret != 0) {
        ERROR("Failed to pack labels config");
        ret = -1;
        goto out;
    }

    ret = pack_container_config_health_check(v2_spec, custom_spec);
    if (ret != 0) {
        ERROR("Failed to pack health check config");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int pack_envs_from_oci_spec(const oci_runtime_spec *oci_spec, const container_config_v2_common_config *v2_spec)
{
    int ret = 0;

    if (oci_spec->process != NULL && oci_spec->process->env != NULL) {
        ret = dup_array_of_strings((const char **)(oci_spec->process->env), oci_spec->process->env_len,
                                   &(v2_spec->config->env), &(v2_spec->config->env_len));
        if (ret != 0) {
            goto out;
        }
    }

out:
    return ret;
}

static void pack_hostname_from_oci_spec(const oci_runtime_spec *oci_spec,
                                        const container_config_v2_common_config *v2_spec)
{
    if (oci_spec->hostname != NULL) {
        free(v2_spec->config->hostname);
        v2_spec->config->hostname = util_strdup_s(oci_spec->hostname);
    }
}

/* container pack common config */
int v2_spec_merge_oci_spec(const oci_runtime_spec *oci_spec, container_config_v2_common_config *v2_spec)
{
    if (oci_spec == NULL || v2_spec == NULL) {
        ERROR("Invalid inputs for pack container common config");
        return -1;
    }

    if (pack_envs_from_oci_spec(oci_spec, v2_spec) != 0) {
        return -1;
    }

    pack_hostname_from_oci_spec(oci_spec, v2_spec);

    if (pack_container_config_annotations_from_oci_spec(oci_spec, v2_spec) != 0) {
        ERROR("Failed to pack annotations config");
        return -1;
    }

    return 0;
}

/* save json config file */
static int save_json_config_file(const char *id, const char *rootpath,
                                 const char *json_data, const char *fname)
{
    int ret = 0;
    int nret;
    int fd = -1;
    ssize_t len = 0;
    char filename[PATH_MAX] = { 0 };

    if (json_data == NULL || strlen(json_data) == 0) {
        return 0;
    }
    nret = snprintf(filename, sizeof(filename), "%s/%s/%s", rootpath, id, fname);
    if (nret < 0 || (size_t)nret >= sizeof(filename)) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }

    fd = util_open(filename, O_CREAT | O_TRUNC | O_CLOEXEC | O_WRONLY, CONFIG_FILE_MODE);
    if (fd == -1) {
        ERROR("Create file %s failed: %s", filename, strerror(errno));
        isulad_set_error_message("Create file '%s' failed: %s", filename, strerror(errno));
        ret = -1;
        goto out;
    }

    len = util_write_nointr(fd, json_data, strlen(json_data));
    if (len < 0 || ((size_t)len) != strlen(json_data)) {
        ERROR("Write file %s failed: %s", filename, strerror(errno));
        isulad_set_error_message("Write file '%s' failed: %s", filename, strerror(errno));
        ret = -1;
    }
    close(fd);

out:
    return ret;
}

#define CONFIG_V2_JSON "config.v2.json"

/* save config v2 json */
int save_config_v2_json(const char *id, const char *rootpath, const char *v2configstr)
{
    if (rootpath == NULL || id == NULL || v2configstr == NULL) {
        return -1;
    }

    return save_json_config_file(id, rootpath, v2configstr, CONFIG_V2_JSON);
}

/* read config v2 */
container_config_v2 *read_config_v2(const char *rootpath, const char *id)
{
    int nret;
    char filename[PATH_MAX] = { 0x00 };
    parser_error err = NULL;
    container_config_v2 *v2config = NULL;

    nret = snprintf(filename, sizeof(filename), "%s/%s/%s", rootpath, id, CONFIG_V2_JSON);
    if (nret < 0 || (size_t)nret >= sizeof(filename)) {
        ERROR("Failed to print string");
        goto out;
    }

    v2config = container_config_v2_parse_file(filename, NULL, &err);
    if (v2config == NULL) {
        ERROR("Failed to parse v2 config file:%s", err);
        goto out;
    }
out:
    free(err);

    return v2config;
}

#define HOSTCONFIGJSON "hostconfig.json"
/* save host config */
int save_host_config(const char *id, const char *rootpath, const char *hostconfigstr)
{
    if (rootpath == NULL || id == NULL || hostconfigstr == NULL) {
        return -1;
    }
    return save_json_config_file(id, rootpath, hostconfigstr, HOSTCONFIGJSON);
}

static host_config *read_host_config(const char *rootpath, const char *id)
{
    int nret;
    char filename[PATH_MAX] = { 0x00 };
    parser_error err = NULL;
    host_config *hostconfig = NULL;

    nret = snprintf(filename, sizeof(filename), "%s/%s/%s", rootpath, id, HOSTCONFIGJSON);
    if (nret < 0 || (size_t)nret >= sizeof(filename)) {
        ERROR("Failed to print string");
        goto out;
    }

    hostconfig = host_config_parse_file(filename, NULL, &err);
    if (hostconfig == NULL) {
        ERROR("Failed to parse host config file:%s", err);
        goto out;
    }
out:
    free(err);
    return hostconfig;
}

static bool check_start_generate_config(const char *rootpath, const char *id)
{
#define START_GENERATE_CONFIG "start_generate_config.json"
    int nret;
    bool ret = false;
    char filename[PATH_MAX] = { 0x00 };
    parser_error err = NULL;
    container_start_generate_config *config = NULL;

    nret = snprintf(filename, sizeof(filename), "%s/%s/%s", rootpath, id, START_GENERATE_CONFIG);
    if (nret < 0 || (size_t)nret >= sizeof(filename)) {
        ERROR("Failed to print string");
        goto out;
    }

    if (!util_file_exists(filename)) {
        return true;
    }

    config = container_start_generate_config_parse_file(filename, NULL, &err);
    if (config == NULL) {
        ERROR("Failed to parse start generate config file:%s", err);
        goto out;
    }
    ret = true;
out:
    free(err);
    free_container_start_generate_config(config);
    return ret;
}

/* container save host config */
static int container_save_host_config(const container_t *cont)
{
    int ret = 0;
    parser_error err = NULL;
    char *json_host_config = NULL;

    if (cont == NULL) {
        return -1;
    }

    json_host_config = host_config_generate_json(cont->hostconfig, NULL, &err);
    if (json_host_config == NULL) {
        ERROR("Failed to generate container host config json string:%s", err ? err : " ");
        ret = -1;
        goto out;
    }

    ret = save_host_config(cont->common_config->id, cont->root_path, json_host_config);
    if (ret != 0) {
        ERROR("Failed to save container host config json to file");
        ret = -1;
        goto out;
    }

out:
    free(json_host_config);
    free(err);

    return ret;
}

/* container save config v2 */
static int container_save_config_v2(const container_t *cont)
{
    int ret = 0;
    char *json_v2 = NULL;
    parser_error err = NULL;
    container_config_v2 config_v2;

    if (cont == NULL) {
        return -1;
    }

    container_state_lock(cont->state);

    config_v2.common_config = cont->common_config;

    config_v2.state = cont->state->state;

    config_v2.image = cont->image_id;

    json_v2 = container_config_v2_generate_json(&config_v2, NULL, &err);
    if (json_v2 == NULL) {
        ERROR("Failed to generate container config V2 json string:%s", err ? err : " ");
        ret = -1;
        goto out;
    }

    ret = save_config_v2_json(cont->common_config->id, cont->root_path, json_v2);
    if (ret != 0) {
        ERROR("Failed to save container config V2 json to file");
        ret = -1;
        goto out;
    }

out:
    free(json_v2);
    free(err);
    container_state_unlock(cont->state);
    return ret;
}

/* container to disk */
int container_to_disk(const container_t *cont)
{
    int ret = 0;

    if (cont == NULL) {
        return -1;
    }

    ret = container_save_config_v2(cont);
    if (ret != 0) {
        return ret;
    }

    ret = container_save_host_config(cont);
    if (ret != 0) {
        return ret;
    }

    return ret;
}

/* container to disk locking */
int container_to_disk_locking(container_t *cont)
{
    int ret = 0;

    if (cont == NULL) {
        return -1;
    }

    container_lock(cont);

    ret = container_to_disk(cont);

    container_unlock(cont);
    return ret;
}

static int do_parse_container_log_config(const char *key, const char *value, container_t *cont)
{
    if (strcmp(key, CONTAINER_LOG_CONFIG_KEY_FILE) == 0) {
        cont->log_path = util_strdup_s(value);
    } else if (strcmp(key, CONTAINER_LOG_CONFIG_KEY_ROTATE) == 0) {
        return util_safe_int(value, &(cont->log_rotate));
    } else if (strcmp(key, CONTAINER_LOG_CONFIG_KEY_SIZE) == 0) {
        return util_parse_byte_size_string(value, &(cont->log_maxsize));
    }
    return 0;
}

/* get log config of container */
static int parse_container_log_configs(container_t *cont)
{
    int ret = -1;
    size_t i = 0;
    json_map_string_string *tmp_annos = NULL;

    if (cont == NULL) {
        return -1;
    }

    if (cont->common_config == NULL || cont->common_config->config == NULL ||
        cont->common_config->config->annotations == NULL) {
        return 0;
    }

    tmp_annos = cont->common_config->config->annotations;
    for (i = 0; i < tmp_annos->len; i++) {
        if (do_parse_container_log_config(tmp_annos->keys[i], tmp_annos->values[i], cont) != 0) {
            ERROR("parse key: %s, value: %s failed", tmp_annos->keys[i], tmp_annos->values[i]);
            goto out;
        }
    }

    ret = 0;
out:
    return ret;
}

/* container load */
container_t *container_load(const char *runtime, const char *rootpath, const char *statepath, const char *id)
{
    container_config_v2 *v2config = NULL;
    container_config_v2_common_config *common_config = NULL;
    host_config *hostconfig = NULL;
    const char *image_id = NULL;
    container_t *cont = NULL;

    if (rootpath == NULL || statepath == NULL || id == NULL || runtime == NULL) {
        return NULL;
    }

    if (!check_start_generate_config(rootpath, id)) {
        return NULL;
    }
    v2config = read_config_v2(rootpath, id);
    if (v2config == NULL) {
        ERROR("Failed to read config v2 file:%s", id);
        return NULL;
    }

    hostconfig = read_host_config(rootpath, id);
    if (hostconfig == NULL) {
        ERROR("Failed to host config file for container: %s", id);
        goto error_out;
    }

    common_config = v2config->common_config;
    v2config->common_config = NULL;
    image_id = v2config->image;

    cont = container_new(runtime, rootpath, statepath, image_id, &hostconfig, &common_config);
    if (cont == NULL) {
        ERROR("Failed to create container '%s'", id);
        goto error_out;
    }

    /* replace cont->state->state with v2config->state */
    free_container_config_v2_state(cont->state->state);

    cont->state->state = v2config->state;
    v2config->state = NULL;

    free_container_config_v2(v2config);

    return cont;

error_out:
    free_container_config_v2_common_config(common_config);
    free_host_config(hostconfig);
    free_container_config_v2(v2config);
    container_unref(cont);
    return NULL;
}

static char *append_quote_to_arg(const char *arg)
{
    size_t arg_len, total;
    char *new_arg = NULL;
    const char *part = "";

    arg_len = strlen(arg);
    if (arg_len > SIZE_MAX - 3) {
        ERROR("Arg is too long");
        return NULL;
    }

    total = arg_len + 1;
    if (strchr(arg, ' ') != NULL) {
        total += 2;
        part = "'";
    }
    new_arg = util_common_calloc_s(total);
    if (new_arg == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    int nret = snprintf(new_arg, total, "%s%s%s", part, arg, part);
    if (nret < 0 || (size_t)nret >= total) {
        free(new_arg);
        ERROR("Sprintf failed");
        return NULL;
    }
    return new_arg;
}

/* container get command */
char *container_get_command(const container_t *cont)
{
    int nret;
    size_t i;
    char *cmd = NULL;
    char **args = NULL;

    if (cont == NULL || cont->common_config == NULL) {
        return NULL;
    }

    if (cont->common_config->path != NULL) {
        nret = util_array_append(&args, cont->common_config->path);
        if (nret < 0) {
            ERROR("Appned string failed");
            goto cleanup;
        }
    }

    for (i = 0; cont->common_config->args != NULL && i < cont->common_config->args_len; i++) {
        char *arg = NULL;

        arg = append_quote_to_arg(cont->common_config->args[i]);
        if (arg == NULL) {
            goto cleanup;
        }
        nret = util_array_append(&args, arg);
        free(arg);
        if (nret < 0) {
            ERROR("Appned string failed");
            goto cleanup;
        }
    }

    cmd = util_string_join(" ", (const char **)args, util_array_len((const char **)args));

cleanup:
    util_free_array(args);
    return cmd;
}

/* container get image */
char *container_get_image(const container_t *cont)
{
    char *tmp = NULL;

    if (cont == NULL) {
        return NULL;
    }

    if (cont->common_config != NULL && cont->common_config->image != NULL) {
        tmp = util_strdup_s(cont->common_config->image);
    }

    return tmp;
}

/* container reset manually stopped */
void container_reset_manually_stopped(container_t *cont)
{
    if (cont == NULL) {
        return;
    }

    container_lock(cont);

    cont->common_config->has_been_manually_stopped = false;

    container_unlock(cont);
    return;
}

/* reset restart manager */
bool reset_restart_manager(container_t *cont, bool reset_count)
{
    if (cont == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    if (cont->rm != NULL) {
        if (restart_manager_cancel(cont->rm)) {
            ERROR("Failed to cancel restart manager");
            return false;
        }
        restart_manager_unref(cont->rm);
    }
    if (reset_count) {
        cont->common_config->restart_count = 0;
    }
    cont->rm = NULL;
    return true;
}

/* get restart manager */
restart_manager_t *get_restart_manager(container_t *cont)
{
    if (cont == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }

    if (cont->rm == NULL) {
        cont->rm = restart_manager_new(cont->hostconfig->restart_policy, cont->common_config->restart_count);
    }
    restart_manager_refinc(cont->rm);
    return cont->rm;
}

/* container update restart manager */
void container_update_restart_manager(container_t *cont, const host_config_restart_policy *policy)
{
    restart_manager_t *rm = NULL;

    if (cont == NULL || policy == NULL) {
        ERROR("Invalid input arguments");
        return;
    }

    rm = get_restart_manager(cont);
    (void)restart_manager_set_policy(rm, policy);
    restart_manager_unref(rm);
}

/* container exit on next */
int container_exit_on_next(container_t *cont)
{
    int ret = 0;
    restart_manager_t *rm = NULL;

    if (cont == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    rm = get_restart_manager(cont);
    if (rm == NULL) {
        return -1;
    }
    ret = restart_manager_cancel(rm);
    restart_manager_unref(rm);
    return ret;
}

/* this function should be called in container_lock */
int container_wait_stop(container_t *cont, int timeout)
{
    int ret = 0;

    if (cont == NULL) {
        return -1;
    }

    if (!is_running(cont->state)) {
        goto unlock;
    }

    ret = container_wait_stop_cond_wait(cont, timeout);
unlock:
    return ret;
}

/* container wait stop locking */
int container_wait_stop_locking(container_t *cont, int timeout)
{
    int ret = 0;

    if (cont == NULL) {
        return -1;
    }

    container_lock(cont);

    if (!is_running(cont->state)) {
        goto unlock;
    }

    ret = container_wait_stop_cond_wait(cont, timeout);
unlock:
    container_unlock(cont);
    return ret;
}

char *container_get_env_nolock(const container_t *cont, const char *key)
{
    size_t i = 0;
    size_t key_len = 0;
    char *val = NULL;
    const char *env = NULL;
    const container_config_v2_common_config *cc = NULL;
    const container_config *ccc = NULL;

    if (cont == NULL) {
        ERROR("nil container_t");
        return val;
    }

    if (key == NULL) {
        ERROR("nil key");
        return val;
    }

    key_len = strlen(key);

    cc = cont->common_config;
    if (cc == NULL) {
        ERROR("nil container common_config");
        return val;
    }

    ccc = cc->config;
    if (ccc == NULL) {
        ERROR("nil container common_config config");
        return val;
    }

    for (i = 0; i < ccc->env_len; i++) {
        env = ccc->env[i];
        size_t env_len = strlen(env);
        if (key_len < env_len && !strncmp(key, env, key_len) && env[key_len] == '=') {
            val = util_strdup_s(env + key_len + 1);
            break;
        }
    }

    return val;
}

int container_read_proc(uint32_t pid, container_pid_t *pid_info)
{
    int ret = 0;
    proc_t *proc = NULL;
    proc_t *p_proc = NULL;

    if (pid == 0) {
        ret = -1;
        goto out;
    }

    proc = util_get_process_proc_info((pid_t)pid);
    if (proc == NULL) {
        ret = -1;
        goto out;
    }

    p_proc = util_get_process_proc_info((pid_t)proc->ppid);
    if (p_proc == NULL) {
        ret = -1;
        goto out;
    }

    pid_info->pid = proc->pid;
    pid_info->start_time = proc->start_time;
    pid_info->ppid = proc->ppid;
    pid_info->pstart_time = p_proc->start_time;

out:
    free(proc);
    free(p_proc);
    return ret;
}


