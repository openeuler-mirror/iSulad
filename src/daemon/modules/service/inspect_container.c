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
 * Description: provide inspect container functions
 ******************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <isula_libutils/container_config_v2.h>
#include <isula_libutils/container_inspect.h>
#include <isula_libutils/container_config.h>
#include <isula_libutils/defs.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "constants.h"
#include "utils_timestamp.h"
#include "service_container_api.h"
#include "image_api.h"
#include "container_api.h"
#include "isulad_config.h"
#include "err_msg.h"
#include "namespace.h"
#include "utils_port.h"

static int dup_path_and_args(const container_t *cont, char **path, char ***args, size_t *args_len)
{
    int ret = 0;
    size_t i = 0;

    if (cont->common_config->path != NULL) {
        *path = util_strdup_s(cont->common_config->path);
    }
    if (cont->common_config->args_len > 0) {
        if ((cont->common_config->args_len) > SIZE_MAX / sizeof(char *)) {
            ERROR("Containers config args len is too many!");
            ret = -1;
            goto out;
        }
        *args = util_common_calloc_s(cont->common_config->args_len * sizeof(char *));
        if ((*args) == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        for (i = 0; i < cont->common_config->args_len; i++) {
            if (cont->common_config->args[i] == NULL) {
                ERROR("Input value of args is null");
                ret = -1;
                goto out;
            }
            (*args)[*args_len] = util_strdup_s(cont->common_config->args[i]);
            (*args_len)++;
        }
    }
out:
    return ret;
}

static int dup_host_config(const host_config *src, host_config **dest)
{
    int ret = -1;
    char *json = NULL;
    parser_error err = NULL;

    if (src == NULL) {
        *dest = NULL;
        return 0;
    }

    json = host_config_generate_json(src, NULL, &err);
    if (json == NULL) {
        ERROR("Failed to generate json: %s", err);
        goto out;
    }
    *dest = host_config_parse_data(json, NULL, &err);
    if (*dest == NULL) {
        ERROR("Failed to parse json: %s", err);
        goto out;
    }
    ret = 0;

out:
    free(err);
    free(json);
    return ret;
}

static int dup_health_check_config(const container_config *src, container_inspect_config *dest)
{
    int ret = 0;
    size_t i = 0;

    if (src == NULL || src->healthcheck == NULL || dest == NULL) {
        return 0;
    }
    dest->health_check = util_common_calloc_s(sizeof(defs_health_check));
    if (dest->health_check == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    if (src->healthcheck->test != NULL && src->healthcheck->test_len != 0) {
        if (src->healthcheck->test_len > SIZE_MAX / sizeof(char *)) {
            ERROR("health check test is too much!");
            ret = -1;
            goto out;
        }
        dest->health_check->test = util_common_calloc_s(src->healthcheck->test_len * sizeof(char *));
        if (dest->health_check->test == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        for (i = 0; i < src->healthcheck->test_len; i++) {
            if (src->healthcheck->test[i] == NULL) {
                ERROR("Input value of src health check test is null");
                ret = -1;
                goto out;
            }
            dest->health_check->test[i] = util_strdup_s(src->healthcheck->test[i]);
            dest->health_check->test_len++;
        }
        dest->health_check->interval = (src->healthcheck->interval == 0) ? DEFAULT_PROBE_INTERVAL :
                                       src->healthcheck->interval;
        dest->health_check->start_period = (src->healthcheck->start_period == 0) ? DEFAULT_START_PERIOD :
                                           src->healthcheck->start_period;
        dest->health_check->timeout = (src->healthcheck->timeout == 0) ? DEFAULT_PROBE_TIMEOUT :
                                      src->healthcheck->timeout;
        dest->health_check->retries = (src->healthcheck->retries != 0) ? src->healthcheck->retries :
                                      DEFAULT_PROBE_RETRIES;

        dest->health_check->exit_on_unhealthy = src->healthcheck->exit_on_unhealthy;
    }
out:
    return ret;
}

static int dup_container_config_env(const container_config *src, container_inspect_config *dest)
{
    int ret = 0;
    size_t i = 0;
    char *tmpstr = NULL;

    if (src->env != NULL && src->env_len > 0) {
        if (src->env_len > SIZE_MAX / sizeof(char *)) {
            ERROR("Container inspect config env elements is too much!");
            ret = -1;
            goto out;
        }
        dest->env = util_common_calloc_s(src->env_len * sizeof(char *));
        if (dest->env == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        for (i = 0; i < src->env_len; i++) {
            if (src->env[i] == NULL) {
                ERROR("Input value of src env is null");
                ret = -1;
                goto out;
            }
            tmpstr = src->env[i];
            dest->env[i] = tmpstr ? util_strdup_s(tmpstr) : NULL;
            dest->env_len++;
        }
    }

out:
    return ret;
}

static int dup_container_config_cmd_and_entrypoint(const container_config *src, container_inspect_config *dest)
{
    int ret = 0;

    if (src == NULL || dest == NULL) {
        return 0;
    }

    ret = util_dup_array_of_strings((const char **)(src->cmd), src->cmd_len, &(dest->cmd), &(dest->cmd_len));
    if (ret != 0) {
        goto out;
    }

    ret = util_dup_array_of_strings((const char **)(src->entrypoint), src->entrypoint_len, &(dest->entrypoint),
                                    &(dest->entrypoint_len));
out:
    return ret;
}

static int dup_container_config_labels(const container_config *src, container_inspect_config *dest)
{
    int ret = 0;

    if (src->labels != NULL) {
        dest->labels = util_common_calloc_s(sizeof(json_map_string_string));
        if (dest->labels == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        ret = dup_json_map_string_string(src->labels, dest->labels);
        if (ret != 0) {
            goto out;
        }
    }
out:
    return ret;
}

static int dup_container_config_volumes(const container_config *src, container_inspect_config *dest)
{
    int ret = 0;

    if (src->volumes != NULL) {
        dest->volumes = dup_map_string_empty_object(src->volumes);
        if (dest->volumes == 0) {
            ret = -1;
            goto out;
        }
    }
out:
    return ret;
}

static int dup_container_config_annotations(const container_config *src, container_inspect_config *dest)
{
    int ret = 0;

    if (src->annotations != NULL) {
        dest->annotations = util_common_calloc_s(sizeof(json_map_string_string));
        if (dest->annotations == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        ret = dup_json_map_string_string(src->annotations, dest->annotations);
        if (ret != 0) {
            goto out;
        }
    }
out:
    return ret;
}

static int dup_container_config(const char *image, const container_config *src, container_inspect_config *dest)
{
    int ret = 0;

    if (src == NULL || dest == NULL) {
        return 0;
    }

    dest->hostname = src->hostname ? util_strdup_s(src->hostname) : util_strdup_s("");
    dest->user = src->user ? util_strdup_s(src->user) : util_strdup_s("");
    dest->tty = src->tty;
    dest->image = image ? util_strdup_s(image) : util_strdup_s("none");
    dest->image_ref = util_strdup_s(src->image_ref);
    dest->stop_signal = util_strdup_s(src->stop_signal);

    if (dup_container_config_env(src, dest) != 0) {
        ret = -1;
        goto out;
    }

    if (dup_container_config_cmd_and_entrypoint(src, dest) != 0) {
        ret = -1;
        goto out;
    }

    if (dup_container_config_labels(src, dest) != 0) {
        ret = -1;
        goto out;
    }

    if (dup_container_config_volumes(src, dest) != 0) {
        ret = -1;
        goto out;
    }

    if (dup_container_config_annotations(src, dest) != 0) {
        ret = -1;
        goto out;
    }

    if (dup_health_check_config(src, dest) != 0) {
        ERROR("Failed to duplicate health check config");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int mount_point_to_inspect(const container_t *cont, container_inspect *inspect)
{
    size_t i, len;

    if (cont->common_config->mount_points == NULL || cont->common_config->mount_points->len == 0) {
        return 0;
    }

    len = cont->common_config->mount_points->len;
    if (len > SIZE_MAX / sizeof(docker_types_mount_point *)) {
        ERROR("Invalid mount point size");
        return -1;
    }
    inspect->mounts = util_common_calloc_s(sizeof(docker_types_mount_point *) * len);
    if (inspect->mounts == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    for (i = 0; i < len; i++) {
        container_config_v2_common_config_mount_points_element *mp = cont->common_config->mount_points->values[i];
        inspect->mounts[i] = util_common_calloc_s(sizeof(docker_types_mount_point));
        if (inspect->mounts[i] == NULL) {
            ERROR("Out of memory");
            return -1;
        }
        inspect->mounts[i]->type = util_strdup_s(mp->type);
        inspect->mounts[i]->source = util_strdup_s(mp->source);
        inspect->mounts[i]->destination = util_strdup_s(mp->destination);
        inspect->mounts[i]->name = util_strdup_s(mp->name);
        inspect->mounts[i]->driver = util_strdup_s(mp->driver);
        inspect->mounts[i]->mode = util_strdup_s(mp->relabel);
        inspect->mounts[i]->propagation = util_strdup_s(mp->propagation);
        inspect->mounts[i]->rw = mp->rw;

        inspect->mounts_len++;
    }
    return 0;
}

static int pack_inspect_container_state(const container_t *cont, container_inspect *inspect)
{
    int ret = 0;

    if (cont->state == NULL) {
        ERROR("Failed to read %s state", cont->common_config->id);
        ret = -1;
        goto out;
    }

    inspect->restart_count = container_state_get_restart_count(cont->state);

    inspect->state = container_state_to_inspect_state(cont->state);
    if (inspect->state == NULL) {
        ERROR("Failed to get container state %s", cont->common_config->id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int pack_inspect_host_config(const container_t *cont, container_inspect *inspect)
{
    int ret = 0;
    host_config *hostconfig = NULL;

    hostconfig = cont->hostconfig;
    if (hostconfig == NULL) {
        ERROR("Failed to read host config");
        ret = -1;
        goto out;
    }

    if (dup_host_config(hostconfig, &inspect->host_config) != 0) {
        ERROR("Failed to dup host config");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int pack_inspect_general_data(const container_t *cont, container_inspect *inspect)
{
    int ret = 0;

    inspect->id = util_strdup_s(cont->common_config->id);
    inspect->name = util_strdup_s(cont->common_config->name);
    if (cont->common_config->created != NULL) {
        inspect->created = util_strdup_s(cont->common_config->created);
    }

    if (dup_path_and_args(cont, &(inspect->path), &(inspect->args), &(inspect->args_len)) != 0) {
        ERROR("Failed to dup path and args");
        ret = -1;
        goto out;
    }

    inspect->image = cont->image_id != NULL ? util_strdup_s(cont->image_id) : util_strdup_s("");

    if (cont->common_config->log_path != NULL) {
        inspect->log_path = util_strdup_s(cont->common_config->log_path);
    }

    if (cont->common_config->hosts_path != NULL) {
        inspect->hosts_path = util_strdup_s(cont->common_config->hosts_path);
    }
    if (cont->common_config->resolv_conf_path != NULL) {
        inspect->resolv_conf_path = util_strdup_s(cont->common_config->resolv_conf_path);
    }
    if (cont->common_config->mount_label != NULL) {
        inspect->mount_label = util_strdup_s(cont->common_config->mount_label);
    }
    if (cont->common_config->process_label != NULL) {
        inspect->process_label = util_strdup_s(cont->common_config->process_label);
    }

    if (cont->common_config->seccomp_profile != NULL) {
        inspect->seccomp_profile = util_strdup_s(cont->common_config->seccomp_profile);
    }

    inspect->no_new_privileges = cont->common_config->no_new_privileges;

    if (mount_point_to_inspect(cont, inspect) != 0) {
        ERROR("Failed to transform to mount point");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int pack_inspect_config(const container_t *cont, container_inspect *inspect)
{
    int ret = 0;

    inspect->config = util_common_calloc_s(sizeof(container_inspect_config));
    if (inspect->config == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (dup_container_config(cont->common_config->image, cont->common_config->config, inspect->config) != 0) {
        ERROR("Failed to dup container config");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static int merge_default_ulimit_with_ulimit(container_inspect *out_inspect)
{
    int ret = 0;
    host_config_ulimits_element **rlimits = NULL;
    size_t i, j, ulimits_len;

    if (conf_get_isulad_default_ulimit(&rlimits) != 0) {
        ERROR("Failed to get isulad default ulimit");
        ret = -1;
        goto out;
    }

    ulimits_len = ulimit_array_len(rlimits);
    for (i = 0; i < ulimits_len; i++) {
        for (j = 0; j < out_inspect->host_config->ulimits_len; j++) {
            if (strcmp(rlimits[i]->name, out_inspect->host_config->ulimits[j]->name) == 0) {
                break;
            }
        }
        if (j < out_inspect->host_config->ulimits_len) {
            continue;
        }

        if (ulimit_array_append(&out_inspect->host_config->ulimits, rlimits[i],
                                out_inspect->host_config->ulimits_len) != 0) {
            ERROR("ulimit append failed");
            ret = -1;
            goto out;
        }
        out_inspect->host_config->ulimits_len++;
    }

out:
    free_default_ulimit(rlimits);
    return ret;
}

static int do_split_cni_portmapping(const cni_inner_port_mapping *cni_port_mapping, char **key,
                                    network_port_binding_host_element **element)
{
    char tmp_key[MAX_PORT_LEN] = { 0 };
    char tmp_hport[MAX_PORT_LEN] = { 0 };
    int nret;

    nret = snprintf(tmp_key, MAX_PORT_LEN, "%d/%s", cni_port_mapping->container_port, cni_port_mapping->protocol);
    if (nret < 0 || nret >= MAX_PORT_LEN) {
        ERROR("Out of memory");
        return -1;
    }
    nret = snprintf(tmp_hport, MAX_PORT_LEN, "%d", cni_port_mapping->host_port);
    if (nret < 0 || nret >= MAX_PORT_LEN) {
        ERROR("Out of memory");
        return -1;
    }
    *element = util_common_calloc_s(sizeof(network_port_binding_host_element));
    if (*element == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    (*element)->host_ip = util_strdup_s(cni_port_mapping->host_ip);
    (*element)->host_port = util_strdup_s(tmp_hport);
    *key = util_strdup_s(tmp_key);

    return 0;
}

static int do_append_element_for_port_list(network_port_binding_host_element *element, network_port_binding *list)
{
    network_port_binding_host_element **new_items = NULL;

    if (list->host_len >= MAX_MEMORY_SIZE / sizeof(network_port_binding_host_element *) - 1) {
        ERROR("Too much memory request");
        return -1;
    }
    if (util_mem_realloc((void **)&new_items, (list->host_len + 1) * sizeof(network_port_binding_host_element *),
                         (void *)list->host, list->host_len * sizeof(network_port_binding_host_element *)) != 0) {
        ERROR("Out of memory");
        return -1;
    }
    new_items[list->host_len] = element;
    list->host_len += 1;
    list->host = new_items;

    return 0;
}

static int do_expand_port_binds_map(const char *key, defs_map_string_object_port_bindings *ptr)
{
    int ret = 0;
    char **new_keys = NULL;
    defs_map_string_object_port_bindings_element **new_vals = NULL;

    if (ptr->len >= MAX_MEMORY_SIZE / sizeof(char *) - 1) {
        ERROR("Too much memory request");
        return -1;
    }
    if (util_mem_realloc((void **)&new_keys, (ptr->len + 1) * sizeof(char *), (void *)ptr->keys,
                         ptr->len * sizeof(char *)) != 0) {
        ERROR("Out of memory");
        return -1;
    }
    ptr->keys = new_keys;
    if (util_mem_realloc((void **)&new_vals, (ptr->len + 1) * sizeof(defs_map_string_object_port_bindings_element *),
                         (void *)ptr->values, ptr->len * sizeof(defs_map_string_object_port_bindings_element *)) != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    ptr->values = new_vals;
    ptr->values[ptr->len] = util_common_calloc_s(sizeof(defs_map_string_object_port_bindings_element));
    if (ptr->values[ptr->len] == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    ptr->keys[ptr->len] = util_strdup_s(key);
    ptr->len += 1;

out:
    return ret;
}

static int do_insert_element_for_port_bindings_map(const char *key, network_port_binding_host_element *element,
                                                   defs_map_string_object_port_bindings *ptr)
{
    size_t i;
    int ret = 0;

    for (i = 0; i < ptr->len; i++) {
        if (strcmp(key, ptr->keys[i]) == 0) {
            break;
        }
    }
    if (i == ptr->len) {
        // expand map
        if (do_expand_port_binds_map(key, ptr) != 0) {
            ret = -1;
            goto out;
        }
    }

    if (ptr->values[i]->element == NULL) {
        ptr->values[i]->element = util_common_calloc_s(sizeof(network_port_binding));
    }
    if (ptr->values[i]->element == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    ret = do_append_element_for_port_list(element, ptr->values[i]->element);

out:
    return ret;
}

static int do_transform_cni_to_map(container_network_settings *settings)
{
    defs_map_string_object_port_bindings *result = NULL;
    size_t i;
    int ret = 0;

    if (settings->cni_ports_len == 0) {
        return 0;
    }
    result = util_common_calloc_s(sizeof(defs_map_string_object_port_bindings));
    if (result == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    result->keys = util_smart_calloc_s(sizeof(char *), settings->cni_ports_len);
    if (result->keys == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    result->values = util_smart_calloc_s(sizeof(defs_map_string_object_port_bindings_element *), settings->cni_ports_len);
    if (result->values == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < settings->cni_ports_len; i++) {
        char *key = NULL;
        network_port_binding_host_element *element = NULL;
        if (do_split_cni_portmapping(settings->cni_ports[i], &key, &element) != 0) {
            ret = -1;
            goto out;
        }
        DEBUG("get port binding: %s --> %s:%s", key, element->host_ip, element->host_port);
        ret = do_insert_element_for_port_bindings_map(key, element, result);
        free(key);
        if (ret != 0) {
            free_network_port_binding_host_element(element);
            goto out;
        }
    }

    free_defs_map_string_object_port_bindings(settings->ports);
    settings->ports = result;
    result = NULL;
    for (i = 0; i < settings->cni_ports_len; i++) {
        free_cni_inner_port_mapping(settings->cni_ports[i]);
        settings->cni_ports[i] = NULL;
    }
    free(settings->cni_ports);
    settings->cni_ports = NULL;
    settings->cni_ports_len = 0;

out:
    free_defs_map_string_object_port_bindings(result);
    return ret;
}

static int pack_inspect_network_settings(const container_network_settings *network_settings,
                                         container_inspect *inspect)
{
    parser_error jerr = NULL;
    char *jstr = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY | OPT_GEN_KEY_VALUE, 0 };
    int ret = 0;

    if (network_settings == NULL) {
        return 0;
    }

    jstr = container_network_settings_generate_json(network_settings, &ctx, &jerr);
    if (jstr == NULL) {
        ERROR("Generate network settings failed: %s", jerr);
        ret = -1;
        goto out;
    }

    free(jerr);
    jerr = NULL;
    inspect->network_settings = container_network_settings_parse_data(jstr, NULL, &jerr);
    if (inspect->network_settings == NULL) {
        ERROR("Parse network settings failed: %s", jerr);
        ret = -1;
        goto out;
    }

    // change cni port mapping to map (string --> array)
    if (do_transform_cni_to_map(inspect->network_settings) != 0) {
        ret = -1;
        ERROR("parse cni port mapping failed");
        goto out;
    }

out:
    free(jerr);
    free(jstr);
    return ret;
}

static container_inspect *pack_inspect_data(const container_t *cont, bool with_host_config)
{
    container_inspect *inspect = NULL;

    inspect = util_common_calloc_s(sizeof(container_inspect));
    if (inspect == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    if (pack_inspect_general_data(cont, inspect) != 0) {
        ERROR("Failed to pack inspect general data, continue to pack other information");
    }

    if (pack_inspect_network_settings(cont->network_settings, inspect) != 0) {
        ERROR("Failed to pack inspect network data, continue to pack other information");
    }

    if (pack_inspect_container_state(cont, inspect) != 0) {
        ERROR("Failed to pack inspect state data, continue to pack other information");
    }

    if (with_host_config && pack_inspect_host_config(cont, inspect) != 0) {
        ERROR("Failed to pack inspect host config data, continue to pack other information");
    }

    if (with_host_config && merge_default_ulimit_with_ulimit(inspect) != 0) {
        ERROR("Failed to pack default ulimit data, continue to pack other information");
    }

    if (pack_inspect_config(cont, inspect) != 0) {
        ERROR("Failed to pack container config data, continue to pack other information");
    }

    if (strcmp(cont->common_config->image_type, IMAGE_TYPE_OCI) == 0) {
        inspect->graph_driver = im_graphdriver_get_metadata_by_container_id(cont->common_config->id);
        if (inspect->graph_driver == NULL) {
            ERROR("Failed to pack container graph driver data, continue to pack other information");
        }
    }

out:
    return inspect;
}

container_inspect *inspect_container(const char *id, int timeout, bool with_host_config)
{
    int ret = 0;
    container_inspect *inspect = NULL;
    container_t *cont = NULL;

    if (!util_valid_container_id_or_name(id)) {
        ERROR("Inspect invalid name %s", id);
        isulad_set_error_message("Inspect invalid name %s", id);
        ret = -1;
        goto out;
    }

    cont = containers_store_get(id);
    if (cont == NULL) {
        ret = -1;
        isulad_try_set_error_message("No such image or container or accelerator:%s", id);
        goto out;
    }

    if (container_timedlock(cont, timeout) != 0) {
        ERROR("Container %s inspect failed due to trylock timeout for %ds.", id, timeout);
        isulad_try_set_error_message("Container %s inspect failed due to trylock timeout for %ds.", id, timeout);
        ret = -1;
        goto out;
    }

    inspect = pack_inspect_data(cont, with_host_config);
    ret = 0;
    container_unlock(cont);

out:
    container_unref(cont);
    if (ret != 0) {
        free_container_inspect(inspect);
        inspect = NULL;
    }
    return inspect;
}

container_inspect_state *inspect_container_state(const char *id, int timeout)
{
    int ret = 0;
    container_inspect_state *inspect = NULL;
    container_t *cont = NULL;

    if (!util_valid_container_id_or_name(id)) {
        ERROR("Inspect invalid name %s", id);
        isulad_set_error_message("Inspect invalid name %s", id);
        ret = -1;
        goto out;
    }

    cont = containers_store_get(id);
    if (cont == NULL) {
        ret = -1;
        isulad_try_set_error_message("No such image or container or accelerator:%s", id);
        goto out;
    }

    if (container_timedlock(cont, timeout) != 0) {
        ERROR("Container %s inspect failed due to trylock timeout for %ds.", id, timeout);
        isulad_try_set_error_message("Container %s inspect failed due to trylock timeout for %ds.", id, timeout);
        ret = -1;
        goto out;
    }

    inspect = container_state_to_inspect_state(cont->state);
    if (inspect == NULL) {
        ERROR("Failed to get container state %s", cont->common_config->id);
        ret = -1;
        goto unlock;
    }

    ret = 0;

unlock:
    container_unlock(cont);
out:
    container_unref(cont);

    if (ret != 0) {
        free_container_inspect_state(inspect);
        inspect = NULL;
    }
    return inspect;
}
