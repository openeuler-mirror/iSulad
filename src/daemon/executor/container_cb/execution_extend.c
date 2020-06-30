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
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container extend callback function definition
 *********************************************************************************/
#include "execution_extend.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <lcr/lcrcontainer.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/sysinfo.h>

#include "isula_libutils/log.h"
#include "events_sender_api.h"
#include "events_collector_api.h"
#include "io_wrapper.h"
#include "isulad_config.h"
#include "config.h"
#include "image_api.h"
#include "verify.h"
#include "isula_libutils/container_inspect.h"
#include "container_api.h"
#include "service_container_api.h"
#include "sysinfo.h"
#include "specs_api.h"
#include "runtime_api.h"

#include "filters.h"
#include "utils.h"
#include "error.h"

struct stats_context {
    struct filters_args *stats_filters;
    container_stats_request *stats_config;
};

static int service_events_handler(const struct isulad_events_request *request, const stream_func_wrapper *stream)
{
    int ret = 0;
    char *name = NULL;
    container_t *container = NULL;

    name = request->id;

    /* check whether specified container exists */
    if (name != NULL) {
        container = containers_store_get(name);
        if (container == NULL) {
            ERROR("No such container:%s", name);
            isulad_set_error_message("No such container:%s", name);
            ret = -1;
            goto out;
        }

        container_unref(container);
    }

    ret = events_subscribe(name, &request->since, &request->until, stream);
    if (ret < 0) {
        ERROR("Failed to subscribe events buffer");
        ret = -1;
        goto out;
    }

    if (add_monitor_client(name, &request->since, &request->until, stream)) {
        ERROR("Failed to add events monitor client");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static int container_events_cb(const struct isulad_events_request *request, const stream_func_wrapper *stream)
{
    int ret = 0;
    uint32_t cc = ISULAD_SUCCESS;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    if (stream == NULL) {
        ERROR("Should provide stream function in events");
        cc = ISULAD_ERR_INPUT;
        goto out;
    }

    ret = service_events_handler(request, stream);
    if (ret != 0) {
        ERROR("Failed to add events monitor");
        cc = ISULAD_ERR_INPUT;
        goto out;
    }

out:
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int dup_container_stats_request(const container_stats_request *src, container_stats_request **dest)
{
    int ret = -1;
    char *json = NULL;
    parser_error err = NULL;

    if (src == NULL) {
        *dest = NULL;
        return 0;
    }

    json = container_stats_request_generate_json(src, NULL, &err);
    if (json == NULL) {
        ERROR("Failed to generate json: %s", err);
        goto out;
    }
    *dest = container_stats_request_parse_data(json, NULL, &err);
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

static void free_stats_context(struct stats_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    filters_args_free(ctx->stats_filters);
    ctx->stats_filters = NULL;
    free_container_stats_request(ctx->stats_config);
    ctx->stats_config = NULL;
    free(ctx);
}
static struct stats_context *stats_context_new(const container_stats_request *request)
{
    struct stats_context *ctx = NULL;

    ctx = util_common_calloc_s(sizeof(struct stats_context));
    if (ctx == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    ctx->stats_filters = filters_args_new();
    if (ctx->stats_filters == NULL) {
        ERROR("Out of memory");
        goto cleanup;
    }
    if (dup_container_stats_request(request, &(ctx->stats_config)) != 0) {
        ERROR("Failed to dup stats request");
        goto cleanup;
    }

    return ctx;
cleanup:
    free_stats_context(ctx);
    return NULL;
}
static const char *accepted_stats_filter_tags[] = { "id", "label", "name", NULL };

static int copy_map_labels(const container_config *config, map_t **map_labels)
{
    *map_labels = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (*map_labels == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (config != NULL && config->labels != NULL && config->labels->len != 0) {
        size_t i;
        json_map_string_string *labels = config->labels;

        for (i = 0; i < labels->len; i++) {
            // Copy labels to internal map for filters
            if (!map_replace(*map_labels, (void *)labels->keys[i], labels->values[i])) {
                ERROR("Failed to insert labels to map");
                return -1;
            }
        }
    }
    return 0;
}

static container_info *get_container_stats(const container_t *cont,
                                           const struct runtime_container_resources_stats_info *einfo,
                                           const struct stats_context *ctx)
{
    int ret = 0;
    uint64_t sysmem_limit;
    uint64_t sys_cpu_usage = 0;
    container_info *info = NULL;
    map_t *map_labels = NULL;

    info = util_common_calloc_s(sizeof(container_info));
    if (info == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    info->id = util_strdup_s(cont->common_config->id);
    info->pids_current = einfo->pids_current;
    info->cpu_use_nanos = einfo->cpu_use_nanos;
    info->blkio_read = einfo->blkio_read;
    info->blkio_write = einfo->blkio_write;
    info->mem_used = einfo->mem_used;
    info->mem_limit = einfo->mem_limit;
    info->kmem_used = einfo->kmem_used;
    info->kmem_limit = einfo->kmem_limit;

    sysmem_limit = get_default_total_mem_size();
    if (get_system_cpu_usage(&sys_cpu_usage)) {
        WARN("Failed to get system cpu usage");
    }

    if (sysmem_limit > 0) {
        if (info->mem_limit > sysmem_limit) {
            info->mem_limit = sysmem_limit;
        }
        if (info->kmem_limit > sysmem_limit) {
            info->kmem_limit = sysmem_limit;
        }
    }
    info->cpu_system_use = sys_cpu_usage;
    info->online_cpus = (uint32_t)get_nprocs();

    info->image_type = util_strdup_s(cont->common_config->image_type);

    if (copy_map_labels(cont->common_config->config, &map_labels) != 0) {
        ret = -1;
        goto cleanup;
    }

    if (!filters_args_match(ctx->stats_filters, "id", info->id)) {
        ret = -1;
        goto cleanup;
    }

    // Do not include container if any of the labels don't match
    if (!filters_args_match_kv_list(ctx->stats_filters, "label", map_labels)) {
        ret = -1;
        goto cleanup;
    }

cleanup:
    map_free(map_labels);
    if (ret != 0) {
        free_container_info(info);
        info = NULL;
    }

    return info;
}

static struct stats_context *fold_stats_filter(const container_stats_request *request)
{
    size_t i, j;
    struct stats_context *ctx = NULL;

    ctx = stats_context_new(request);
    if (ctx == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (request->containers != NULL && request->containers_len > 0) {
        ctx->stats_config->all = true;
    }

    if (request->filters == NULL) {
        return ctx;
    }

    for (i = 0; i < request->filters->len; i++) {
        if (!filters_args_valid_key(accepted_stats_filter_tags, sizeof(accepted_stats_filter_tags) / sizeof(char *),
                                    request->filters->keys[i])) {
            ERROR("Invalid filter '%s'", request->filters->keys[i]);
            isulad_set_error_message("Invalid filter '%s'", request->filters->keys[i]);
            goto error_out;
        }
        for (j = 0; j < request->filters->values[i]->len; j++) {
            bool bret = false;
            bret = filters_args_add(ctx->stats_filters, request->filters->keys[i],
                                    request->filters->values[i]->keys[j]);
            if (!bret) {
                ERROR("Add filter args failed");
                goto error_out;
            }
        }
    }

    return ctx;
error_out:
    free_stats_context(ctx);
    return NULL;
}

static int service_stats_make_memory(container_info ***stats_arr, size_t num)
{
    if (num > SIZE_MAX / sizeof(container_info *)) {
        return -1;
    }

    *stats_arr = util_common_calloc_s(num * sizeof(container_info *));
    if (*stats_arr == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    return 0;
}

static void pack_stats_response(container_stats_response *response, uint32_t cc, size_t info_len, container_info **info)
{
    if (response == NULL) {
        return;
    }
    response->container_stats_len = info_len;
    response->container_stats = info;
    response->cc = cc;
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
}

static int stats_get_all_containers_id(const container_stats_request *request, char ***idsarray, size_t *ids_len,
                                       bool *check_exists)
{
    int ret = -1;
    char **array = NULL;

    if (request == NULL) {
        return 0;
    }

    if (request->containers_len > 0 && request->containers != NULL) {
        size_t n;
        for (n = 0; n < request->containers_len; n++) {
            if (!util_valid_container_id_or_name(request->containers[n])) {
                ERROR("Invalid container name: %s", request->containers[n]);
                isulad_set_error_message("Invalid container name: %s", request->containers[n]);
                goto cleanup;
            }
            if (util_array_append(&array, request->containers[n]) != 0) {
                ERROR("Can not append array");
                goto cleanup;
            }
        }
        *check_exists = true;
    } else {
        array = containers_store_list_ids();
    }
    *ids_len = util_array_len((const char **)array);
    *idsarray = array;
    array = NULL;
    ret = 0;

cleanup:
    util_free_array(array);
    return ret;
}

static int get_containers_stats(char **idsarray, size_t ids_len, const struct stats_context *ctx, bool check_exists,
                                container_info ***info, size_t *info_len)
{
    int ret = 0;
    int nret;
    size_t i;

    nret = service_stats_make_memory(info, ids_len);
    if (nret != 0) {
        ret = -1;
        goto cleanup;
    }

    for (i = 0; i < ids_len; i++) {
        struct runtime_container_resources_stats_info einfo = { 0 };
        container_t *cont = NULL;

        cont = containers_store_get(idsarray[i]);
        if (cont == NULL) {
            if (check_exists) {
                ERROR("No such container: %s", idsarray[i]);
                isulad_set_error_message("No such container: %s", idsarray[i]);
                ret = -1;
                goto cleanup;
            }
            continue;
        }
        if (container_is_running(cont->state)) {
            rt_stats_params_t params = { 0 };
            params.rootpath = cont->root_path;
            params.state = cont->state_path;

            nret = runtime_resources_stats(cont->common_config->id, cont->runtime, &params, &einfo);
            if (nret != 0) {
                container_unref(cont);
                continue;
            }
        } else {
            if (!ctx->stats_config->all) {
                container_unref(cont);
                continue;
            }
        }

        (*info)[*info_len] = get_container_stats(cont, &einfo, ctx);
        container_unref(cont);
        if ((*info)[*info_len] == NULL) {
            continue;
        }
        (*info_len)++;
    }
cleanup:
    return ret;
}

static int container_stats_cb(const container_stats_request *request, container_stats_response **response)
{
    bool check_exists = false;
    size_t ids_len = 0;
    size_t info_len = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char **idsarray = NULL;
    container_info **info = NULL;
    struct stats_context *ctx = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_stats_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    ctx = fold_stats_filter(request);
    if (ctx == NULL) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    if (stats_get_all_containers_id(request, &idsarray, &ids_len, &check_exists) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }
    if (ids_len == 0) {
        goto pack_response;
    }

    if (get_containers_stats(idsarray, ids_len, ctx, check_exists, &info, &info_len)) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

pack_response:
    pack_stats_response(*response, cc, info_len, info);
    util_free_array(idsarray);
    free_stats_context(ctx);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int do_resume_container(container_t *cont)
{
    int ret = 0;
    const char *id = cont->common_config->id;
    rt_resume_params_t params = { 0 };

    container_lock(cont);

    if (!container_is_running(cont->state)) {
        ERROR("Container %s is not running", id);
        isulad_set_error_message("Container %s is not running", id);
        ret = -1;
        goto out;
    }

    if (!container_is_paused(cont->state)) {
        ERROR("Container %s is not paused", id);
        isulad_set_error_message("Container %s is not paused", id);
        ret = -1;
        goto out;
    }

    params.rootpath = cont->root_path;
    params.state = cont->state_path;
    if (runtime_resume(id, cont->runtime, &params)) {
        ERROR("Failed to resume container:%s", id);
        ret = -1;
        goto out;
    }

    container_state_reset_paused(cont->state);

    container_update_health_monitor(cont->common_config->id);

    if (container_to_disk(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        ret = -1;
        goto out;
    }

out:
    container_unlock(cont);
    return ret;
}

static int oci_image_export_rootfs(const char *id, const char *file)
{
    int ret = 0;
    im_export_request *request = NULL;

    if (id == NULL || file == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    request = util_common_calloc_s(sizeof(im_export_request));
    if (request == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    request->name_id = util_strdup_s(id);
    request->file = util_strdup_s(file);
    request->type = util_strdup_s(IMAGE_TYPE_OCI);

    ret = im_container_export(request);
    if (ret != 0) {
        ERROR("Failed to export rootfs to %s from container %s", file, id);
    }

out:
    free_im_export_request(request);
    return ret;
}

static int export_container(container_t *cont, const char *file)
{
    int ret = 0;

    container_lock(cont);

    if (oci_image_export_rootfs(cont->common_config->id, file)) {
        ret = -1;
    }

    container_unlock(cont);
    return ret;
}

static void pack_resume_response(container_resume_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
}

static int container_resume_cb(const container_resume_request *request, container_resume_response **response)
{
    int ret = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *name = NULL;
    char *id = NULL;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_resume_response));
    if (*response == NULL) {
        ERROR("Resume: Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;
    if (name == NULL) {
        ERROR("Resume: receive NULL id");
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(name);
    if (cont == NULL) {
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);
    EVENT("Event: {Object: %s, Type: Resuming}", id);

    if (container_is_in_gc_progress(id)) {
        isulad_set_error_message("You cannot resume container %s in garbage collector progress.", id);
        ERROR("You cannot resume container %s in garbage collector progress.", id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    ret = do_resume_container(cont);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Resumed}", id);
    (void)isulad_monitor_send_container_event(id, UNPAUSE, -1, 0, NULL, NULL);

pack_response:
    pack_resume_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int pause_container(container_t *cont)
{
    int ret = 0;
    const char *id = cont->common_config->id;
    rt_pause_params_t params = { 0 };

    container_lock(cont);

    if (!container_is_running(cont->state)) {
        ERROR("Container %s is not running", id);
        isulad_set_error_message("Container %s is not running", id);
        ret = -1;
        goto out;
    }

    if (container_is_paused(cont->state)) {
        ERROR("Container %s is already paused", id);
        isulad_set_error_message("Container %s is already paused", id);
        ret = -1;
        goto out;
    }

    if (container_is_restarting(cont->state)) {
        ERROR("Container %s is restarting, wait until the container is running", id);
        isulad_set_error_message("Container %s is restarting, wait until the container is running", id);
        ret = -1;
        goto out;
    }

    params.rootpath = cont->root_path;
    params.state = cont->state_path;
    if (runtime_pause(id, cont->runtime, &params)) {
        ERROR("Failed to pause container:%s", id);
        ret = -1;
        goto out;
    }

    container_state_set_paused(cont->state);

    container_update_health_monitor(cont->common_config->id);

    if (container_to_disk(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        ret = -1;
        goto out;
    }
out:
    container_unlock(cont);
    return ret;
}

static void pack_pause_response(container_pause_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
}

static int container_pause_cb(const container_pause_request *request, container_pause_response **response)
{
    int ret = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *name = NULL;
    char *id = NULL;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_pause_response));
    if (*response == NULL) {
        ERROR("Pause: Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;

    if (name == NULL) {
        ERROR("Pause: receive NULL id");
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(name);
    if (cont == NULL) {
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    EVENT("Event: {Object: %s, Type: Pausing}", id);

    if (container_is_in_gc_progress(id)) {
        isulad_set_error_message("You cannot pause container %s in garbage collector progress.", id);
        ERROR("You cannot pause container %s in garbage collector progress.", id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    ret = pause_container(cont);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Paused}", id);
    (void)isulad_monitor_send_container_event(id, PAUSE, -1, 0, NULL, NULL);

pack_response:
    pack_pause_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static void host_config_restore_unlocking(container_t *cont, host_config *backup_hostconfig)
{
    free_host_config(cont->hostconfig);
    cont->hostconfig = backup_hostconfig;
    if (container_to_disk(cont)) {
        ERROR("Failed to save container \"%s\" to disk", cont->common_config->id);
    }
}

static void update_container_cpu(const host_config *hostconfig, host_config *chostconfig)
{
    if (hostconfig->cpu_shares != 0) {
        chostconfig->cpu_shares = hostconfig->cpu_shares;
    }
    if (hostconfig->cpu_period != 0) {
        chostconfig->cpu_period = hostconfig->cpu_period;
    }
    if (hostconfig->cpu_quota != 0) {
        chostconfig->cpu_quota = hostconfig->cpu_quota;
    }
    if (hostconfig->cpuset_cpus != NULL) {
        free(chostconfig->cpuset_cpus);
        chostconfig->cpuset_cpus = util_strdup_s(hostconfig->cpuset_cpus);
    }
    if (hostconfig->cpuset_mems != NULL) {
        free(chostconfig->cpuset_mems);
        chostconfig->cpuset_mems = util_strdup_s(hostconfig->cpuset_mems);
    }
}

static int update_container_memory(const char *id, const host_config *hostconfig, host_config *chostconfig)
{
    int ret = 0;

    if (hostconfig->memory != 0) {
        // if memory limit smaller than already set memoryswap limit and doesn't
        // update the memoryswap limit, then error out.
        if (chostconfig->memory_swap > 0 && hostconfig->memory > chostconfig->memory_swap &&
            hostconfig->memory_swap == 0) {
            ERROR("Memory limit should be smaller than already set memoryswap limit,"
                  " update the memoryswap at the same time");
            isulad_set_error_message("Cannot update container %s: Memory limit should be smaller than "
                                     "already set memoryswap limit, update the memoryswap at the same time.",
                                     id);
            ret = -1;
            goto out;
        }
        chostconfig->memory = hostconfig->memory;
    }

    if (hostconfig->memory_swap != 0) {
        chostconfig->memory_swap = hostconfig->memory_swap;
    }
    if (hostconfig->memory_reservation != 0) {
        chostconfig->memory_reservation = hostconfig->memory_reservation;
    }
    if (hostconfig->kernel_memory != 0) {
        chostconfig->kernel_memory = hostconfig->kernel_memory;
    }

out:
    return ret;
}

static int update_container_restart_policy(const host_config *hostconfig, host_config *chostconfig)
{
    int ret = 0;

    if (hostconfig->restart_policy != NULL && hostconfig->restart_policy->name != NULL) {
        free_host_config_restart_policy(chostconfig->restart_policy);
        chostconfig->restart_policy = util_common_calloc_s(sizeof(host_config_restart_policy));
        if (chostconfig->restart_policy == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        chostconfig->restart_policy->name = util_strdup_s(hostconfig->restart_policy->name);
        chostconfig->restart_policy->maximum_retry_count = hostconfig->restart_policy->maximum_retry_count;
    }
out:
    return ret;
}

static int update_container(const container_t *cont, const host_config *hostconfig)
{
    int ret = 0;
    char *id = NULL;
    host_config *chostconfig = NULL;

    if (cont == NULL || cont->hostconfig == NULL || hostconfig == NULL) {
        return -1;
    }

    id = cont->common_config->id;

    chostconfig = cont->hostconfig;

    if (hostconfig->blkio_weight != 0) {
        chostconfig->blkio_weight = hostconfig->blkio_weight;
    }

    update_container_cpu(hostconfig, chostconfig);

    ret = update_container_memory(id, hostconfig, chostconfig);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    ret = update_container_restart_policy(hostconfig, chostconfig);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

host_config *dump_host_config(const host_config *origconfig)
{
    char *json = NULL;
    parser_error err = NULL;
    host_config *newconfig = NULL;

    if (origconfig == NULL) {
        return NULL;
    }

    json = host_config_generate_json(origconfig, NULL, &err);
    if (json == NULL) {
        ERROR("Failed to generate json: %s", err);
        goto out;
    }
    newconfig = host_config_parse_data(json, NULL, &err);
    if (newconfig == NULL) {
        ERROR("Failed to parse json: %s", err);
        goto out;
    }

out:
    free(err);
    free(json);
    return newconfig;
}

static int update_host_config_check(container_t *cont, host_config *hostconfig)
{
    int ret = 0;
    const char *id = cont->common_config->id;

    ret = verify_host_config_settings(hostconfig, true);
    if (ret != 0) {
        goto out;
    }

    if (container_is_removal_in_progress(cont->state) || container_is_dead(cont->state)) {
        ERROR("Container is marked for removal and cannot be \"update\".");
        isulad_set_error_message(
            "Cannot update container %s: Container is marked for removal and cannot be \"update\".", id);
        ret = -1;
        goto out;
    }

    if (container_is_running(cont->state) && hostconfig->kernel_memory) {
        ERROR("Can not update kernel memory to a running container, please stop it first.");
        isulad_set_error_message("Cannot update container %s: Can not update kernel memory to a running container,"
                                 " please stop it first.",
                                 id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int do_update_resources(const container_update_request *request, container_t *cont)
{
    int ret = 0;
    const char *id = cont->common_config->id;
    parser_error err = NULL;
    host_config *hostconfig = NULL;
    host_config *backup_hostconfig = NULL;
    oci_runtime_spec *oci_spec = NULL;
    oci_runtime_spec *backup_oci_spec = NULL;
    rt_update_params_t params = { 0 };

    if (request->host_config == NULL) {
        DEBUG("receive NULL host config");
        ret = -1;
        goto out;
    }

    hostconfig = host_config_parse_data(request->host_config, NULL, &err);
    if (hostconfig == NULL) {
        ERROR("Failed to parse host config data:%s", err);
        ret = -1;
        goto out;
    }

    container_lock(cont);

    if (update_host_config_check(cont, hostconfig)) {
        ret = -1;
        goto unlock_out;
    }

    backup_hostconfig = dump_host_config(cont->hostconfig);
    if (backup_hostconfig == NULL) {
        ret = -1;
        goto unlock_out;
    }

    if (update_container(cont, hostconfig)) {
        ret = -1;
        goto restore_hostspec;
    }
    if (container_to_disk(cont)) {
        ERROR("Failed to save container \"%s\" to disk", id);
        ret = -1;
        goto restore_hostspec;
    }

    if (hostconfig->restart_policy && hostconfig->restart_policy->name) {
        container_update_restart_manager(cont, hostconfig->restart_policy);
    }

    oci_spec = load_oci_config(cont->root_path, id);
    if (oci_spec == NULL) {
        ERROR("Failed to load oci config");
        ret = -1;
        goto restore_hostspec;
    }

    backup_oci_spec = load_oci_config(cont->root_path, id);
    if (backup_oci_spec == NULL) {
        ERROR("Failed to load oci config");
        ret = -1;
        goto restore_hostspec;
    }

    ret = merge_conf_cgroup(oci_spec, hostconfig);
    if (ret != 0) {
        ERROR("Failed to merge cgroup config to oci spec");
        ret = -1;
        goto restore_hostspec;
    }

    if (save_oci_config(id, cont->root_path, oci_spec) != 0) {
        ERROR("Failed to save updated oci spec");
        ret = -1;
        goto restore_ocispec;
    }

    if (container_is_running(cont->state)) {
        params.rootpath = cont->root_path;
        params.hostconfig = hostconfig;
        if (runtime_update(id, cont->runtime, &params)) {
            ERROR("Update container %s failed", id);
            ret = -1;
            goto restore_ocispec;
        }
    }

    goto unlock_out;

restore_ocispec:
    if (save_oci_config(id, cont->root_path, backup_oci_spec) != 0) {
        ERROR("Failed to restore oci spec");
        ret = -1;
    }

restore_hostspec:
    host_config_restore_unlocking(cont, backup_hostconfig);

unlock_out:
    container_unlock(cont);
out:
    if (ret == 0) {
        free_host_config(backup_hostconfig);
    }
    free_host_config(hostconfig);
    free_oci_runtime_spec(oci_spec);
    free_oci_runtime_spec(backup_oci_spec);
    free(err);
    return ret;
}

static void pack_update_response(container_update_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
}

static int container_update_cb(const container_update_request *request, container_update_response **response)
{
    uint32_t cc = ISULAD_SUCCESS;
    char *container_name = NULL;
    char *id = NULL;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_update_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    container_name = request->name;
    if (container_name == NULL) {
        DEBUG("receive NULL Request id");
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(container_name)) {
        ERROR("Invalid container name %s", container_name);
        isulad_set_error_message("Invalid container name %s", container_name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(container_name);
    if (cont == NULL) {
        ERROR("No such container: %s", container_name);
        isulad_set_error_message("No such container: %s", container_name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);
    EVENT("Event: {Object: %s, Type: updating}", id);

    if (do_update_resources(request, cont) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: updated}", id);
    (void)isulad_monitor_send_container_event(id, CREATE, -1, 0, NULL, NULL);

pack_response:
    pack_update_response(*response, cc, id);

    container_unref(cont);

    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static void pack_export_response(container_export_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
}

static int container_export_cb(const container_export_request *request, container_export_response **response)
{
    int ret = 0;
    char *name = NULL;
    char *id = NULL;
    char *file = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_export_response));
    if (*response == NULL) {
        ERROR("Export: Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;
    file = request->file;

    if (name == NULL) {
        ERROR("Export: receive NULL id");
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    cont = containers_store_get(name);
    if (cont == NULL) {
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);

    if (container_is_in_gc_progress(id)) {
        isulad_set_error_message("You cannot export container %s in garbage collector progress.", id);
        ERROR("You cannot export container %s in garbage collector progress.", id);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    ret = export_container(cont, file);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    (void)isulad_monitor_send_container_event(id, EXPORT, -1, 0, NULL, NULL);
pack_response:
    pack_export_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

static int runtime_resize_helper(const char *id, const char *runtime, const char *rootpath, unsigned int height,
                                 unsigned int width)
{
    int ret = 0;
    rt_resize_params_t params = { 0 };

    params.rootpath = rootpath;
    params.height = height;
    params.width = width;

    ret = runtime_resize(id, runtime, &params);
    if (ret != 0) {
        ERROR("Failed to resize container %s", id);
    }

    return ret;
}

static int runtime_exec_resize_helper(const char *id, const char *runtime, const char *rootpath, const char *suffix,
                                      unsigned int height, unsigned int width)
{
    int ret = 0;
    rt_exec_resize_params_t params = { 0 };

    params.rootpath = rootpath;
    params.suffix = suffix;
    params.height = height;
    params.width = width;

    ret = runtime_exec_resize(id, runtime, &params);
    if (ret != 0) {
        ERROR("Failed to resize container %s", id);
    }

    return ret;
}

static int resize_container(container_t *cont, const char *suffix, unsigned int height, unsigned int width)
{
    int ret = 0;
    const char *id = cont->common_config->id;

    container_lock(cont);

    if (!container_is_running(cont->state)) {
        ERROR("Container %s is not running", id);
        isulad_set_error_message("Container %s is not running", id);
        ret = -1;
        goto out;
    }

    if (suffix != NULL) {
        DEBUG("Failed to resize container:%s suffix:%s", id, suffix);
        if (runtime_exec_resize_helper(id, cont->runtime, cont->root_path, suffix, height, width)) {
            ERROR("Failed to resize container:%s", id);
            ret = -1;
            goto out;
        }
    } else {
        if (runtime_resize_helper(id, cont->runtime, cont->root_path, height, width)) {
            ERROR("Failed to resize container:%s", id);
            ret = -1;
            goto out;
        }
    }

out:
    container_unlock(cont);
    return ret;
}

static void pack_resize_response(struct isulad_container_resize_response *response, uint32_t cc, const char *id)
{
    if (response == NULL) {
        return;
    }
    response->cc = cc;
    if (id != NULL) {
        response->id = util_strdup_s(id);
    }
    if (g_isulad_errmsg != NULL) {
        response->errmsg = util_strdup_s(g_isulad_errmsg);
        DAEMON_CLEAR_ERRMSG();
    }
}

static int resize_request_check(const struct isulad_container_resize_request *request)
{
    int ret = 0;

    char *name = request->id;
    if (name == NULL) {
        ERROR("Resume: receive NULL id");
        ret = -1;
        goto out;
    }

    if (!util_valid_container_id_or_name(name)) {
        ERROR("Invalid container name %s", name);
        isulad_set_error_message("Invalid container name %s", name);
        ret = -1;
        goto out;
    }

    if (request->suffix != NULL && !util_valid_exec_suffix(request->suffix)) {
        ERROR("Invalid suffix name %s", name);
        isulad_set_error_message("Invalid suffix name %s", name);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int container_resize_cb(const struct isulad_container_resize_request *request,
                               struct isulad_container_resize_response **response)
{
    int ret = 0;
    uint32_t cc = ISULAD_SUCCESS;
    char *name = NULL;
    char *id = NULL;
    container_t *cont = NULL;

    DAEMON_CLEAR_ERRMSG();
    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(struct isulad_container_resize_response));
    if (*response == NULL) {
        ERROR("Resume: Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    if (resize_request_check(request) != 0) {
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    name = request->id;

    cont = containers_store_get(name);
    if (cont == NULL) {
        ERROR("No such container:%s", name);
        isulad_set_error_message("No such container:%s", name);
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    id = cont->common_config->id;
    isula_libutils_set_log_prefix(id);
    EVENT("Event: {Object: %s, Type: Resizing}", id);

    ret = resize_container(cont, request->suffix, request->height, request->width);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        container_state_set_error(cont->state, (const char *)g_isulad_errmsg);
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Resized}", id);
    (void)isulad_monitor_send_container_event(id, RESIZE, -1, 0, NULL, NULL);

pack_response:
    pack_resize_response(*response, cc, id);
    container_unref(cont);
    isula_libutils_free_log_prefix();
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

void container_extend_callback_init(service_container_callback_t *cb)
{
    cb->update = container_update_cb;
    cb->pause = container_pause_cb;
    cb->resume = container_resume_cb;
    cb->stats = container_stats_cb;
    cb->events = container_events_cb;
    cb->export_rootfs = container_export_cb;
    cb->resize = container_resize_cb;
}
