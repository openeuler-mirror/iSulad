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
 * Description: provide container list callback function definition
 ********************************************************************************/

#include "list.h"
#include <stdio.h>
#include <isula_libutils/container_config.h>
#include <isula_libutils/container_config_v2.h>
#include <isula_libutils/container_container.h>
#include <isula_libutils/defs.h>
#include <isula_libutils/json_common.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "container_api.h"
#include "filters.h"
#include "utils.h"
#include "error.h"
#include "constants.h"
#include "err_msg.h"
#include "map.h"
#include "utils_array.h"
#include "utils_timestamp.h"

struct list_context {
    struct filters_args *ps_filters;
    container_list_request *list_config;
};

static int dup_container_list_request(const container_list_request *src, container_list_request **dest)
{
    int ret = -1;
    char *json = NULL;
    parser_error err = NULL;

    if (src == NULL) {
        *dest = NULL;
        return 0;
    }

    json = container_list_request_generate_json(src, NULL, &err);
    if (json == NULL) {
        ERROR("Failed to generate json: %s", err);
        goto out;
    }
    *dest = container_list_request_parse_data(json, NULL, &err);
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

static void free_list_context(struct list_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    filters_args_free(ctx->ps_filters);
    ctx->ps_filters = NULL;
    free_container_list_request(ctx->list_config);
    ctx->list_config = NULL;
    free(ctx);
}

static struct list_context *list_context_new(const container_list_request *request)
{
    struct list_context *ctx = NULL;

    ctx = util_common_calloc_s(sizeof(struct list_context));
    if (ctx == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    ctx->ps_filters = filters_args_new();
    if (ctx->ps_filters == NULL) {
        ERROR("Out of memory");
        goto cleanup;
    }
    if (dup_container_list_request(request, &ctx->list_config) != 0) {
        ERROR("Failed to dup list request");
        goto cleanup;
    }
    return ctx;
cleanup:
    free_list_context(ctx);
    return NULL;
}

static const char *accepted_ps_filter_tags[] = { "id", "label", "name", "status", "last_n", NULL };

static int filter_by_name(const struct list_context *ctx, const map_t *map_id_name, const map_t *matches, bool idsearch)
{
    int ret = 0;
    bool default_value = true;

    if (ctx == NULL || map_id_name == NULL) {
        return -1;
    }

    map_itor *itor = map_itor_new(map_id_name);
    if (itor == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        void *id = map_itor_key(itor);
        const char *name = map_itor_value(itor);
        if (idsearch && map_search(matches, id) == NULL) {
            continue;
        }
        if (filters_args_match(ctx->ps_filters, "name", name)) {
            if (!map_replace(matches, id, &default_value)) {
                ERROR("Failed to insert");
                map_itor_free(itor);
                ret = -1;
                goto out;
            }
        }
    }
    map_itor_free(itor);

out:
    return ret;
}

static int append_ids(const map_t *matches, char ***filtered_ids)
{
    map_itor *itor = map_itor_new(matches);
    if (itor == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        if (util_array_append(filtered_ids, map_itor_key(itor)) != 0) {
            ERROR("Append failed");
            util_free_array(*filtered_ids);
            *filtered_ids = NULL;
            map_itor_free(itor);
            return -1;
        }
    }
    map_itor_free(itor);
    return 0;
}

static int insert_matched_id(char **ids, map_t *matches, void *value, size_t ids_len)
{
    size_t i;

    for (i = 0; i < ids_len; i++) {
        container_t *cont = containers_store_get_by_prefix(ids[i]);
        if (cont != NULL) {
            bool inserted;
            inserted = map_insert(matches, cont->common_config->id, value);
            container_unref(cont);
            if (!inserted) {
                ERROR("Insert map failed: %s", ids[i]);
                return -1;
            }
        }
    }
    return 0;
}

static inline void set_idsearch(size_t ids_len, bool *value)
{
    if (ids_len > 0) {
        *value = true;
    }
}

typedef struct {
    void *id;
    int64_t created;
} container_time_id_info;

/*
* used by qsort function for comparing container create time
*/
static inline int container_create_time_cmp(container_time_id_info **first, container_time_id_info **second)
{
    return (*second)->created > (*first)->created;
}

static void free_filtered_last_list(container_time_id_info **filtered_last_list, int len)
{
    int i;
    if (filtered_last_list == NULL) {
        return;
    }
    for (i = 0; i < len; i++) {
        free(filtered_last_list[i]->id);
        free(filtered_last_list[i]);
        filtered_last_list[i] = NULL;
    }
    free(filtered_last_list);
    filtered_last_list = NULL;
}

static container_time_id_info *get_last_list_info(void *id, int64_t create_time)
{
    container_time_id_info *last_list_info = NULL;

    last_list_info = (container_time_id_info *)util_common_calloc_s(sizeof(container_time_id_info));
    if (last_list_info == NULL) {
        ERROR("Failed to malloc for last_list");
        return NULL;
    }

    last_list_info->created = create_time;
    last_list_info->id = util_strdup_s(id);
    if (last_list_info->id == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    return last_list_info;
}

static int append_filtered_ids(char ***filtered_ids, container_time_id_info **filtered_last_list, size_t append_num)
{
    size_t count = 0;
    char **array = (char **)util_smart_calloc_s(sizeof(char *), (size_t)append_num + 1);
    if (array == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    while (count < append_num) {
        array[count] = util_strdup_s(filtered_last_list[count]->id);
        count++;
    }
    array[count] = NULL;
    *filtered_ids = array;

    return 0;
}

static int filter_by_create_time(size_t last_num, const map_t *map_id_name, char ***filtered_ids)
{
    int ret = -1;
    size_t container_num = 0;
    size_t container_valid_num = 0;
    size_t container_append_num = 0;
    int64_t container_create_time = 0;
    container_t *cont = NULL;
    container_time_id_info **filtered_last_list = NULL;

    if (map_id_name == NULL) {
        return ret;
    }

    map_itor *itor = map_itor_new(map_id_name);
    if (itor == NULL) {
        ERROR("Out of memory");
        goto cleanup;
    }
    container_num = map_size(map_id_name);
    if (container_num == 0) {
        ret = 0;
        goto cleanup;
    }
    filtered_last_list =
        (container_time_id_info **)util_smart_calloc_s(sizeof(container_time_id_info *), container_num);
    if (filtered_last_list == NULL) {
        ERROR("Out of memory");
        goto cleanup;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        const char *name = map_itor_value(itor);
        void *id = map_itor_key(itor);
        if (id == NULL) {
            continue;
        }
        cont = containers_store_get(name);
        if (cont == NULL) {
            ERROR("Container '%s' not exist", name);
            continue;
        }
        if (cont->common_config->created != NULL &&
            util_to_unix_nanos_from_str(cont->common_config->created, &container_create_time) != 0) {
            ERROR("Failed to container %s created time", cont->common_config->id);
            continue;
        }
        filtered_last_list[container_valid_num] = get_last_list_info(id, container_create_time);
        if (filtered_last_list[container_valid_num] == NULL) {
            continue;
        }
        container_valid_num++;
    }

    if (container_valid_num > 1) {
        qsort(filtered_last_list, (size_t)(container_valid_num), sizeof(container_time_id_info *),
              (int (*)(const void *, const void *))container_create_time_cmp);
    }

    container_append_num = container_valid_num;
    if (container_append_num > last_num) {
        container_append_num = last_num;
    }

    if (append_filtered_ids(filtered_ids, filtered_last_list, container_append_num) != 0) {
        goto cleanup;
    }
    ret = 0;

cleanup:
    map_itor_free(itor);
    container_unref(cont);
    free_filtered_last_list(filtered_last_list, container_valid_num);
    return ret;
}

static char **filter_by_name_id_matches(const struct list_context *ctx, const map_t *map_id_name)
{
    int ret = 0;
    size_t last_num = 0;
    size_t names_len, ids_len, last_len;
    bool idsearch = false;
    bool default_value = true;
    char **names = NULL;
    char **ids = NULL;
    char **last_n = NULL;
    char **filtered_ids = NULL;
    map_t *matches = NULL;

    names = filters_args_get(ctx->ps_filters, "name");
    names_len = util_array_len((const char **)names);

    ids = filters_args_get(ctx->ps_filters, "id");
    ids_len = util_array_len((const char **)ids);

    last_n = filters_args_get(ctx->ps_filters, "last_n");
    last_len = util_array_len((const char **)last_n);

    if (names_len == 0 && ids_len == 0 && last_len == 0) {
        if (append_ids(map_id_name, &filtered_ids) != 0) {
            goto cleanup;
        }
        return filtered_ids;
    }

    set_idsearch(ids_len, &idsearch);

    matches = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (matches == NULL) {
        ERROR("Out of memory");
        goto cleanup;
    }

    if (insert_matched_id(ids, matches, &default_value, ids_len) != 0) {
        goto cleanup;
    }

    if (names_len > 0) {
        ret = filter_by_name(ctx, map_id_name, matches, idsearch);
        if (ret != 0) {
            goto cleanup;
        }
    }

    if (map_size(matches) > 0) {
        if (append_ids(map_id_name, &filtered_ids) != 0) {
            goto cleanup;
        }
    }

    if (last_len > 0) {
        last_num = atoi(ctx->list_config->filters->values[0]->keys[0]);
    }
    if (last_num > 0) {
        ret = filter_by_create_time(last_num, map_id_name, &filtered_ids);
        if (ret != 0) {
            goto cleanup;
        }
    }

cleanup:
    util_free_array(ids);
    util_free_array(names);
    util_free_array(last_n);
    map_free(matches);
    return filtered_ids;
}

char *container_get_health_state(const container_state *cont_state)
{
    if (cont_state == NULL || cont_state->health == NULL || cont_state->health->status == NULL) {
        return NULL;
    }

    if (strcmp(cont_state->health->status, HEALTH_STARTING) == 0) {
        return util_strdup_s("health: starting");
    }

    return util_strdup_s(cont_state->health->status);
}

static int replace_labels(container_container *isuladinfo, json_map_string_string *labels, const map_t *map_labels)
{
    isuladinfo->labels = util_common_calloc_s(sizeof(json_map_string_string));

    if (isuladinfo->labels == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (dup_json_map_string_string(labels, isuladinfo->labels) != 0) {
        ERROR("Failed to dup labels");
        return -1;
    }
    size_t i;
    for (i = 0; i < labels->len; i++) {
        if (!map_replace(map_labels, (void *)labels->keys[i], labels->values[i])) {
            ERROR("Failed to insert labels to map");
            return -1;
        }
    }
    return 0;
}

static int replace_annotations(const container_config_v2_common_config *common_config, container_container *isuladinfo)
{
    if (common_config->config->annotations != NULL && common_config->config->annotations->len != 0) {
        isuladinfo->annotations = util_common_calloc_s(sizeof(json_map_string_string));
        if (isuladinfo->annotations == NULL) {
            ERROR("Out of memory");
            return -1;
        }

        if (dup_json_map_string_string(common_config->config->annotations, isuladinfo->annotations) != 0) {
            ERROR("Failed to dup annotations");
            return -1;
        }
    }
    return 0;
}

static void dup_id_name(const container_config_v2_common_config *common_config, container_container *isuladinfo)
{
    if (common_config->id != NULL) {
        isuladinfo->id = util_strdup_s(common_config->id);
    }

    if (common_config->name != NULL) {
        isuladinfo->name = util_strdup_s(common_config->name);
    }
}

static void dup_container_labels(const map_t *map_labels, const container_config_v2_common_config *common_config,
                                 container_container *isuladinfo)
{
    int ret = 0;

    if (common_config->config == NULL) {
        return;
    }

    if (common_config->config->labels != NULL && common_config->config->labels->len != 0) {
        json_map_string_string *labels = common_config->config->labels;

        ret = replace_labels(isuladinfo, labels, map_labels);
        if (ret != 0) {
            ERROR("Failed to dup container %s labels", common_config->id);
        }
    }

    return;
}

static void dup_container_annotations(const container_config_v2_common_config *common_config,
                                      container_container *isuladinfo)
{
    int ret = 0;

    if (common_config->config == NULL) {
        return;
    }

    ret = replace_annotations(common_config, isuladinfo);
    if (ret != 0) {
        ERROR("Failed to dup container %s annotations", common_config->id);
    }

    return;
}

static void dup_container_created_time(const container_config_v2_common_config *common_config,
                                       container_container *isuladinfo)
{
    if (common_config->created != NULL &&
        util_to_unix_nanos_from_str(common_config->created, &isuladinfo->created) != 0) {
        ERROR("Failed to dup container %s created time", common_config->id);
    }

    return;
}

static void dup_container_image_ref(const container_config_v2_common_config *common_config,
                                    container_container *isuladinfo)
{
    if (common_config->config == NULL) {
        return;
    }

    isuladinfo->image_ref = util_strdup_s(common_config->config->image_ref);

    return;
}

static int convert_common_config_info(const map_t *map_labels, const container_config_v2_common_config *common_config,
                                      container_container *isuladinfo)
{
    if (map_labels == NULL || common_config == NULL || isuladinfo == NULL) {
        return -1;
    }

    dup_id_name(common_config, isuladinfo);

    dup_container_image_ref(common_config, isuladinfo);

    dup_container_labels(map_labels, common_config, isuladinfo);

    dup_container_annotations(common_config, isuladinfo);

    dup_container_created_time(common_config, isuladinfo);

    return 0;
}

static int container_info_match(const struct list_context *ctx, const map_t *map_labels,
                                const container_container *isuladinfo, const container_state *cont_state)
{
    int ret = 0;
    Container_Status cs;

    if (ctx == NULL || map_labels == NULL || cont_state == NULL) {
        return -1;
    }

    if (!filters_args_match(ctx->ps_filters, "name", isuladinfo->name)) {
        ret = -1;
        goto out;
    }

    if (!filters_args_match(ctx->ps_filters, "id", isuladinfo->id)) {
        ret = -1;
        goto out;
    }

    cs = container_state_judge_status(cont_state);
    if (cs == CONTAINER_STATUS_CREATED) {
        if (!filters_args_match(ctx->ps_filters, "status", "created") &&
            !filters_args_match(ctx->ps_filters, "status", "inited")) {
            ret = -1;
            goto out;
        }
    } else if (!filters_args_match(ctx->ps_filters, "status", container_state_to_string(cs))) {
        ret = -1;
        goto out;
    }

    // Do not include container if any of the labels don't match
    if (!filters_args_match_kv_list(ctx->ps_filters, "label", map_labels)) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int get_cnt_state(const struct list_context *ctx, const container_state *cont_state, const char *name)
{
    if (cont_state == NULL) {
        ERROR("Failed to read %s state", name);
        return -1;
    }

    if (!cont_state->running && !ctx->list_config->all) {
        return -1;
    }
    return 0;
}

static int fill_container_info(container_container *container_info, const container_state *cont_state,
                               const map_t *map_labels, const container_t *cont)
{
    int ret = 0;
    char *image = NULL;
    char *timestr = NULL;
    char *defvalue = "-";

    ret = convert_common_config_info(map_labels, cont->common_config, container_info);
    if (ret != 0) {
        goto out;
    }

    container_info->pid = (int32_t)cont_state->pid;

    container_info->status = (int)container_state_judge_status(cont_state);

    container_info->command = container_get_command(cont);
    image = container_get_image(cont);
    container_info->image = image ? image : util_strdup_s("none");

    container_info->exit_code = (uint32_t)(cont_state->exit_code);
    timestr = cont_state->started_at ? cont_state->started_at : defvalue;
    container_info->startat = util_strdup_s(timestr);

    timestr = cont_state->finished_at ? cont_state->finished_at : defvalue;
    container_info->finishat = util_strdup_s(timestr);

    container_info->runtime = cont->runtime ? util_strdup_s(cont->runtime) : util_strdup_s("none");

    container_info->health_state = container_get_health_state(cont_state);

    container_info->restartcount = (uint64_t)cont_state->restart_count;

out:
    return ret;
}

static void unref_cont(container_t *cont)
{
    if (cont != NULL) {
        container_unref(cont);
    }
    return;
}

static container_container *get_container_info(const char *name, const struct list_context *ctx)
{
    int ret = 0;
    container_container *container_info = NULL;
    container_t *cont = NULL;
    container_state *cont_state = NULL;
    map_t *map_labels = NULL;

    cont = containers_store_get(name);
    if (cont == NULL) {
        ERROR("Container '%s' not exist", name);
        return NULL;
    }
    cont_state = container_dup_state(cont->state);

    if (get_cnt_state(ctx, cont_state, name) != 0) {
        ret = -1;
        goto cleanup;
    }

    map_labels = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (map_labels == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto cleanup;
    }

    container_info = util_common_calloc_s(sizeof(container_container));
    if (container_info == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto cleanup;
    }

    ret = fill_container_info(container_info, cont_state, map_labels, cont);
    if (ret != 0) {
        goto cleanup;
    }

    ret = container_info_match(ctx, map_labels, container_info, cont_state);
    if (ret != 0) {
        goto cleanup;
    }

cleanup:
    unref_cont(cont);
    map_free(map_labels);
    free_container_state(cont_state);
    if (ret != 0) {
        free_container_container(container_info);
        container_info = NULL;
    }
    return container_info;
}

static int do_add_filters(const char *filter_key, const json_map_string_bool *filter_value, struct list_context *ctx)
{
    int ret = 0;
    size_t j;
    bool bret = false;

    for (j = 0; j < filter_value->len; j++) {
        if (strcmp(filter_key, "status") == 0) {
            if (!container_is_valid_state_string(filter_value->keys[j])) {
                ERROR("Unrecognised filter value for status: %s", filter_value->keys[j]);
                isulad_set_error_message("Unrecognised filter value for status: %s", filter_value->keys[j]);
                ret = -1;
                goto out;
            }
            ctx->list_config->all = true;
        }
        if (strcmp(filter_key, "last_n") == 0) {
            ctx->list_config->all = true;
        }
        bret = filters_args_add(ctx->ps_filters, filter_key, filter_value->keys[j]);
        if (!bret) {
            ERROR("Add filter args failed");
            ret = -1;
            goto out;
        }
    }
out:
    return ret;
}

static struct list_context *fold_filter(const container_list_request *request)
{
    size_t i;
    struct list_context *ctx = NULL;

    ctx = list_context_new(request);
    if (ctx == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (request->filters == NULL) {
        return ctx;
    }

    for (i = 0; i < request->filters->len; i++) {
        if (!filters_args_valid_key(accepted_ps_filter_tags, sizeof(accepted_ps_filter_tags) / sizeof(char *),
                                    request->filters->keys[i])) {
            ERROR("Invalid filter '%s'", request->filters->keys[i]);
            isulad_set_error_message("Invalid filter '%s'", request->filters->keys[i]);
            goto error_out;
        }
        if (do_add_filters(request->filters->keys[i], request->filters->values[i], ctx) != 0) {
            goto error_out;
        }
    }

    return ctx;
error_out:
    free_list_context(ctx);
    return NULL;
}

static int pack_list_containers(char **idsarray, const struct list_context *ctx, container_list_response *response)
{
    int ret = 0;
    int j = 0;
    size_t container_nums = 0;

    container_nums = util_array_len((const char **)idsarray);
    if (container_nums == 0) {
        goto out;
    }

    if (container_nums > (SIZE_MAX / sizeof(container_container *))) {
        ERROR("Get too many containers:%zu", container_nums);
        ret = -1;
        goto out;
    }

    response->containers = util_common_calloc_s(container_nums * sizeof(container_container *));
    if (response->containers == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    while (idsarray != NULL && idsarray[j] != NULL) {
        response->containers[response->containers_len] = get_container_info(idsarray[j], ctx);
        if (response->containers[response->containers_len] == NULL) {
            j++;
            continue;
        }
        j++;
        response->containers_len++;
    }
out:
    return ret;
}

int container_list_cb(const container_list_request *request, container_list_response **response)
{
    char **idsarray = NULL;
    map_t *map_id_name = NULL;
    uint32_t cc = ISULAD_SUCCESS;
    struct list_context *ctx = NULL;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(container_list_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    ctx = fold_filter(request);
    if (ctx == NULL) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

    map_id_name = container_name_index_get_all();
    if (map_id_name == NULL) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }
    if (map_size(map_id_name) == 0) {
        goto pack_response;
    }
    // fastpath to only look at a subset of containers if specific name
    // or ID matches were provided by the user--otherwise we potentially
    // end up querying many more containers than intended
    idsarray = filter_by_name_id_matches(ctx, map_id_name);

    if (pack_list_containers(idsarray, ctx, (*response)) != 0) {
        cc = ISULAD_ERR_EXEC;
        goto pack_response;
    }

pack_response:
    map_free(map_id_name);
    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }
    util_free_array(idsarray);
    free_list_context(ctx);

    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}
