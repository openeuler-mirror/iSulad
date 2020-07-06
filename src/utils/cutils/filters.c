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
 * Author: tanyifeng
 * Create: 2018-11-07
 * Description: provide filters functions
 ******************************************************************************/
#include "filters.h"

#include <stdlib.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_array.h"
#include "utils_regex.h"


static void filters_args_fields_free(void *key, void *val)
{
    free(key);
    map_free(val);
}

struct filters_args *filters_args_new(void)
{
    struct filters_args *filters = NULL;

    filters = util_common_calloc_s(sizeof(struct filters_args));
    if (filters == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    // value of fields is a map of map[string][bool]
    filters->fields = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, filters_args_fields_free);
    if (filters->fields == NULL) {
        free(filters);
        ERROR("Out of memory");
        return NULL;
    }
    return filters;
}

// Free filters
void filters_args_free(struct filters_args *filters)
{
    if (filters == NULL) {
        return;
    }

    map_free(filters->fields);
    filters->fields = NULL;
    free(filters);
}

char **filters_args_get(const struct filters_args *filters, const char *field)
{
    char **slice = NULL;
    map_t *field_values_map = NULL;
    map_itor *itor = NULL;

    if (filters == NULL || filters->fields == NULL) {
        return NULL;
    }

    field_values_map = map_search(filters->fields, (void *)field);
    if (field_values_map == NULL || map_size(field_values_map) == 0) {
        return NULL;
    }

    itor = map_itor_new(field_values_map);
    if (itor == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        int aret;
        aret = util_array_append(&slice, map_itor_key(itor));
        if (aret != 0) {
            ERROR("Out of memory");
            util_free_array(slice);
            map_itor_free(itor);
            return NULL;
        }
    }
    map_itor_free(itor);
    return slice;
}

// Add a new value to a filter field.
bool filters_args_add(struct filters_args *filters, const char *name,
                      const char *value)
{
    bool default_value = true;
    map_t *map_str_bool = NULL;

    if (filters == NULL || filters->fields == NULL) {
        return false;
    }

    map_str_bool = map_search(filters->fields, (void *)name);
    if (map_str_bool == NULL) {
        map_str_bool = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
        if (map_str_bool == NULL) {
            ERROR("Out of memory");
            return false;
        }
        if (!map_replace(filters->fields, (void *)name, (void *)map_str_bool)) {
            ERROR("Failed to insert name: %s", name);
            map_free(map_str_bool);
            return false;
        }
    }
    if (!map_replace(map_str_bool, (void *)value, (void *)(&default_value))) {
        ERROR("Failed to insert value: %s", value);
        return false;
    }

    return true;
}

// Remove a value from a filter field.
bool filters_args_del(struct filters_args *filters, const char *name,
                      const char *value)
{
    map_t *map_str_bool = NULL;

    if (filters == NULL || filters->fields == NULL) {
        return false;
    }

    map_str_bool = map_search(filters->fields, (void *)name);
    if (map_str_bool != NULL) {
        if (!map_remove(map_str_bool, (void *)value)) {
            ERROR("Failed to remove value %s from name %s", value, name);
            return false;
        }
    }
    return true;
}

size_t filters_args_len(const struct filters_args *filters)
{
    if (filters == NULL || filters->fields == NULL) {
        return 0;
    }
    return map_size(filters->fields);
}

static bool do_filters_args_match_kv_list(const map_t *field_values_map, const map_t *sources)
{
    size_t size, i;
    bool bret = false;
    map_itor *itor = NULL;

    size = map_size(field_values_map);
    itor = map_itor_new(field_values_map);
    if (itor == NULL) {
        ERROR("Out of memory");
        goto cleanup;
    }
    for (i = 0; map_itor_valid(itor) && i < size; map_itor_next(itor), i++) {
        const char *name2match = NULL;
        const char *sources_value = NULL;
        char **test_kv = NULL;
        char *copy = NULL;
        char *pos = NULL;
        int aret = 0;

        name2match = map_itor_key(itor);
        copy = util_strdup_s(name2match);
        // Splitted by '=' to at most 2 substring, better to implement util_string_split_n
        pos = strchr(copy, '=');
        if (pos == NULL) {
            aret = util_array_append(&test_kv, copy);
            free(copy);
            if (aret != 0) {
                ERROR("Out of memory");
                util_free_array(test_kv);
                goto cleanup;
            }
        } else {
            *pos++ = '\0';
            aret = util_array_append(&test_kv, copy);
            if (aret != 0) {
                ERROR("Out of memory");
                free(copy);
                util_free_array(test_kv);
                goto cleanup;
            }
            aret = util_array_append(&test_kv, pos);
            free(copy);
            if (aret != 0) {
                ERROR("Out of memory");
                util_free_array(test_kv);
                goto cleanup;
            }
        }

        if (test_kv == NULL) {
            ERROR("Out of memory");
            util_free_array(test_kv);
            goto cleanup;
        }

        sources_value = map_search(sources, (void *)test_kv[0]);
        if (sources_value == NULL) {
            util_free_array(test_kv);
            goto cleanup;
        }

        if (util_array_len((const char **)test_kv) == 2 && strcmp(test_kv[1], sources_value) != 0) {
            util_free_array(test_kv);
            goto cleanup;
        }
        util_free_array(test_kv);
    }
    bret = true;
cleanup:
    map_itor_free(itor);
    return bret;
}

/* check if a field is match or not
 *      filters_args are {'label': {'label1=1','label2=2'}, 'image.name', {'busybox'}},
 *      field is 'label' and sources are {'label1': '1', 'label2': '2'}
 *      it returns true.
 */
bool filters_args_match_kv_list(const struct filters_args *filters, const char *field, const map_t *sources)
{
    map_t *field_values_map = NULL;

    // Do not filter if there is no filter set or cannot determine filter
    if (filters == NULL || filters->fields == NULL) {
        return true;
    }

    field_values_map = map_search(filters->fields, (void *)field);
    if (field_values_map == NULL || map_size(field_values_map) == 0) {
        return true;
    }

    if (sources == NULL || map_size(sources) == 0) {
        return false;
    }

    if (sources->type != MAP_STR_STR) {
        ERROR("Input arg is not valid map[string][string]");
        return false;
    }

    return do_filters_args_match_kv_list(field_values_map, sources);
}

bool filters_args_exact_match(const struct filters_args *filters, const char *field, const char *source)
{
    map_t *field_values_map = NULL;

    // Do not filter if there is no filter set or cannot determine filter
    if (filters == NULL || filters->fields == NULL) {
        return true;
    }

    field_values_map = map_search(filters->fields, (void *)field);
    if (field_values_map == NULL || map_size(field_values_map) == 0) {
        return true;
    }

    // try to march full name value to avoid O(N) regular expression matching
    if (map_search(field_values_map, (void *)source) != NULL) {
        return true;
    }

    return false;
}

bool filters_args_match(const struct filters_args *filters, const char *field, const char *source)
{
    map_t *field_values_map = NULL;
    map_itor *itor = NULL;

    if (filters_args_exact_match(filters, field, source)) {
        return true;
    }

    field_values_map = map_search(filters->fields, (void *)field);
    itor = map_itor_new(field_values_map);
    if (itor == NULL) {
        ERROR("Out of memory");
        return false;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        const char *name2match = map_itor_key(itor);
        if (util_reg_match(name2match, source) != 0) {
            continue;
        }
        map_itor_free(itor);
        return true;
    }
    map_itor_free(itor);
    return false;
}

/* check whether field is one of accepted name or not */
bool filters_args_valid_key(const char **accepted, size_t len, const char *field)
{
    size_t i;

    if (field == NULL) {
        return false;
    }
    for (i = 0; i < len; i++) {
        if (accepted[i] != NULL && strcmp(accepted[i], field) == 0) {
            return true;
        }
    }
    return false;
}

