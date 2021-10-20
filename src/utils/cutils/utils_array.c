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
 * Create: 2018-11-1
 * Description: provide container utils functions
 *******************************************************************************/

#define _GNU_SOURCE
#include "utils_array.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "isula_libutils/log.h"
#include "utils.h"

void util_free_array_by_len(char **array, size_t len)
{
    size_t i = 0;

    if (array == NULL) {
        return;
    }

    for (; i < len; i++) {
        UTIL_FREE_AND_SET_NULL(array[i]);
    }

    free(array);
}

size_t util_array_len(const char **array)
{
    const char **pos;
    size_t len = 0;

    for (pos = array; pos != NULL && *pos != NULL; pos++) {
        len++;
    }

    return len;
}

void util_free_array(char **array)
{
    char **p;

    for (p = array; p != NULL && *p != NULL; p++) {
        UTIL_FREE_AND_SET_NULL(*p);
    }
    free(array);
}

int util_array_append(char ***array, const char *element)
{
    size_t len;
    char **new_array = NULL;

    if (array == NULL || element == NULL) {
        return -1;
    }

    // let new len to len + 2 for element and null
    len = util_array_len((const char **)(*array));

    if (len > SIZE_MAX / sizeof(char *) - 2) {
        ERROR("Too many array elements!");
        return -1;
    }
    new_array = util_common_calloc_s((len + 2) * sizeof(char *));
    if (new_array == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    if (*array != NULL) {
        (void)memcpy(new_array, *array, len * sizeof(char *));
        UTIL_FREE_AND_SET_NULL(*array);
    }
    *array = new_array;

    new_array[len] = util_strdup_s(element);

    return 0;
}

int util_grow_array(char ***orig_array, size_t *orig_capacity, size_t size,
                    size_t increment)
{
    size_t add_capacity;
    char **add_array = NULL;

    if (orig_array == NULL || orig_capacity == NULL || increment == 0) {
        return -1;
    }

    if (((*orig_array) == NULL)  || ((*orig_capacity) == 0)) {
        UTIL_FREE_AND_SET_NULL(*orig_array);
        *orig_capacity = 0;
    }

    add_capacity = *orig_capacity;
    while (size + 1 > add_capacity) {
        add_capacity += increment;
    }
    if (add_capacity != *orig_capacity) {
        if (add_capacity > SIZE_MAX / sizeof(void *)) {
            return -1;
        }
        add_array = util_common_calloc_s(add_capacity * sizeof(void *));
        if (add_array == NULL) {
            return -1;
        }
        if (*orig_array != NULL) {
            (void)memcpy(add_array, *orig_array, *orig_capacity * sizeof(void *));
            UTIL_FREE_AND_SET_NULL(*orig_array);
        }

        *orig_array = add_array;
        *orig_capacity = add_capacity;
    }

    return 0;
}

static size_t get_string_array_scale_size(size_t old_size)
{
#define DOUBLE_THRESHOLD 1024
    const size_t max_threshold = MAX_MEMORY_SIZE / sizeof(char *);
    if (old_size == 0) {
        return 1;
    }

    if (old_size < DOUBLE_THRESHOLD) {
        return old_size << 1;
    }

    // new_size = old_size + old_size / 4
    if (old_size > max_threshold - (old_size >> 2)) {
        return max_threshold;
    }

    return old_size + (old_size >> 2);
}

static bool do_expand_array(string_array *array)
{
    size_t new_size = get_string_array_scale_size(array->cap);
    char **new_items = NULL;

    // array capability sure less than MAX_MEMORY_SIZE
    // so we need to check Overflow:
    if (new_size == array->cap) {
        ERROR("Too large string array, overflow memory");
        return false;
    }

    // new_size * sizeof(*new_items) and list->len * sizeof(*list->items)
    if (util_mem_realloc((void **)&new_items, new_size * sizeof(char *), (void *)array->items,
                         array->len * sizeof(char *)) != 0) {
        ERROR("Out of memory");
        return false;
    }
    array->items = new_items;
    array->cap = new_size;

    return true;
}

int util_append_string_array(string_array *sarr, const char *val)
{
    if (sarr == NULL) {
        ERROR("invalid string array");
        return -1;
    }

    if (val == NULL) {
        DEBUG("empty new item, just ignore it");
        return 0;
    }

    if (sarr->len < sarr->cap) {
        goto out;
    }

    // expand string array
    if (!do_expand_array(sarr)) {
        return -1;
    }

out:
    sarr->items[sarr->len] = util_strdup_s(val);
    sarr->len += 1;
    return 0;
}

bool util_string_array_contain(const string_array *sarr, const char *elem)
{
    size_t i;

    if (elem == NULL || sarr == NULL) {
        return false;
    }

    for (i = 0; i < sarr->len; i++) {
        if (strcmp(sarr->items[i], elem) == 0) {
            return true;
        }
    }

    return false;
}

void util_free_string_array(string_array *ptr)
{
    size_t i;

    if (ptr == NULL) {
        return;
    }

    for (i = 0; i < ptr->len; i++) {
        free(ptr->items[i]);
        ptr->items[i] = NULL;
    }
    free(ptr->items);
    ptr->items = NULL;
    ptr->len = 0;
    ptr->cap = 0;

    free(ptr);
}
